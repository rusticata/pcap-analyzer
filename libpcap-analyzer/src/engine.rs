use crate::analyzer::*;
use crate::plugin_registry::PluginRegistry;
use pcap_parser::*;
use pcap_parser::data::PacketData;
use std::cmp::min;
use std::io::Read;

use crossbeam_queue::SegQueue;
use libpcap_tools::*;
use std::sync::Arc;
use std::thread::JoinHandle;

use pnet_base::MacAddr;
use pnet_packet::ethernet::{EtherType, EtherTypes, EthernetPacket};

pub enum Job<'a> {
    Exit,
    PrintDebug,
    New(
        Packet<'a>,
        ParseContext,
        &'a [u8],
        EtherType,
    ),
}

pub struct Worker {
    _id: usize,
    handler: JoinHandle<()>,
}

/// pcap/pcap-ng analyzer engine
pub struct ThreadedPcapEngine {
    a: Box<Analyzer>,
    registry: Arc<PluginRegistry>,
    buffer_initial_capacity: usize,
    n_workers: usize,
}

impl ThreadedPcapEngine {
    /// Build a new ThreadedPcapEngine, taking ownership of the input PcapAnalyzer
    pub fn new(a: Box<Analyzer>, registry: PluginRegistry, config: &Config) -> Self {
        let buffer_initial_capacity = config
            .get_usize("buffer_initial_capacity")
            .unwrap_or(128 * 1024);
        let n_workers = config.get_usize("num_threads").unwrap_or(num_cpus::get());
        ThreadedPcapEngine {
            a,
            registry: Arc::new(registry),
            buffer_initial_capacity,
            n_workers,
        }
    }

    /// Main function: given a reader, read all pcap data and call analyzer for each Packet
    pub fn run<R: Read>(&mut self, f: &mut R) -> Result<(), Error> {
        let capacity = self.buffer_initial_capacity;
        let mut reader = pcap_parser::create_reader(capacity, f)?;

        self.a.init()?;
        let mut ctx = ParseContext::default();
        ctx.pcap_index = 0;

        let (offset, block) = reader.next()?;
        match block {
            PcapBlockOwned::NG(Block::SectionHeader(ref shb)) => {
                ctx.bigendian = shb.is_bigendian();
            },
            PcapBlockOwned::LegacyHeader(ref hdr) => {
                let if_info = InterfaceInfo {
                    link_type: hdr.network,
                    if_tsresol: 0,
                    if_tsoffset: 0,
                    snaplen: hdr.snaplen,
                };
                ctx.interfaces.push(if_info);
                ctx.bigendian = hdr.is_bigendian();
            },
            _ => unreachable!(),
        };
        reader.consume(offset);

        let mut last_incomplete_index = 0;

        let local_jobs: Vec<_> = (0..self.n_workers)
            .map(|_| Arc::new(SegQueue::new()))
            .collect();
        let workers: Vec<_> = (0..self.n_workers)
            .map(|i| {
                let local_q = local_jobs[i].clone();
                let arc_registry = self.registry.clone();
                let handler = ::std::thread::spawn(move || {
                    debug!("worker thread {} starting", i);
                    loop {
                        if let Ok(msg) = local_q.pop() {
                            match msg {
                                Job::Exit => break,
                                Job::PrintDebug => {
                                    TAD.with(|f| {
                                        debug!(
                                            "thread {}: hash table size: {}",
                                            i,
                                            f.borrow().flows.len()
                                        );
                                    });
                                }
                                Job::New(packet, ctx, data, ethertype) => {
                                    debug!("thread {}: got a job", i);
                                    // extern_l2(&s, &registry);
                                    let res =
                                        handle_l3(&packet, &ctx, data, ethertype, &arc_registry);
                                    if res.is_err() {
                                        warn!("thread {}: handle_l3 failed", i);
                                    }
                                    ()
                                }
                            }
                        }
                        // ::std::thread::sleep(::std::time::Duration::from_millis(10));
                    }
                });
                Worker { _id: i, handler }
                // (q, exit.clone(), handler)
            })
            .collect();
        loop {
            match reader.next() {
                Ok((offset, block)) => {
                    let packet = match block {
                        PcapBlockOwned::NG(Block::SectionHeader(ref _shb)) => {
                            debug!("pcap-ng: new section");
                            ctx.interfaces = Vec::new();
                            reader.consume_noshift(offset);
                            continue;
                        },
                        PcapBlockOwned::NG(Block::InterfaceDescription(ref idb)) => {
                            let if_info = pcapng_build_interface(idb);
                            ctx.interfaces.push(if_info);
                            reader.consume_noshift(offset);
                            continue;
                        },
                        PcapBlockOwned::NG(Block::EnhancedPacket(ref epb)) => {
                            ctx.pcap_index += 1;
                            assert!((epb.if_id as usize) < ctx.interfaces.len());
                            let if_info = &ctx.interfaces[epb.if_id as usize];
                            let (ts_sec, ts_frac, unit) = pcap_parser::build_ts(epb.ts_high, epb.ts_low,
                                                                                if_info.if_tsoffset, if_info.if_tsresol);
                            let unit = unit as u32; // XXX lossy cast
                            let ts_usec = if unit != MICROS_PER_SEC {
                                ts_frac/ ((unit / MICROS_PER_SEC) as u32) } else { ts_frac };
                            let ts = Duration::new(ts_sec, ts_usec);
                            let data = pcap_parser::data::get_packetdata(epb.data, if_info.link_type, epb.caplen as usize)
                                .ok_or(Error::Generic("Parsing PacketData failed (EnhancedPacket)"))?;
                            Packet {
                                interface: epb.if_id,
                                ts,
                                data,
                                origlen: epb.origlen,
                                caplen: epb.caplen,
                                pcap_index: ctx.pcap_index,
                            }
                        },
                        PcapBlockOwned::NG(Block::SimplePacket(ref spb)) => {
                            ctx.pcap_index += 1;
                            assert!(ctx.interfaces.len() > 0);
                            let if_info = &ctx.interfaces[0];
                            let blen = (spb.block_len1 - 16) as usize;
                            let data = pcap_parser::data::get_packetdata(spb.data, if_info.link_type, blen)
                                .ok_or(Error::Generic("Parsing PacketData failed (SimplePacket)"))?;
                            Packet {
                                interface: 0,
                                ts: Duration::default(),
                                data,
                                origlen: spb.origlen,
                                caplen: if_info.snaplen,
                                pcap_index: ctx.pcap_index,
                            }
                        },
                        PcapBlockOwned::LegacyHeader(ref hdr) => {
                            let if_info = InterfaceInfo{
                                link_type: hdr.network,
                                if_tsoffset: 0,
                                if_tsresol: 6,
                                snaplen: hdr.snaplen,
                            };
                            ctx.interfaces.push(if_info);
                            debug!("Legacy pcap,  link type: {}", hdr.network);
                            reader.consume_noshift(offset);
                            continue;
                        },
                        PcapBlockOwned::Legacy(ref b) => {
                            ctx.pcap_index += 1;
                            assert!(ctx.interfaces.len() > 0);
                            let if_info = &ctx.interfaces[0];
                            let blen = b.caplen as usize;
                            let data = pcap_parser::data::get_packetdata(b.data, if_info.link_type, blen)
                                .ok_or(Error::Generic("Parsing PacketData failed (Legacy Packet)"))?;
                            Packet {
                                interface: 0,
                                ts: Duration::new(b.ts_sec, b.ts_usec),
                                data,
                                origlen: b.origlen,
                                caplen: b.caplen,
                                pcap_index: ctx.pcap_index,
                            }
                        },
                        PcapBlockOwned::NG(Block::InterfaceStatistics(_)) |
                        PcapBlockOwned::NG(Block::NameResolution(_)) => {
                            // XXX just ignore block
                            reader.consume_noshift(offset);
                            continue;
                        },
                        _ => {
                            warn!("unsupported block");
                            reader.consume_noshift(offset);
                            continue;
                        }
                    };
                    debug!("**************************************************************");
                    // build ts
                    if ctx.first_packet_ts.is_null() {
                        ctx.first_packet_ts = packet.ts;
                    }
                    debug!("    time  : {} / {:06}", packet.ts.secs, packet.ts.micros);
                    ctx.rel_ts = packet.ts - ctx.first_packet_ts; // an underflow is weird but not critical
                    debug!("    reltime  : {}.{:06}", ctx.rel_ts.secs, ctx.rel_ts.micros);
                    // call engine
                    // XXX remove packet from lifetime management, it must be made 'static
                    // to be sent to threads
                    // "by doing this, I solely declare that I am responsible of the lifetime
                    // and safety of packet"
                    let packet : Packet<'static> = unsafe {
                        ::std::mem::transmute(packet)
                    };
                    self.dispatch(&local_jobs, packet, &ctx)?;
                    reader.consume_noshift(offset);
                    continue;
                },
                Err(PcapError::Eof) => break,
                Err(PcapError::Incomplete) => {
                    if last_incomplete_index == ctx.pcap_index {
                        warn!("Could not read complete data block.");
                        warn!("Hint: the reader buffer size may be too small, or the input file nay be truncated.");
                        break;
                    }
                    last_incomplete_index = ctx.pcap_index;
                    // wait for current threads to finish
                    debug!("wait for threads (pcap_index: {})", ctx.pcap_index);
                    for (i, j) in local_jobs.iter().enumerate() {
                        debug!("waiting for job {}", i);
                        while !j.is_empty() {
                            // eprintln!("jobs[{}]: {} jobs remaining", i, j.len());
                            ::std::thread::sleep(::std::time::Duration::from_millis(1));
                        }
                    }
                    // refill the buffer
                    debug!("refill");
                    reader.refill()?;
                    continue;
                },
                Err(e) => panic!("error while reading: {:?}", e),
            }
        }

        debug!("main: exit");
        for i in 0..local_jobs.len() {
            local_jobs[i].push(Job::PrintDebug);
            local_jobs[i].push(Job::Exit);
        }
        for w in workers {
            // for w in &self.workers {
            w.handler.join().expect("panic occurred in a thread");
        }
        debug!("main: all workers ended");

        self.a.teardown();
        Ok(())
    }

    fn dispatch<'a>(
        &self,
        jobs: &Vec<Arc<SegQueue<Job<'a>>>>,
        packet: Packet<'static>,
        ctx: &ParseContext,
    ) -> Result<(), Error> {
        // get layer type and data
        let link_type = match ctx.interfaces.get(packet.interface as usize) {
            Some(if_info) => if_info.link_type,
            None => {
                warn!(
                    "Could not get link_type (missing interface info) for packet idx={}",
                    ctx.pcap_index
                );
                return Err(Error::Generic("Missing interface info"));
            }
        };
        debug!("linktype: {}", link_type);
        match packet.data {
            PacketData::L2(data) => self.handle_l2(jobs, packet, &ctx, data),
            PacketData::L3(ethertype, data) => {
                extern_dispatch_l3(
                    &jobs,
                    packet,
                    &ctx,
                    data,
                    EtherType(ethertype),
                )
            },
            PacketData::L4(_,_) => {
                warn!("Unsupported packet data layer 4");
                unimplemented!() // XXX
            },
            PacketData::Unsupported(_) => {
                warn!("Unsupported linktype {}", link_type);
                unimplemented!( ) // XXX
            },
        }
    }

    fn handle_l2<'a>(
        &self,
        jobs: &Vec<Arc<SegQueue<Job<'a>>>>,
        packet: Packet<'static>,
        ctx: &ParseContext,
        data: &'static [u8],
    ) -> Result<(), Error> {
        debug!("handle_l2 (idx={})", ctx.pcap_index);
        // resize slice to remove padding
        let datalen = min(packet.caplen as usize, data.len());
        let data = &data[..datalen];

        // let start = ::std::time::Instant::now();
        self.registry.run_plugins_l2(&packet, &data);
        // let elapsed = start.elapsed();
        // debug!("Time to run l2 plugins: {}.{}", elapsed.as_secs(), elapsed.as_millis());

        match EthernetPacket::new(data) {
            Some(eth) => {
                // debug!("    source: {}", eth.get_source());
                // debug!("    dest  : {}", eth.get_destination());
                let dest = eth.get_destination();
                if dest.0 == 1 {
                    // Multicast
                    if eth.get_destination() == MacAddr(0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc) {
                        info!("Cisco CDP/VTP/UDLD");
                        return Ok(());
                    } else if eth.get_destination() == MacAddr(0x01, 0x00, 0x0c, 0xcd, 0xcd, 0xd0) {
                        info!("Cisco Multicast address");
                        return Ok(());
                    } else {
                        info!("Ethernet broadcast (unknown type) (idx={})", ctx.pcap_index);
                    }
                }
                debug!("    ethertype: 0x{:x}", eth.get_ethertype().0);
                // self.handle_l3(&packet, &ctx, eth.payload(), eth.get_ethertype())
                let payload = &data[14..];
                extern_dispatch_l3(
                    &jobs,
                    packet,
                    &ctx,
                    payload,
                    eth.get_ethertype(),
                )
            }
            None => {
                // packet too small to be ethernet
                Ok(())
            }
        }
    }
}

fn extern_dispatch_l3<'a>(
    jobs: &Vec<Arc<SegQueue<Job<'a>>>>,
    packet: Packet<'a>,
    ctx: &ParseContext,
    data: &'a [u8],
    ethertype: EtherType,
) -> Result<(), Error> {
    let n_workers = jobs.len();
    let i = fan_out(data, ethertype, n_workers);
    debug_assert!(i < n_workers);
    jobs[i].push(Job::New(packet, ctx.clone(), data, ethertype));
    Ok(())
}

fn fan_out(data: &[u8], ethertype: EtherType, n_workers: usize) -> usize {
    match ethertype {
        EtherTypes::Ipv4 => {
            if data.len() >= 20 {
                // let src = &data[12..15];
                // let dst = &data[16..19];
                // let proto = data[9];
                // (src[0] ^ dst[0] ^ proto) as usize % n_workers
                let mut buf: [u8; 20] = [0; 20];
                let sz = 8;
                // source IP, in network-order
                buf[0] = data[12];
                buf[1] = data[13];
                buf[2] = data[14];
                buf[3] = data[15];
                // destination IP, in network-order
                buf[4] = data[16];
                buf[5] = data[17];
                buf[6] = data[18];
                buf[7] = data[19];
                // we may append source and destination ports
                // XXX breaks fragmentation
                // if data[9] == crate::plugin::TRANSPORT_TCP || data[9] == crate::plugin::TRANSPORT_UDP {
                //     if data.len() >= 24 {
                //         // source port, in network-order
                //         buf[8] = data[20];
                //         buf[9] = data[21];
                //         // destination port, in network-order
                //         buf[10] = data[22];
                //         buf[11] = data[23];
                //         sz = 12;
                //     }
                // }
                let hash = crate::toeplitz::toeplitz_hash(crate::toeplitz::KEY, &buf[..sz]);
                // debug!("{:?} -- hash --> 0x{:x}", buf, hash);
                ((hash >> 24) ^ (hash & 0xff)) as usize % n_workers
            } else {
                n_workers - 1
            }
        }
        EtherTypes::Ipv6 => {
            if data.len() >= 40 {
                let mut buf: [u8; 40] = [0; 40];
                let sz = 32;
                // source IP + destination IP, in network-order
                buf[0..32].copy_from_slice(&data[8..40]);
                // we may append source and destination ports
                // XXX breaks fragmentation
                // if data[6] == crate::plugin::TRANSPORT_TCP || data[6] == crate::plugin::TRANSPORT_UDP {
                //     if data.len() >= 44 {
                //         // source port, in network-order
                //         buf[33] = data[40];
                //         buf[34] = data[41];
                //         // destination port, in network-order
                //         buf[35] = data[42];
                //         buf[36] = data[43];
                //         sz += 4;
                //     }
                // }
                let hash = crate::toeplitz::toeplitz_hash(crate::toeplitz::KEY, &buf[..sz]);
                // debug!("{:?} -- hash --> 0x{:x}", buf, hash);
                ((hash >> 24) ^ (hash & 0xff)) as usize % n_workers
            } else {
                n_workers - 1
            }
        }
        _ => 0,
    }
}
