use crate::analyzer::*;
use crate::plugin_registry::PluginRegistry;
use circular::Buffer;
use nom::{HexDisplay, IResult, Needed, Offset};
use pcap_parser::*;
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
        pcap_parser::Packet<'a>,
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
    buffer_max_size: usize,
    buffer_initial_capacity: usize,
    n_workers: usize,
}

enum PcapType {
    Pcap,
    PcapBE,
    PcapNG,
    PcapNGBE,
}

impl ThreadedPcapEngine {
    /// Build a new ThreadedPcapEngine, taking ownership of the input PcapAnalyzer
    pub fn new(a: Box<Analyzer>, registry: PluginRegistry, config: &Config) -> Self {
        let buffer_max_size = config.get_usize("buffer_max_size").unwrap_or(65536 * 8);
        let buffer_initial_capacity = config
            .get_usize("buffer_initial_capacity")
            .unwrap_or(16384 * 8);
        let n_workers = config.get_usize("num_threads").unwrap_or(num_cpus::get());
        ThreadedPcapEngine {
            a,
            registry: Arc::new(registry),
            buffer_max_size,
            buffer_initial_capacity,
            n_workers,
        }
    }

    /// Main function: given a reader, read all pcap data and call analyzer for each Packet
    pub fn run<R: Read>(&mut self, f: &mut R) -> Result<(), Error> {
        let mut capacity = self.buffer_initial_capacity;
        let mut b = Buffer::with_capacity(capacity);
        let sz = f.read(b.space())?;
        b.fill(sz);

        self.a.init()?;
        let mut ctx = ParseContext::default();
        ctx.pcap_index = 1;

        let (length, in_pcap_type) = {
            if let Ok((remaining, h)) = pcapng::parse_sectionheaderblock(b.data()) {
                ctx.bigendian = h.is_bigendian();
                if h.is_bigendian() {
                    (b.data().offset(remaining), PcapType::PcapNGBE)
                } else {
                    (b.data().offset(remaining), PcapType::PcapNG)
                }
            } else if let Ok((remaining, h)) = pcap::parse_pcap_header(b.data()) {
                let if_info = InterfaceInfo {
                    link_type: Linktype(h.network),
                    if_tsresol: 0,
                    if_tsoffset: 0,
                };
                ctx.interfaces.push(if_info);
                ctx.bigendian = h.is_bigendian();
                if h.is_bigendian() {
                    (b.data().offset(remaining), PcapType::PcapBE)
                } else {
                    (b.data().offset(remaining), PcapType::Pcap)
                }
            } else {
                return Err(Error::Generic("couldn't parse input file header"));
            }
        };

        // println!("consumed {} bytes", length);
        b.consume(length);

        let mut consumed = length;
        let mut last_incomplete_offset = 0;

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

        let get_next_packet = match in_pcap_type {
            PcapType::Pcap => pcap_get_raw_data,
            PcapType::PcapBE => pcap_get_raw_data_be,
            PcapType::PcapNG => pcapng_get_raw_data,
            PcapType::PcapNGBE => pcapng_get_raw_data_be,
        };
        loop {
            let needed: Option<Needed>;

            // println!("{}", (&b.data()[..min(b.available_data(), 128)]).to_hex(16));

            loop {
                let length = {
                    // read block
                    let data = b.data();
                    let data_unsafe =
                        unsafe { ::std::slice::from_raw_parts(data.as_ptr(), data.len()) };
                    match get_next_packet(data_unsafe, &mut ctx) {
                        Ok((remaining, opt_packet)) => {
                            // eprintln!("parse_block ok, index {}", pcap_index);
                            // println!("parsed packet: {:?}", opt_packet);

                            if let Some(packet) = opt_packet {
                                debug!("**************************************************************");
                                let ts = Duration::new(packet.header.ts_sec, packet.header.ts_usec);
                                if ctx.pcap_index == 1 {
                                    ctx.first_packet_ts = ts;
                                }
                                debug!(
                                    "    time  : {} / {}",
                                    packet.header.ts_sec, packet.header.ts_usec
                                );
                                ctx.rel_ts = ts - ctx.first_packet_ts; // an underflow is weird but not critical
                                debug!("    reltime  : {}.{}", ctx.rel_ts.secs, ctx.rel_ts.micros);
                                self.dispatch(&local_jobs, packet, &ctx)?;
                                ctx.pcap_index += 1;
                            }

                            b.data().offset(remaining)
                        }
                        Err(nom::Err::Incomplete(n)) => {
                            // println!("not enough data, needs a refill: {:?}", n);

                            needed = Some(n);
                            break;
                        }
                        Err(nom::Err::Failure(e)) => {
                            error!("pcap parse failure: {:?}", e);
                            return Err(Error::Generic("parse error"));
                        }
                        Err(nom::Err::Error(_e)) => {
                            // panic!("parse error: {:?}", e);
                            error!("Error while parsing pcap data");
                            debug!("{:?}", _e);
                            debug!("{}", (&b.data()[..min(b.available_data(), 128)]).to_hex(16));
                            return Err(Error::Generic("parse error"));
                        }
                    }
                };
                // println!("consuming {} of {} bytes", length, b.available_data());
                b.consume_noshift(length);
                consumed += length;
            }

            if let Some(Needed::Size(sz)) = needed {
                if sz > b.capacity() {
                    // println!("growing buffer capacity from {} bytes to {} bytes", capacity, capacity*2);
                    capacity = (capacity * 3) / 2;
                    if capacity > self.buffer_max_size {
                        warn!(
                            "requesting capacity {} over buffer_max_size {}",
                            capacity, self.buffer_max_size
                        );
                        return Err(Error::Generic("buffer size too small"));
                    }
                    debug!("grow (refill?)");
                    b.grow(capacity);
                } else {
                    // eprintln!("incomplete, but less missing bytes {} than buffer size {} consumed {}", sz, capacity, consumed);
                    // XXX if last_incomplete_offset == consumed {
                    // XXX     warn!("seems file is truncated, exiting (idx={})", ctx.pcap_index);
                    // XXX     break;
                    // XXX }
                    last_incomplete_offset = consumed;
                    // wait for current threads to finish
                    // eprintln!("wait for threads (pcap_index: {})", ctx.pcap_index);
                    for (i, j) in local_jobs.iter().enumerate() {
                        debug!("waiting for job {}", i);
                        while !j.is_empty() {
                            // eprintln!("jobs[{}]: {} jobs remaining", i, j.len());
                            ::std::thread::sleep(::std::time::Duration::from_millis(1));
                        }
                    }
                    debug!("refill");
                    // refill the buffer
                    let sz = f.read(b.space())?;
                    b.fill(sz);
                    // println!("refill: {} more bytes, available data: {} bytes, consumed: {} bytes",
                    //          sz, b.available_data(), consumed);

                    // if there's no more available data in the buffer after a write, that means we reached
                    // the end of the file
                    if b.available_data() == 0 {
                        // println!("no more data to read or parse, stopping the reading loop");
                        break;
                    }
                }
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
        packet: pcap_parser::Packet<'static>,
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
        let (layer_type, data) = get_packet_data(link_type, &packet)?;
        match layer_type {
            LayerType::L2 => self.handle_l2(jobs, packet, &ctx),
            LayerType::L3(ethertype) => {
                extern_dispatch_l3(
                    &jobs,
                    packet,
                    &ctx,
                    data,
                    EtherType(ethertype),
                )
            }
        }
    }

    fn handle_l2<'a>(
        &self,
        jobs: &Vec<Arc<SegQueue<Job<'a>>>>,
        packet: pcap_parser::Packet<'static>,
        ctx: &ParseContext,
    ) -> Result<(), Error> {
        debug!("handle_l2 (idx={})", ctx.pcap_index);
        // resize slice to remove padding
        let datalen = min(packet.header.caplen as usize, packet.data.len());
        let data = &packet.data[..datalen];

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
    packet: pcap_parser::Packet<'a>,
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
            unimplemented!();
        }
        _ => 0,
    }
}

fn pcap_get_raw_data<'a, 'ctx>(
    i: &'a [u8],
    _ctx: &'ctx mut ParseContext,
) -> IResult<&'a [u8], Option<pcap_parser::Packet<'a>>> {
    pcap::parse_pcap_frame(i).map(|(rem, p)| (rem, Some(p)))
}

fn pcap_get_raw_data_be<'a, 'ctx>(
    i: &'a [u8],
    _ctx: &'ctx mut ParseContext,
) -> IResult<&'a [u8], Option<pcap_parser::Packet<'a>>> {
    pcap::parse_pcap_frame_be(i).map(|(rem, p)| (rem, Some(p)))
}

fn pcapng_get_raw_cont<'a, 'ctx>(
    i: &'a [u8],
    block: Block<'a>,
    ctx: &'ctx mut ParseContext,
) -> (&'a [u8], Option<pcap_parser::Packet<'a>>) {
    match block {
        Block::SectionHeader(ref _hdr) => {
            warn!("new section header block");
            // XXX we may have to change endianess
            // XXX invalidate all interfaces
            // (i, None)
            unimplemented!();
        }
        Block::InterfaceDescription(ref ifdesc) => {
            let if_info = pcapng_build_interface(ifdesc);
            ctx.interfaces.push(if_info);
            (i, None)
        }
        Block::EnhancedPacket(ref p) => {
            let if_info = match ctx.interfaces.get(p.if_id as usize) {
                Some(if_info) => if_info,
                None => {
                    warn!("Could not get interface for EnhancedPacket");
                    return (i, None);
                }
            };
            match pcapng_build_packet(if_info, block) {
                Some(packet) => (i, Some(packet)),
                None => {
                    warn!("could not convert block to packet (idx={})", ctx.pcap_index);
                    (i, None)
                }
            }
        }
        Block::SimplePacket(_) => {
            let if_info = match ctx.interfaces.first() {
                Some(if_info) => if_info,
                None => {
                    warn!("Could not get interface for SimplePacket");
                    return (i, None);
                }
            };
            match pcapng_build_packet(if_info, block) {
                Some(packet) => (i, Some(packet)),
                None => {
                    warn!("could not convert block to packet (idx={})", ctx.pcap_index);
                    (i, None)
                }
            }
        }
        // ignore some block types
        Block::InterfaceStatistics(_) => (i, None),
        // warn if parser does not recognize block
        Block::Unknown(ref block) => {
            warn!("pcap-ng: unknown block (type = 0x{:x})", block.block_type);
            (i, None)
        }
    }
}

fn pcapng_get_raw_data<'a, 'ctx>(
    i: &'a [u8],
    ctx: &'ctx mut ParseContext,
) -> IResult<&'a [u8], Option<pcap_parser::Packet<'a>>> {
    pcapng::parse_block(i).map(|(rem, block)| pcapng_get_raw_cont(rem, block, ctx))
}

fn pcapng_get_raw_data_be<'a, 'ctx>(
    i: &'a [u8],
    ctx: &'ctx mut ParseContext,
) -> IResult<&'a [u8], Option<pcap_parser::Packet<'a>>> {
    pcapng::parse_block_be(i).map(|(rem, block)| pcapng_get_raw_cont(rem, block, ctx))
}
