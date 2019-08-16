use crate::config::Config;
use crate::packet::Packet;
use pcap_parser::*;
use std::io::Read;

use crate::analyzer::PcapAnalyzer;
use crate::context::*;
use crate::duration::{Duration, MICROS_PER_SEC};
use crate::error::Error;

/// pcap/pcap-ng analyzer engine
pub struct PcapEngine {
    a: Box<dyn PcapAnalyzer>,
    buffer_max_size: usize,
    buffer_initial_capacity: usize,
}

impl PcapEngine {
    /// Build a new PcapEngine, taking ownership of the input PcapAnalyzer
    pub fn new(a: Box<dyn PcapAnalyzer>, config: &Config) -> Self {
        let buffer_max_size = config.get_usize("buffer_max_size").unwrap_or(65536 * 8);
        let buffer_initial_capacity = config
            .get_usize("buffer_initial_capacity")
            .unwrap_or(16384 * 8);
        PcapEngine {
            a,
            buffer_max_size,
            buffer_initial_capacity,
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

        loop {
            ctx.pcap_index += 1;
            match reader.next() {
                Ok((offset, block)) => {
                    let packet = match block {
                        PcapBlockOwned::NG(Block::SectionHeader(ref _shb)) => {
                            debug!("pcap-ng: new section");
                            ctx.interfaces = Vec::new();
                            reader.consume(offset);
                            continue;
                        },
                        PcapBlockOwned::NG(Block::InterfaceDescription(ref idb)) => {
                            let if_info = pcapng_build_interface(idb);
                            ctx.interfaces.push(if_info);
                            reader.consume(offset);
                            continue;
                        },
                        PcapBlockOwned::NG(Block::EnhancedPacket(ref epb)) => {
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
                            reader.consume(offset);
                            continue;
                        },
                        PcapBlockOwned::Legacy(ref b) => {
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
                            reader.consume(offset);
                            continue;
                        },
                        _ => {
                            warn!("unsupported block");
                            reader.consume(offset);
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
                    self.a
                        .handle_packet(&packet, &ctx)
                        .or(Err("Analyzer error"))?;
                    reader.consume(offset);
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
                    // refill the buffer
                    debug!("refill");
                    reader.refill()?;
                    continue;
                },
                Err(e) => panic!("error while reading: {:?}", e),
            }
        }

        self.a.teardown();
        Ok(())
    }
}
