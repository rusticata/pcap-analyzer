use circular::Buffer;
use nom::{HexDisplay, IResult, Needed, Offset};
use pcap_parser::*;
use std::cmp::min;
use std::io::Read;

use crate::analyzer::PcapAnalyzer;
use crate::context::*;
use crate::duration::Duration;
use crate::error::Error;

/// pcap/pcap-ng analyzer engine
pub struct PcapEngine {
    a: Box<PcapAnalyzer>,
}

enum PcapType {
    // Unknown,
    Pcap,
    PcapBE,
    PcapNG,
    PcapNGBE,
}

impl PcapEngine {
    pub fn new(a: Box<PcapAnalyzer>) -> Self {
        PcapEngine { a }
    }

    /// Main function: for a reader, read all pcap data and run all plugins
    pub fn run<R: Read>(&mut self, f: &mut R) -> Result<(), Error> {
        let mut capacity = 16384 * 8;
        let buffer_max_size = 65536 * 8;
        let mut b = Buffer::with_capacity(capacity);
        let sz = f.read(b.space())?;
        b.fill(sz);

        self.a.init()?;
        let mut ctx = ParseContext::default();

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
                    match get_next_packet(b.data(), &mut ctx) {
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
                                self.a.handle_packet(&packet, &ctx).or(Err("Analyzer error"))?;
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
                b.consume(length);
                consumed += length;
            }

            if let Some(Needed::Size(sz)) = needed {
                if sz > b.capacity() {
                    // println!("growing buffer capacity from {} bytes to {} bytes", capacity, capacity*2);
                    capacity = (capacity * 3) / 2;
                    if capacity > buffer_max_size {
                        warn!(
                            "requesting capacity {} over buffer_max_size {}",
                            capacity, buffer_max_size
                        );
                        return Err(Error::Generic("buffer size too small"));
                    }
                    b.grow(capacity);
                } else {
                    // eprintln!("incomplete, but less missing bytes {} than buffer size {} consumed {}", sz, capacity, consumed);
                    if last_incomplete_offset == consumed {
                        warn!("seems file is truncated, exiting");
                        break;
                    }
                    last_incomplete_offset = consumed;
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

        self.a.teardown();
        Ok(())
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
