use crate::filter::*;
use crate::pcap::*;
use crate::pcapng::*;
use crate::traits::Writer;
use libpcap_tools::{ParseBlockContext, Error, Packet, ParseContext, PcapAnalyzer};
use pcap_parser::data::*;
use pcap_parser::Linktype;
use pcap_parser::{Block, PcapBlockOwned};
use std::io::Write;

#[derive(Copy, Clone, Debug)]
pub enum FileFormat {
    Pcap,
    PcapNG,
}

#[derive(Debug, Default)]
struct Stats {
    num_packets: u32,
    num_bytes: u64,
}

pub struct Rewriter {
    snaplen: usize,
    output_linktype: Linktype,
    output_layer: usize,
    writer: Box<dyn Writer>,
    filters: Vec<Box<dyn Filter>>,
    stats: Stats,
}

impl Rewriter {
    pub fn new(w: Box<dyn Write>, output_format: FileFormat) -> Self {
        let output_linktype = Linktype::RAW;
        let output_layer = get_linktype_layer(output_linktype);
        let writer: Box<dyn Writer> = match output_format {
            FileFormat::Pcap => Box::new(PcapWriter::new(w)),
            FileFormat::PcapNG => Box::new(PcapNGWriter::new(w)),
        };
        Rewriter {
            snaplen: 65535, // XXX
            output_linktype,
            output_layer,
            writer,
            filters: Vec::new(),
            stats: Stats::default(),
        }
    }
}

fn convert_layer<'p>(input: &'p PacketData, output_layer: usize) -> Result<&'p [u8], &'static str> {
    match (input, output_layer) {
        (PacketData::L2(data), 2) => Ok(data),
        (PacketData::L2(data), 3) => {
            if data.len() < 14 {
                return Err("L2 data too small for ethernet");
            }
            Ok(&data[14..])
        }
        (PacketData::L3(_, _), 2) => Err("Can't convert L3 data to L2"),
        (PacketData::L3(_, data), 3) => Ok(data),
        (PacketData::L4(_, _), _) => Err("Input is L4 - don't know what to do"),
        (PacketData::Unsupported(_), _) => Err("Input link type not supported"),
        (_, _) => Err("Invalid layer conversion"),
    }
}

fn get_linktype_layer(l: Linktype) -> usize {
    match l {
        Linktype::RAW => 3,
        _ => panic!("Unsupported output link type"),
    }
}

impl PcapAnalyzer for Rewriter {
    fn init(&mut self) -> Result<(), Error> {
        self.writer.init_file(self.snaplen, self.output_linktype)?;
        Ok(())
    }

    fn handle_block(&mut self, block: &PcapBlockOwned, _block_ctx: &ParseBlockContext)  -> Result<(), Error> {
        // handle specific pcapng blocks
        if let PcapBlockOwned::NG(b) = block {
            match b {
                // skip data blocks, processed in `handle_packet`
                Block::SimplePacket(_) | Block::EnhancedPacket(_) => (),
                _ => {
                    self.writer
                        .write_block(block)
                        .expect("Could not write packet");
                }
            }
        }
        // legacy packets are processed in `handle_packet`
        Ok(())
    }

    fn handle_packet(&mut self, packet: &Packet, ctx: &ParseContext) -> Result<(), Error> {
        let link_type = packet.link_type;
        // let snaplen = if_info.snaplen;
        // debug!("snaplen: {}", snaplen);
        // apply filters
        let data = match apply_filters(&self.filters, packet.data.clone()) {
            FResult::Ok(d) => d,
            FResult::Drop => {
                return Ok(());
            }
            FResult::Error(e) => panic!("Filter fatal error: {}", e),
        };
        // convert data
        let data = convert_layer(&data, self.output_layer).map_err(Error::Generic)?;
        // truncate it to new snaplen
        let data = {
            if self.snaplen > 0 && data.len() > self.snaplen {
                info!(
                    "truncating index {} to {} bytes",
                    ctx.pcap_index, self.snaplen
                );
                &data[..self.snaplen as usize]
            } else {
                data
            }
        };
        debug!(
            "Writing packet {} with link_type {} ({} bytes)",
            ctx.pcap_index,
            link_type,
            data.len()
        );
        let written = self.writer.write_packet(packet, data)?;
        self.stats.num_packets += 1;
        self.stats.num_bytes += written as u64;

        Ok(())
    }

    fn teardown(&mut self) {
        info!("Done.");
        info!("Stats: {:?}", self.stats);
    }
}
