use crate::pcap::*;
use crate::traits::Writer;
use libpcap_tools::{Error, Packet, ParseContext, PcapAnalyzer};

use pcap_parser::data::*;
use pcap_parser::Linktype;
use std::io::Write;

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
    stats: Stats,
}

impl Rewriter {
    pub fn new(w: Box<dyn Write>) -> Self {
        let output_linktype = Linktype::RAW;
        let output_layer = get_linktype_layer(output_linktype);
        let writer = Box::new(PcapWriter::new(w));
        Rewriter {
            snaplen: 65535, // XXX
            output_linktype,
            output_layer,
            writer,
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

    fn handle_packet(&mut self, packet: &Packet, ctx: &ParseContext) -> Result<(), Error> {
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
        // convert data
        let data = convert_layer(&packet.data, self.output_layer).map_err(|e| Error::Generic(e))?;
        // truncate it to new snaplen
        let data = {
            if data.len() > self.snaplen {
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
        let written = self.writer.write_packet(&packet, data)?;
        self.stats.num_packets += 1;
        self.stats.num_bytes += written as u64;

        Ok(())
    }

    fn teardown(&mut self) {
        info!("Done.");
        info!("Stats: {:?}", self.stats);
    }
}
