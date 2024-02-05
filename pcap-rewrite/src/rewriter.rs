use crate::filters::filter::*;
use crate::pcap::*;
use crate::pcapng::*;
use crate::traits::Writer;
use libpcap_tools::{Error, Packet, ParseBlockContext, ParseContext, PcapAnalyzer};
use log::{debug, error, info};
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
    run_pre_analysis: bool,
}

#[allow(dead_code)]
impl Rewriter {
    pub fn new(
        output: Box<dyn Write>,
        output_format: FileFormat,
        filters: Vec<Box<dyn Filter>>,
    ) -> Self {
        let output_linktype = Linktype::RAW;
        let output_layer = get_linktype_layer(output_linktype);
        let writer: Box<dyn Writer> = match output_format {
            FileFormat::Pcap => Box::new(PcapWriter::new(output)),
            FileFormat::PcapNG => Box::new(PcapNGWriter::new(output)),
        };
        Rewriter {
            snaplen: 65535, // XXX
            output_linktype,
            output_layer,
            writer,
            filters,
            stats: Stats::default(),
            run_pre_analysis: false,
        }
    }

    /// Return true if one of the plugins or more require a pre-analysis pass
    pub fn require_pre_analysis(&self) -> bool {
        self.filters
            .iter()
            .fold(false, |acc, filter| acc | filter.require_pre_analysis())
    }

    /// Set the rewriter's run pre analysis.
    pub fn set_run_pre_analysis(&mut self, run_pre_analysis: bool) {
        self.run_pre_analysis = run_pre_analysis;
    }

    /// Add a filter to the list
    pub fn push_filter(&mut self, f: Box<dyn Filter>) {
        self.filters.push(f);
    }

    /// Return an iterator over the filters
    pub fn filters(&self) -> impl Iterator<Item = &Box<dyn Filter>> {
        self.filters.iter()
    }

    /// Return a mutable iterator over the filters
    pub fn filters_mut(&mut self) -> impl Iterator<Item = &mut Box<dyn Filter>> {
        self.filters.iter_mut()
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
        if !self.run_pre_analysis {
            self.writer.init_file(self.snaplen, self.output_linktype)?;
        }
        Ok(())
    }

    fn handle_block(
        &mut self,
        block: &PcapBlockOwned,
        _block_ctx: &ParseBlockContext,
    ) -> Result<(), Error> {
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

        if self.run_pre_analysis {
            // run pre-analysis plugins
            for p in self.filters.iter_mut() {
                if let Err(e) = p.pre_analyze(packet) {
                    error!("Pre-analysis plugin returned fatal error {}", e);
                    return Err(Error::Generic("Pre-analysis fatal error"));
                }
            }
            return Ok(());
        }

        // apply filters
        let data = match apply_filters(&self.filters, packet.data.clone()) {
            Ok(Verdict::Accept(d)) => d,
            Ok(Verdict::Drop) => {
                return Ok(());
            }
            Err(e) => panic!("Filter fatal error: {}", e),
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
                &data[..self.snaplen]
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
        if self.run_pre_analysis {
            info!("Pre-analysis done.");
            self.run_pre_analysis = false;
            
            for filter in self.filters.iter_mut() {
                if let Err(e) = filter.preanalysis_done() {
                    panic!("Pre-analysis filter returned fatal error in post preanalysis function {}", e);
                }
            }

            return;
        }
        info!("Done.");
        info!("Stats: {:?}", self.stats);
    }
}
