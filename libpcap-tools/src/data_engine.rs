use crate::analyzer::PcapAnalyzer;
use crate::block_engine::{BlockAnalyzer, BlockEngine};
use crate::config::Config;
use crate::context::*;
use crate::duration::{Duration, MICROS_PER_SEC};
use crate::engine::PcapEngine;
use crate::error::Error;
use crate::packet::Packet;
use pcap_parser::{Block, PcapBlockOwned};
use std::io::Read;

struct PcapDataAnalyzer<A: PcapAnalyzer> {
    data_analyzer: A,

    ctx: ParseContext,
    interfaces: Vec<InterfaceInfo>,
}

/// pcap/pcap-ng data analyzer engine
///
/// `PcapDataEngine` iterates over a pcap input, parses data and abstracts the
/// format (pcap datalink, endianness etc.) for the analysis.
///
/// `PcapDataEngine` stores a `PcapAnalyzer` instance, and wraps it to receive parsed data blocks.
/// Internally, it is an abstraction over a `BlockEngine`.
///
/// ## example
///
/// ```
/// use libpcap_tools::{Config, Error, Packet, ParseContext, PcapAnalyzer, PcapDataEngine, PcapEngine};
/// #[derive(Default)]
/// pub struct ExampleAnalyzer {
///     packet_count: usize,
/// }
///
/// impl PcapAnalyzer for ExampleAnalyzer {
///     fn handle_packet(&mut self, packet: &Packet, ctx: &ParseContext) -> Result<(), Error> {
///         Ok(())
///     }
/// }
///
/// let config = Config::default();
/// let analyzer = ExampleAnalyzer::default();
/// let mut engine = PcapDataEngine::new(analyzer, &config);
///
/// // `engine.run()` can take any `mut Read` as input
/// // Here, we use a cursor as an example
/// use std::io::Cursor;
/// let mut input = Cursor::new(vec![1, 2, 3, 4, 5]);
/// let res = engine.run(&mut input);
/// ```
pub struct PcapDataEngine<A: PcapAnalyzer> {
    engine: BlockEngine<PcapDataAnalyzer<A>>,
}

impl<A: PcapAnalyzer> PcapDataEngine<A> {
    pub fn new(data_analyzer: A, config: &Config) -> Self {
        let data_analyzer = PcapDataAnalyzer::new(data_analyzer);
        let engine = BlockEngine::new(data_analyzer, config);
        PcapDataEngine { engine }
    }

    pub fn data_analyzer(&self) -> &A {
        &self.engine.analyzer().data_analyzer
    }

    pub fn data_analyzer_mut(&mut self) -> &mut A {
        &mut self.engine.analyzer_mut().data_analyzer
    }
}

impl<A: PcapAnalyzer> PcapDataAnalyzer<A> {
    pub fn new(data_analyzer: A) -> Self {
        let ctx = ParseContext::default();
        let interfaces = Vec::new();
        PcapDataAnalyzer {
            data_analyzer,
            ctx,
            interfaces,
        }
    }
}

impl<A: PcapAnalyzer> PcapEngine for PcapDataEngine<A> {
    fn run(&mut self, reader: &mut dyn Read) -> Result<(), Error> {
        self.engine.run(reader)
    }
}

impl<A: PcapAnalyzer> BlockAnalyzer for PcapDataAnalyzer<A> {
    fn init(&mut self) -> Result<(), Error> {
        self.data_analyzer.init()
    }

    fn handle_block(
        &mut self,
        block: &PcapBlockOwned,
        block_ctx: &ParseBlockContext,
    ) -> Result<(), Error> {
        self.data_analyzer.handle_block(block, block_ctx)?;
        let packet = match block {
            PcapBlockOwned::NG(Block::SectionHeader(_)) => {
                // reset section-related variables
                self.interfaces = Vec::new();
                return Ok(());
            }
            PcapBlockOwned::NG(Block::InterfaceDescription(ref idb)) => {
                let if_info = pcapng_build_interface(idb);
                self.interfaces.push(if_info);
                return Ok(());
            }
            PcapBlockOwned::NG(Block::EnhancedPacket(ref epb)) => {
                self.ctx.pcap_index += 1;
                assert!((epb.if_id as usize) < self.interfaces.len());
                let if_info = &self.interfaces[epb.if_id as usize];
                let unit = if_info.ts_unit;
                let (ts_sec, ts_frac) =
                    pcap_parser::build_ts(epb.ts_high, epb.ts_low, if_info.if_tsoffset, unit);
                let unit = unit as u32; // XXX lossy cast
                let ts_usec = if unit != MICROS_PER_SEC {
                    ts_frac / (unit / MICROS_PER_SEC)
                } else {
                    ts_frac
                };
                let ts = Duration::new(ts_sec, ts_usec);
                let data = pcap_parser::data::get_packetdata(
                    epb.data,
                    if_info.link_type,
                    epb.caplen as usize,
                )
                .ok_or(Error::Generic("Parsing PacketData failed (EnhancedPacket)"))?;
                Packet {
                    interface: epb.if_id,
                    ts,
                    link_type: if_info.link_type,
                    data,
                    origlen: epb.origlen,
                    caplen: epb.caplen,
                    pcap_index: self.ctx.pcap_index,
                }
            }
            PcapBlockOwned::NG(Block::SimplePacket(ref spb)) => {
                self.ctx.pcap_index += 1;
                assert!(!self.interfaces.is_empty());
                let if_info = &self.interfaces[0];
                let blen = (spb.block_len1 - 16) as usize;
                let data = pcap_parser::data::get_packetdata(spb.data, if_info.link_type, blen)
                    .ok_or(Error::Generic("Parsing PacketData failed (SimplePacket)"))?;
                Packet {
                    interface: 0,
                    ts: Duration::default(),
                    data,
                    link_type: if_info.link_type,
                    origlen: spb.origlen,
                    caplen: if_info.snaplen,
                    pcap_index: self.ctx.pcap_index,
                }
            }
            PcapBlockOwned::LegacyHeader(ref hdr) => {
                let precision = if hdr.is_nanosecond_precision() { 9 } else { 6 };
                let ts_unit = if hdr.is_nanosecond_precision() {
                    1_000_000_000
                } else {
                    1_000_000
                };
                let if_info = InterfaceInfo {
                    link_type: hdr.network,
                    if_tsoffset: 0,
                    if_tsresol: precision,
                    ts_unit,
                    snaplen: hdr.snaplen,
                };
                self.interfaces.push(if_info);
                trace!("Legacy pcap,  link type: {}", hdr.network);
                return Ok(());
            }
            PcapBlockOwned::Legacy(ref b) => {
                self.ctx.pcap_index += 1;
                assert!(!self.interfaces.is_empty());
                let if_info = &self.interfaces[0];
                let blen = b.caplen as usize;
                let data = pcap_parser::data::get_packetdata(b.data, if_info.link_type, blen)
                    .ok_or(Error::Generic("Parsing PacketData failed (Legacy Packet)"))?;
                let ts = if if_info.if_tsresol == 6 {
                    Duration::new(b.ts_sec, b.ts_usec)
                } else {
                    Duration::new(b.ts_sec, b.ts_usec / 1000)
                };
                Packet {
                    interface: 0,
                    ts,
                    link_type: if_info.link_type,
                    data,
                    origlen: b.origlen,
                    caplen: b.caplen,
                    pcap_index: self.ctx.pcap_index,
                }
            }
            PcapBlockOwned::NG(Block::InterfaceStatistics(_))
            | PcapBlockOwned::NG(Block::NameResolution(_)) => {
                // XXX just ignore block
                return Ok(());
            }
            _ => {
                warn!("unsupported block");
                return Ok(());
            }
        };
        trace!("**************************************************************");
        // build ts
        if self.ctx.first_packet_ts.is_null() {
            self.ctx.first_packet_ts = packet.ts;
        }
        trace!("    time  : {} / {:06}", packet.ts.secs, packet.ts.micros);
        self.ctx.rel_ts = packet.ts - self.ctx.first_packet_ts; // an underflow is weird but not critical
        trace!(
            "    reltime  : {}.{:06}",
            self.ctx.rel_ts.secs,
            self.ctx.rel_ts.micros
        );
        // call data analyzer
        self.data_analyzer.handle_packet(&packet, &self.ctx)?;
        Ok(())
    }

    fn teardown(&mut self) {
        self.data_analyzer.teardown()
    }

    fn before_refill(&mut self) {
        self.data_analyzer.before_refill()
    }
}
