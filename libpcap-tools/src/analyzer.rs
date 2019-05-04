use crate::context::ParseContext;

/// Common trait for pcap/pcap-ng analyzers
pub trait PcapAnalyzer {
    fn init(&mut self) {}

    fn handle_packet(&mut self, packet: &pcap_parser::Packet, ctx: &ParseContext);

    fn teardown(&mut self) {}
}
