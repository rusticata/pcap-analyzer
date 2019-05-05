use crate::context::ParseContext;
use crate::error::Error;

/// Common trait for pcap/pcap-ng analyzers
pub trait PcapAnalyzer {
    fn init(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn handle_packet(
        &mut self,
        packet: &pcap_parser::Packet,
        ctx: &ParseContext,
    ) -> Result<(), Error>;

    fn teardown(&mut self) {}
}
