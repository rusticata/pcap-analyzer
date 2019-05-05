use crate::context::ParseContext;
use crate::error::Error;

/// Common trait for pcap/pcap-ng analyzers
pub trait PcapAnalyzer {
    /// Initialization function, call before reading pcap data (optional)
    fn init(&mut self) -> Result<(), Error> {
        Ok(())
    }

    /// Callback function for every pcap Packet read
    fn handle_packet(
        &mut self,
        packet: &pcap_parser::Packet,
        ctx: &ParseContext,
    ) -> Result<(), Error>;

    /// Teardown function, called after reading pcap data (optional)
    fn teardown(&mut self) {}
}
