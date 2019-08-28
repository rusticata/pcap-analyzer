use crate::context::ParseContext;
use crate::error::Error;
use crate::packet::Packet;

/// Common trait for pcap/pcap-ng analyzers
pub trait PcapAnalyzer {
    /// Initialization function, call before reading pcap data (optional)
    fn init(&mut self) -> Result<(), Error> {
        Ok(())
    }

    /// Callback function for every pcap Packet containing data
    fn handle_packet(
        &mut self,
        packet: &Packet,
        ctx: &ParseContext,
    ) -> Result<(), Error>;

    /// Teardown function, called after reading pcap data (optional)
    fn teardown(&mut self) {}

    fn before_refill(&mut self) {}
}

/// Common trait for pcap/pcap-ng analyzers (thread-safe version)
pub trait SafePcapAnalyzer: PcapAnalyzer + Send + Sync {}
