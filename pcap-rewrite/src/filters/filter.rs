use libpcap_tools::{Packet,ParseContext};
use pcap_parser::data::PacketData;

/// Verdict emitted by a Filter
pub enum Verdict<O> {
    /// Success, and the new (filtered) data
    Accept(O),
    /// Packet must be dropped
    Drop,
}

/// Intermediate result for a Filter
pub type FResult<O, E> = Result<Verdict<O>, E>;

pub trait Filter {
    fn filter<'i>(&self, ctx: &ParseContext, i: PacketData<'i>) -> FResult<PacketData<'i>, String>;

    /// Does this filter plugin require a first pass to pre-analyze data? (default: `false`)
    fn require_pre_analysis(&self) -> bool {
        false
    }

    /// Pre-analysis function
    ///
    /// Any error raised in this function is fatal
    ///
    /// Note: packet content can be accessed in `packet.data`
    fn pre_analyze(&mut self, _packet: &Packet) -> Result<(), String> {
        Ok(())
    }

    fn preanalysis_done(&mut self) -> Result<(), String> {
        Ok(())
    }
}

pub fn apply_filters<'d>(
    filters: &'d [Box<dyn Filter>],
    ctx: &ParseContext,
    data: PacketData<'d>,
) -> FResult<PacketData<'d>, String> {
    filters.iter().try_fold(Verdict::Accept(data), |d, f| {
        if let Verdict::Accept(data) = d {
            f.filter(ctx, data)
        } else {
            Ok(d)
        }
    })
}
