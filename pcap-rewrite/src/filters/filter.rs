use libpcap_tools::{Error,Packet,ParseContext};
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
    fn filter<'i>(&self, ctx: &ParseContext, i: PacketData<'i>) -> FResult<PacketData<'i>, Error>;

    /// Does this filter plugin require a first pass to pre-analyze data? (default: `false`)
    fn require_pre_analysis(&self) -> bool {
        false
    }

    /// Pre-analysis function
    ///
    /// Any error raised in this function is fatal
    ///
    /// Note: packet content can be accessed in `packet.data`
    fn pre_analyze(&mut self, _packet: &Packet) -> Result<(), Error> {
        Ok(())
    }

    fn preanalysis_done(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

pub fn apply_filters<'d>(
    filters: &'d [Box<dyn Filter>],
    ctx: &ParseContext,
    data: PacketData<'d>,
) -> FResult<PacketData<'d>, Error> {
    filters.iter().try_fold(Verdict::Accept(data), |d, f| {
        if let Verdict::Accept(data) = d {
            f.filter(ctx, data)
        } else {
            Ok(d)
        }
    })
}
