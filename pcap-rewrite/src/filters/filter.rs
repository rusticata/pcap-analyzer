use libpcap_tools::Packet;
use pcap_parser::data::PacketData;

/// Intermediate result for a Filter
pub enum FResult<O, E> {
    /// Success, and the new (filtered) data
    Ok(O),
    /// Packet must be dropped
    Drop,
    /// A fatal error occured
    Error(E),
}

pub trait Filter {
    fn filter<'i>(&self, i: PacketData<'i>) -> FResult<PacketData<'i>, String>;

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
}

pub fn apply_filters<'d>(
    filters: &'d [Box<dyn Filter>],
    data: PacketData<'d>,
) -> FResult<PacketData<'d>, String> {
    filters.iter().fold(FResult::Ok(data), |d, f| {
        if let FResult::Ok(data) = d {
            f.filter(data)
        } else {
            d
        }
    })
}
