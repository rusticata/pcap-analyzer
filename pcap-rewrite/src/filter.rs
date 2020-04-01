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
