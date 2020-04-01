use pcap_parser::data::PacketData;

pub enum FResult<O, E> {
    Ok(O),
    Drop,
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
