use libpcap_tools::{FiveTuple, Flow};

pub struct PacketData<'l3, 'l4, 't, 'f> {
    pub five_tuple: &'t FiveTuple,
    /// true if this packet is in same direction as the first packet
    /// seen in this flow
    pub to_server: bool,
    pub l3_type: u16,
    pub l3_data: &'l3 [u8],
    pub l4_type: u8,
    /// L4 data, if protocol is known by core engine
    pub l4_data: Option<&'l4 [u8]>,
    pub flow: Option<&'f Flow>,
}
