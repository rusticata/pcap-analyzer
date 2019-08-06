use libpcap_tools::{FiveTuple, Flow};

pub struct PacketInfo<'l3, 'l4, 't, 'f> {
    /// The five-tuple for *this packet*
    pub five_tuple: &'t FiveTuple,
    /// true if this packet is in same direction as the first packet
    /// seen in this flow
    pub to_server: bool,
    pub l3_type: u16,
    /// Raw L4 data
    pub l4_data: &'l3 [u8],
    /// L4 payload type
    pub l4_type: u8,
    /// L4 payload, if protocol is known by core engine
    pub l4_payload: Option<&'l4 [u8]>,
    pub flow: Option<&'f Flow>,
    pub pcap_index: usize,
}
