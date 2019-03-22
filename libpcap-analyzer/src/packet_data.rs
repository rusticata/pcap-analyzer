use crate::five_tuple::FiveTuple;
use crate::flow::Flow;

pub struct PacketData<'a, 't, 'f> {
    pub five_tuple: &'t FiveTuple,
    /// true if this packet is in same direction as the first packet
    /// seen in this flow
    pub to_server: bool,
    pub l3_type: u16,
    pub l3_data: &'a [u8],
    pub l4_type: u8,
    pub l4_data: Option<&'a [u8]>,
    pub flow: Option<&'f Flow>,
}
