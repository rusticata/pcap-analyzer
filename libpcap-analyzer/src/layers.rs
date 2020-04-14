use pnet_packet::ethernet::EtherTypes;
use pnet_packet::ip::IpNextHeaderProtocols;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum LinkLayerType {
    Ethernet = 0x1,
}
