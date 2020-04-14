use pnet_packet::ethernet::EtherTypes;
use pnet_packet::ip::IpNextHeaderProtocols;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum LinkLayerType {
    Ethernet = 0x1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum NetworkLayerType {
    Ipv4 = EtherTypes::Ipv4.0,
    Ipv6 = EtherTypes::Ipv6.0,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum TransportLayerType {
    Icmp = IpNextHeaderProtocols::Icmp.0 as u16,
    Tcp = IpNextHeaderProtocols::Tcp.0 as u16,
    Udp = IpNextHeaderProtocols::Udp.0 as u16,
}
