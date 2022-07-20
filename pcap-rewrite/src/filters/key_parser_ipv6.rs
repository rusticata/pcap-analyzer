use pnet_packet::ipv6::Ipv6Packet;
use std::net::IpAddr;

pub fn parse_src_ipaddr(payload: &[u8]) -> Result<IpAddr, String> {
    let ipv6 = Ipv6Packet::new(payload).ok_or("Expected Ipv6 packet but not found")?;
    Ok(IpAddr::V6(ipv6.get_source()))
}

pub fn parse_dst_ipaddr(payload: &[u8]) -> Result<IpAddr, String> {
    let ipv6 = Ipv6Packet::new(payload).ok_or("Expected Ipv6 packet but not found")?;
    Ok(IpAddr::V6(ipv6.get_destination()))
}
