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

pub fn parse_src_dst_ipaddr(payload: &[u8]) -> Result<(IpAddr, IpAddr),String> {
    let ipv6 = Ipv6Packet::new(payload).unwrap();
    let src_ipaddr = IpAddr::V6(ipv6.get_source());
    let dst_ipaddr = IpAddr::V6(ipv6.get_destination());
    Result::Ok((src_ipaddr, dst_ipaddr))
}