use std::net::IpAddr;

use pnet::packet::ipv4::Ipv4Packet;

pub fn parse_src_ipaddr(payload: &[u8]) -> Result<IpAddr, String> {
    let ipv4 = Ipv4Packet::new(payload).ok_or("Expected Ipv4 packet but not found")?;
    Result::Ok(IpAddr::V4(ipv4.get_source()))
}

pub fn parse_dst_ipaddr(payload: &[u8]) -> Result<IpAddr, String> {
    let ipv4 = Ipv4Packet::new(payload).ok_or("Expected Ipv6 packet but not found")?;
    Result::Ok(IpAddr::V4(ipv4.get_destination()))
}
