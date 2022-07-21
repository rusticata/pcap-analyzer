use std::net::IpAddr;

use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::tcp::TcpPacket;
use pnet_packet::udp::UdpPacket;
use pnet_packet::Packet;
use pnet_packet::ip::IpNextHeaderProtocol;

pub fn parse_src_ipaddr(payload: &[u8]) -> Result<IpAddr, String> {
    let ipv4 = Ipv4Packet::new(payload).ok_or("Expected Ipv4 packet but not found")?;
    Result::Ok(IpAddr::V4(ipv4.get_source()))
}

pub fn parse_dst_ipaddr(payload: &[u8]) -> Result<IpAddr, String> {
    let ipv4 = Ipv4Packet::new(payload).ok_or("Expected Ipv6 packet but not found")?;
    Result::Ok(IpAddr::V4(ipv4.get_destination()))
}

pub fn parse_src_dst_ipaddr(payload: &[u8]) -> Result<(IpAddr, IpAddr), String> {
    let ipv4 = Ipv4Packet::new(payload).unwrap();
    let src_ipaddr = IpAddr::V4(ipv4.get_source());
    let dst_ipaddr = IpAddr::V4(ipv4.get_destination());
    Result::Ok((src_ipaddr, dst_ipaddr))
}

pub fn parse_src_ipaddr_proto_dst_port(
    payload: &[u8],
) -> Result<(IpAddr, IpNextHeaderProtocol, u16), String> {
    let ipv4_packet = Ipv4Packet::new(payload).ok_or("Expected Ipv4 packet but not found")?;

    let src_ipaddr = IpAddr::V4(ipv4_packet.get_source());

    match ipv4_packet.get_next_level_protocol() {
        IpNextHeaderProtocols::Tcp => {
            let ipv4_payload = ipv4_packet.payload();
            match TcpPacket::new(ipv4_payload) {
                Some(ref tcp) => {
                    let dst_port = tcp.get_destination();
                    Ok((src_ipaddr, IpNextHeaderProtocols::Tcp, dst_port))
                }
                None => Err("Expected TCP packet in Ipv4 but could not parse".to_string()),
            }
        }
        IpNextHeaderProtocols::Udp => match UdpPacket::new(ipv4_packet.payload()) {
            Some(ref udp) => {
                let dst_port = udp.get_destination();
                Ok((src_ipaddr, IpNextHeaderProtocols::Udp, dst_port))
            }
            None => Err("Expected UDP packet in Ipv4 but could not parse".to_string()),
        },
        _ => Ok((src_ipaddr, ipv4_packet.get_next_level_protocol(), 0)),
    }
}
