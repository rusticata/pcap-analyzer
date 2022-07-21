use std::net::IpAddr;

use pnet_packet::ip::IpNextHeaderProtocol;
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv6::Ipv6Packet;
use pnet_packet::tcp::TcpPacket;
use pnet_packet::udp::UdpPacket;

use crate::filters::ipv6_utils;
use libpcap_tools::FiveTuple;

pub fn parse_src_ipaddr(payload: &[u8]) -> Result<IpAddr, String> {
    let ipv6 = Ipv6Packet::new(payload).ok_or("Expected Ipv6 packet but not found")?;
    Ok(IpAddr::V6(ipv6.get_source()))
}

pub fn parse_dst_ipaddr(payload: &[u8]) -> Result<IpAddr, String> {
    let ipv6 = Ipv6Packet::new(payload).ok_or("Expected Ipv6 packet but not found")?;
    Ok(IpAddr::V6(ipv6.get_destination()))
}

pub fn parse_src_dst_ipaddr(payload: &[u8]) -> Result<(IpAddr, IpAddr), String> {
    let ipv6_packet = Ipv6Packet::new(payload).ok_or("Expected Ipv6 packet but not found")?;
    let src_ipaddr = IpAddr::V6(ipv6_packet.get_source());
    let dst_ipaddr = IpAddr::V6(ipv6_packet.get_destination());
    Result::Ok((src_ipaddr, dst_ipaddr))
}

pub fn parse_src_ipaddr_proto_dst_port(
    payload: &[u8],
) -> Result<(IpAddr, IpNextHeaderProtocol, u16), String> {
    let ipv6_packet = Ipv6Packet::new(payload).ok_or("Expected Ipv6 packet but not found")?;

    let src_ipaddr = IpAddr::V6(ipv6_packet.get_source());

    let (_fragment_packet_option, l4_proto, payload) =
        ipv6_utils::get_fragment_packet_option_l4_protol4_payload(payload, &ipv6_packet)?;

    match l4_proto {
        IpNextHeaderProtocols::Tcp => match TcpPacket::new(payload) {
            Some(ref tcp) => {
                let dst_port = tcp.get_destination();
                Ok((src_ipaddr, IpNextHeaderProtocols::Tcp, dst_port))
            }
            None => Err("Expected TCP packet in Ipv6 but could not parse".to_string()),
        },
        IpNextHeaderProtocols::Udp => match UdpPacket::new(payload) {
            Some(ref udp) => {
                let dst_port = udp.get_destination();
                Ok((src_ipaddr, IpNextHeaderProtocols::Udp, dst_port))
            }
            None => Err("Expected UDP packet in Ipv6 but could not parse".to_string()),
        },
        _ => Ok((src_ipaddr, l4_proto, 0)),
    }
}

pub fn parse_five_tuple(payload: &[u8]) -> Result<FiveTuple, String> {
    let ipv6_packet = Ipv6Packet::new(payload).ok_or("Expected Ipv6 packet but not found")?;

    let src_ipaddr = IpAddr::V6(ipv6_packet.get_source());
    let dst_ipaddr = IpAddr::V6(ipv6_packet.get_destination());

    let (_fragment_packet_option, l4_proto, payload) =
        ipv6_utils::get_fragment_packet_option_l4_protol4_payload(payload, &ipv6_packet)?;

    match l4_proto {
        IpNextHeaderProtocols::Tcp => match TcpPacket::new(payload) {
            Some(ref tcp) => {
                let src_port = tcp.get_source();
                let dst_port = tcp.get_destination();
                Ok(FiveTuple {
                    src: src_ipaddr,
                    dst: dst_ipaddr,
                    proto: 6_u8,
                    src_port,
                    dst_port,
                })
            }
            None => Err("Expected TCP packet in Ipv6 but could not parse".to_string()),
        },
        IpNextHeaderProtocols::Udp => match UdpPacket::new(payload) {
            Some(ref udp) => {
                let src_port = udp.get_source();
                let dst_port = udp.get_destination();
                Ok(FiveTuple {
                    src: src_ipaddr,
                    dst: dst_ipaddr,
                    proto: 17_u8,
                    src_port,
                    dst_port,
                })
            }
            None => Err("Expected UDP packet in Ipv6 but could not parse".to_string()),
        },
        _ => Ok(FiveTuple {
            src: src_ipaddr,
            dst: dst_ipaddr,
            proto: l4_proto.0,
            src_port: 0,
            dst_port: 0,
        }),
    }
}
