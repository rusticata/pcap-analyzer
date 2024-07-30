use std::net::IpAddr;

use pnet_packet::ip::IpNextHeaderProtocol;
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::tcp::TcpPacket;
use pnet_packet::udp::UdpPacket;
use pnet_packet::Packet;

use libpcap_tools::{Error, FiveTuple, ParseContext};

use super::fragmentation::two_tuple_proto_ipid::TwoTupleProtoIpid;
use super::fragmentation::two_tuple_proto_ipid_five_tuple::TwoTupleProtoIpidFiveTuple;

pub fn parse_src_ipaddr(_ctx: &ParseContext, payload: &[u8]) -> Result<IpAddr, Error> {
    let ipv4 =
        Ipv4Packet::new(payload).ok_or(Error::Pnet("Expected Ipv4 packet but could not parse"))?;
    Result::Ok(IpAddr::V4(ipv4.get_source()))
}

pub fn parse_dst_ipaddr(_ctx: &ParseContext, payload: &[u8]) -> Result<IpAddr, Error> {
    let ipv4 =
        Ipv4Packet::new(payload).ok_or(Error::Pnet("Expected Ipv6 packet but could not parse"))?;
    Result::Ok(IpAddr::V4(ipv4.get_destination()))
}

pub fn parse_src_dst_ipaddr(
    _ctx: &ParseContext,
    payload: &[u8],
) -> Result<(IpAddr, IpAddr), Error> {
    let ipv4_packet =
        Ipv4Packet::new(payload).ok_or(Error::Pnet("Expected Ipv4 packet but could not parse"))?;
    let src_ipaddr = IpAddr::V4(ipv4_packet.get_source());
    let dst_ipaddr = IpAddr::V4(ipv4_packet.get_destination());
    Result::Ok((src_ipaddr, dst_ipaddr))
}

pub fn parse_src_ipaddr_proto_dst_port(
    ctx: &ParseContext,
    payload: &[u8],
) -> Result<(IpAddr, IpNextHeaderProtocol, u16), Error> {
    let ipv4_packet =
        Ipv4Packet::new(payload).ok_or(Error::Pnet("Expected Ipv4 packet but could not parse"))?;

    let src_ipaddr = IpAddr::V4(ipv4_packet.get_source());

    match ipv4_packet.get_next_level_protocol() {
        IpNextHeaderProtocols::Tcp => {
            let ipv4_payload = libpcap_analyzer::extract_payload_l3_ipv4(ctx, &ipv4_packet)?;
            match TcpPacket::new(ipv4_payload) {
                Some(ref tcp) => {
                    let dst_port = tcp.get_destination();
                    Ok((src_ipaddr, IpNextHeaderProtocols::Tcp, dst_port))
                }
                None => Err(Error::Pnet(
                    "Expected TCP packet in Ipv4 but could not parse",
                )),
            }
        }
        IpNextHeaderProtocols::Udp => match UdpPacket::new(ipv4_packet.payload()) {
            Some(ref udp) => {
                let dst_port = udp.get_destination();
                Ok((src_ipaddr, IpNextHeaderProtocols::Udp, dst_port))
            }
            None => Err(Error::Pnet(
                "Expected UDP packet in Ipv4 but could not parse",
            )),
        },
        _ => Ok((src_ipaddr, ipv4_packet.get_next_level_protocol(), 0)),
    }
}

pub fn parse_two_tuple_proto_ipid(
    _ctx: &ParseContext,
    payload: &[u8],
) -> Result<TwoTupleProtoIpid, Error> {
    let ipv4_packet =
        Ipv4Packet::new(payload).ok_or(Error::Pnet("Expected Ipv4 packet but could not parse"))?;
    let src_ipaddr = IpAddr::V4(ipv4_packet.get_source());
    let dst_ipaddr = IpAddr::V4(ipv4_packet.get_destination());
    let proto = ipv4_packet.get_next_level_protocol().0;
    let ip_id = ipv4_packet.get_identification() as u32;
    Ok(TwoTupleProtoIpid::new(src_ipaddr, dst_ipaddr, proto, ip_id))
}

pub fn parse_five_tuple(ctx: &ParseContext, payload: &[u8]) -> Result<FiveTuple, Error> {
    let ipv4_packet =
        Ipv4Packet::new(payload).ok_or(Error::Pnet("Expected Ipv4 packet but could not parse"))?;

    let src_ipaddr = IpAddr::V4(ipv4_packet.get_source());
    let dst_ipaddr = IpAddr::V4(ipv4_packet.get_destination());

    match ipv4_packet.get_next_level_protocol() {
        IpNextHeaderProtocols::Tcp => {
            let ipv4_payload = libpcap_analyzer::extract_payload_l3_ipv4(ctx, &ipv4_packet)?;
            match TcpPacket::new(ipv4_payload) {
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
                None => Err(Error::Pnet(
                    "Expected TCP packet in Ipv4 but could not parse",
                )),
            }
        }
        IpNextHeaderProtocols::Udp => {
            let ipv4_payload = libpcap_analyzer::extract_payload_l3_ipv4(ctx, &ipv4_packet)?;
            match UdpPacket::new(ipv4_payload) {
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
                None => Err(Error::Pnet(
                    "Expected UDP packet in Ipv4 but could not parse",
                )),
            }
        }
        _ => Ok(FiveTuple {
            src: src_ipaddr,
            dst: dst_ipaddr,
            proto: ipv4_packet.get_next_level_protocol().0,
            src_port: 0,
            dst_port: 0,
        }),
    }
}

pub fn parse_two_tuple_proto_ipid_five_tuple(
    ctx: &ParseContext,
    payload: &[u8],
) -> Result<TwoTupleProtoIpidFiveTuple, Error> {
    let two_tuple_proto_ipid = parse_two_tuple_proto_ipid(ctx, payload)?;
    let five_tuple = parse_five_tuple(ctx, payload)?;
    let two_tuple_proto_ipid_five_tuple =
        TwoTupleProtoIpidFiveTuple::new(Some(two_tuple_proto_ipid), Some(five_tuple));
    Ok(two_tuple_proto_ipid_five_tuple)
}
