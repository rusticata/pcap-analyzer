use std::net::IpAddr;

use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv6::Ipv6Packet;
use pnet_packet::tcp::TcpPacket;
use pnet_packet::udp::UdpPacket;

use crate::container::ipaddr_proto_port_container::IpAddrProtoPort;
use crate::filters::ipv6_utils;
use libpcap_tools::{Error, FiveTuple, ParseContext};

use super::fragmentation::two_tuple_proto_ipid::TwoTupleProtoIpid;
use super::fragmentation::two_tuple_proto_ipid_five_tuple::TwoTupleProtoIpidFiveTuple;

pub fn parse_src_ipaddr(_ctx: &ParseContext, payload: &[u8]) -> Result<IpAddr, Error> {
    let ipv6 =
        Ipv6Packet::new(payload).ok_or(Error::Pnet("Expected Ipv6 packet but could not parse"))?;
    Ok(IpAddr::V6(ipv6.get_source()))
}

pub fn parse_dst_ipaddr(_ctx: &ParseContext, payload: &[u8]) -> Result<IpAddr, Error> {
    let ipv6 =
        Ipv6Packet::new(payload).ok_or(Error::Pnet("Expected Ipv6 packet but could not parse"))?;
    Ok(IpAddr::V6(ipv6.get_destination()))
}

pub fn parse_src_dst_ipaddr(
    _ctx: &ParseContext,
    payload: &[u8],
) -> Result<(IpAddr, IpAddr), Error> {
    let ipv6_packet =
        Ipv6Packet::new(payload).ok_or(Error::Pnet("Expected Ipv6 packet but could not parse"))?;
    let src_ipaddr = IpAddr::V6(ipv6_packet.get_source());
    let dst_ipaddr = IpAddr::V6(ipv6_packet.get_destination());
    Result::Ok((src_ipaddr, dst_ipaddr))
}

pub fn parse_src_ipaddr_proto_dst_port(
    _ctx: &ParseContext,
    payload: &[u8],
) -> Result<IpAddrProtoPort, Error> {
    let ipv6_packet =
        Ipv6Packet::new(payload).ok_or(Error::Pnet("Expected Ipv6 packet but could not parse"))?;

    let src_ipaddr = IpAddr::V6(ipv6_packet.get_source());

    let (_fragment_packet_option, l4_proto, payload) =
        ipv6_utils::get_fragment_packet_option_l4_protol4_payload(payload, &ipv6_packet)?;

    match l4_proto {
        IpNextHeaderProtocols::Tcp => match TcpPacket::new(payload) {
            Some(ref tcp) => {
                let dst_port = tcp.get_destination();
                Ok(IpAddrProtoPort::new(src_ipaddr, IpNextHeaderProtocols::Tcp, dst_port))
            }
            None => Err(Error::Pnet(
                "Expected TCP packet in Ipv6 but could not parse",
            )),
        },
        IpNextHeaderProtocols::Udp => match UdpPacket::new(payload) {
            Some(ref udp) => {
                let dst_port = udp.get_destination();
                Ok(IpAddrProtoPort::new(src_ipaddr, IpNextHeaderProtocols::Udp, dst_port))
            }
            None => Err(Error::Pnet(
                "Expected UDP packet in Ipv6 but could not parse",
            )),
        },
        _ => Ok(IpAddrProtoPort::new(src_ipaddr, l4_proto, 0)),
    }
}

pub fn parse_two_tuple_proto_ipid(
    _ctx: &ParseContext,
    payload: &[u8],
) -> Result<Option<TwoTupleProtoIpid>, Error> {
    let ipv6_packet =
        Ipv6Packet::new(payload).ok_or(Error::Pnet("Expected Ipv6 packet but could not parse"))?;
    let src_ipaddr = IpAddr::V6(ipv6_packet.get_destination());
    let dst_ipaddr = IpAddr::V6(ipv6_packet.get_destination());

    let (fragment_packet_option, l4_proto, _payload) =
        ipv6_utils::get_fragment_packet_option_l4_protol4_payload(payload, &ipv6_packet)?;

    let proto = l4_proto.0;

    match fragment_packet_option {
        Some(fragment_packet) => {
            let ip_id = fragment_packet.get_id();
            Ok(Some(TwoTupleProtoIpid::new(
                src_ipaddr, dst_ipaddr, proto, ip_id,
            )))
        }
        None => Ok(None),
    }
}

pub fn parse_five_tuple(_ctx: &ParseContext, payload: &[u8]) -> Result<FiveTuple, Error> {
    let ipv6_packet =
        Ipv6Packet::new(payload).ok_or(Error::Pnet("Expected Ipv6 packet but could not parse"))?;

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
            None => Err(Error::Pnet(
                "Expected TCP packet in Ipv6 but could not parse",
            )),
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
            None => Err(Error::Pnet(
                "Expected UDP packet in Ipv6 but could not parse",
            )),
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

pub fn parse_two_tuple_proto_ipid_five_tuple(
    ctx: &ParseContext,
    payload: &[u8],
) -> Result<TwoTupleProtoIpidFiveTuple, Error> {
    Ok(TwoTupleProtoIpidFiveTuple::new(
        parse_two_tuple_proto_ipid(ctx, payload)?,
        // TODO: replace by dedicated error type to distinguish between Ipv6Packet parsing error and TcpPacket/UdpPacket error related to fragmentation
        parse_five_tuple(ctx, payload).ok(),
    ))
}
