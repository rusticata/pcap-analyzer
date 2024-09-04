use std::net::IpAddr;

use log::warn;
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv6::Ipv6Packet;
use pnet_packet::tcp::TcpPacket;
use pnet_packet::udp::UdpPacket;

use crate::container::ipaddr_proto_port_container::IpAddrProtoPort;
use crate::filters::ipv6_utils;
use libpcap_tools::{Error, FiveTuple, ParseContext};

use super::fragmentation::two_tuple_proto_ipid::TwoTupleProtoIpid;
use super::fragmentation::two_tuple_proto_ipid_five_tuple::TwoTupleProtoIpidFiveTuple;
use crate::filters::fragmentation::key_fragmentation_matching::KeyFragmentationMatching;
use crate::filters::ipaddr_pair::IpAddrPair;
use crate::filters::fragmentation::fragmentation_test;

pub fn parse_src_ipaddr(ctx: &ParseContext, payload: &[u8]) -> Result<IpAddr, Error> {
    let ipv6 = Ipv6Packet::new(payload).ok_or_else(|| {
        warn!(
            "Expected Ipv6 packet but could not parse at index {}",
            ctx.pcap_index
        );
        Error::Pnet("Expected Ipv6 packet but could not parse")
    })?;
    Ok(IpAddr::V6(ipv6.get_source()))
}

pub fn parse_dst_ipaddr(ctx: &ParseContext, payload: &[u8]) -> Result<IpAddr, Error> {
    let ipv6 = Ipv6Packet::new(payload).ok_or_else(|| {
        warn!(
            "Expected Ipv6 packet but could not parse at index {}",
            ctx.pcap_index
        );
        Error::Pnet("Expected Ipv6 packet but could not parse")
    })?;
    Ok(IpAddr::V6(ipv6.get_destination()))
}

pub fn parse_src_dst_ipaddr(ctx: &ParseContext, payload: &[u8]) -> Result<IpAddrPair, Error> {
    let ipv6_packet = Ipv6Packet::new(payload).ok_or_else(|| {
        warn!(
            "Expected Ipv6 packet but could not parse at index {}",
            ctx.pcap_index
        );
        Error::Pnet("Expected Ipv6 packet but could not parse")
    })?;
    let src_ipaddr = IpAddr::V6(ipv6_packet.get_source());
    let dst_ipaddr = IpAddr::V6(ipv6_packet.get_destination());
    Result::Ok(IpAddrPair::new(src_ipaddr, dst_ipaddr))
}

pub fn parse_src_ipaddr_proto_dst_port(
    ctx: &ParseContext,
    payload: &[u8],
) -> Result<IpAddrProtoPort, Error> {
    let ipv6_packet = Ipv6Packet::new(payload).ok_or_else(|| {
        warn!(
            "Expected Ipv6 packet but could not parse at index {}",
            ctx.pcap_index
        );
        Error::Pnet("Expected Ipv6 packet but could not parse")
    })?;

    let src_ipaddr = IpAddr::V6(ipv6_packet.get_source());

    let (fragment_packet_option, l4_proto, payload) =
        ipv6_utils::get_fragment_packet_option_l4_protol4_payload(payload, &ipv6_packet)?;

    match l4_proto {
        IpNextHeaderProtocols::Tcp => {
            let next_header_not_fragment_or_offset_is_zero = match fragment_packet_option {
                None => true,
                Some(fragment_packet) => fragment_packet.get_fragment_offset() == 0,
            };
            if payload.len() >= 20 && next_header_not_fragment_or_offset_is_zero {
                match TcpPacket::new(payload) {
                    Some(ref tcp) => {
                        let dst_port = tcp.get_destination();
                        Ok(IpAddrProtoPort::new(
                            src_ipaddr,
                            IpNextHeaderProtocols::Tcp,
                            dst_port,
                        ))
                    }
                    None => {
                        warn!(
                            "Expected TCP packet in Ipv4 but could not parse at index {}",
                            ctx.pcap_index
                        );
                        Err(Error::Pnet(
                            "Expected TCP packet in Ipv6 but could not parse",
                        ))
                    }
                }
            } else {
                Ok(IpAddrProtoPort::new(
                    src_ipaddr,
                    IpNextHeaderProtocols::Tcp,
                    0,
                ))
            }
        }
        IpNextHeaderProtocols::Udp => {
            let next_header_not_fragment_or_offset_is_zero = match fragment_packet_option {
                None => true,
                Some(fragment_packet) => fragment_packet.get_fragment_offset() == 0,
            };
            if payload.len() >= 20 && next_header_not_fragment_or_offset_is_zero {
                match UdpPacket::new(payload) {
                    Some(ref udp) => {
                        let dst_port = udp.get_destination();
                        Ok(IpAddrProtoPort::new(
                            src_ipaddr,
                            IpNextHeaderProtocols::Udp,
                            dst_port,
                        ))
                    }
                    None => {
                        warn!(
                            "Expected UDP packet in Ipv4 but could not parse at index {}",
                            ctx.pcap_index
                        );
                        Err(Error::Pnet(
                            "Expected UDP packet in Ipv6 but could not parse",
                        ))
                    }
                }
            } else {
                Ok(IpAddrProtoPort::new(
                    src_ipaddr,
                    IpNextHeaderProtocols::Udp,
                    0,
                ))
            }
        }
        _ => Ok(IpAddrProtoPort::new(src_ipaddr, l4_proto, 0)),
    }
}

pub fn parse_two_tuple_proto_ipid(
    ctx: &ParseContext,
    payload: &[u8],
) -> Result<Option<TwoTupleProtoIpid>, Error> {
    let ipv6_packet = Ipv6Packet::new(payload).ok_or_else(|| {
        warn!(
            "Expected Ipv6 packet but could not parse at index {}",
            ctx.pcap_index
        );
        Error::Pnet("Expected Ipv6 packet but could not parse")
    })?;
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

/// Extract a FiveTuple from a payload.
/// The return type is an option to encode insufficent transport payload.
pub fn parse_five_tuple(ctx: &ParseContext, payload: &[u8]) -> Result<Option<FiveTuple>, Error> {
    let ipv6_packet = Ipv6Packet::new(payload).ok_or_else(|| {
        warn!(
            "Expected Ipv6 packet but could not parse at index {}",
            ctx.pcap_index
        );
        Error::Pnet("Expected Ipv6 packet but could not parse")
    })?;

    let src_ipaddr = IpAddr::V6(ipv6_packet.get_source());
    let dst_ipaddr = IpAddr::V6(ipv6_packet.get_destination());

    let (fragment_packet_option, l4_proto, payload) =
        ipv6_utils::get_fragment_packet_option_l4_protol4_payload(payload, &ipv6_packet)?;

    match l4_proto {
        IpNextHeaderProtocols::Tcp => {
            let next_header_not_fragment_or_offset_is_zero = match fragment_packet_option {
                None => true,
                Some(fragment_packet) => fragment_packet.get_fragment_offset() == 0,
            };
            if payload.len() >= 20 && next_header_not_fragment_or_offset_is_zero {
                match TcpPacket::new(payload) {
                    Some(ref tcp) => {
                        let src_port = tcp.get_source();
                        let dst_port = tcp.get_destination();
                        Ok(Some(FiveTuple {
                            src: src_ipaddr,
                            dst: dst_ipaddr,
                            proto: 6_u8,
                            src_port,
                            dst_port,
                        }))
                    }
                    None => {
                        warn!(
                            "Expected TCP packet in Ipv6 but could not parse at index {}",
                            ctx.pcap_index
                        );
                        Err(Error::Pnet(
                            "Expected TCP packet in Ipv6 but could not parse",
                        ))
                    }
                }
            } else {
                Ok(None)
            }
        }
        IpNextHeaderProtocols::Udp => {
            let next_header_not_fragment_or_offset_is_zero = match fragment_packet_option {
                None => true,
                Some(fragment_packet) => fragment_packet.get_fragment_offset() == 0,
            };
            if payload.len() >= 8 && next_header_not_fragment_or_offset_is_zero {
                match UdpPacket::new(payload) {
                    Some(ref udp) => {
                        let src_port = udp.get_source();
                        let dst_port = udp.get_destination();
                        Ok(Some(FiveTuple {
                            src: src_ipaddr,
                            dst: dst_ipaddr,
                            proto: 17_u8,
                            src_port,
                            dst_port,
                        }))
                    }
                    None => {
                        warn!(
                            "Expected UDP packet in Ipv6 but could not parse at index {}",
                            ctx.pcap_index
                        );
                        Err(Error::Pnet(
                            "Expected UDP packet in Ipv6 but could not parse",
                        ))
                    }
                }
            } else {
                Ok(None)
            }
        }
        _ => Ok(Some(FiveTuple {
            src: src_ipaddr,
            dst: dst_ipaddr,
            proto: l4_proto.0,
            src_port: 0,
            dst_port: 0,
        })),
    }
}

/// Parse both TwoTupleProtoIpid and FiveTuple.
/// This function is used when parsing the first fragment.
pub fn parse_two_tuple_proto_ipid_five_tuple(
    ctx: &ParseContext,
    payload: &[u8],
) -> Result<TwoTupleProtoIpidFiveTuple, Error> {
    Ok(TwoTupleProtoIpidFiveTuple::new(
        parse_two_tuple_proto_ipid(ctx, payload)?,
        // TODO: replace by dedicated error type to distinguish between Ipv6Packet parsing error and TcpPacket/UdpPacket error related to fragmentation
        parse_five_tuple(ctx, payload)?,
    ))
}

/// Parse FiveTuple and then, if FiveTuple parsing was not possible, parse TwoTupleProtoIpid.
/// This functions is used when trying to find packet related to a first fragment.
pub fn parse_key_fragmentation_transport<Key>(
    key_parse: fn(&ParseContext, &[u8]) -> Result<Option<Key>, Error>,
    ctx: &ParseContext,
    payload: &[u8],
) -> Result<KeyFragmentationMatching<Option<Key>>, Error> {
    if fragmentation_test::is_ipv6_fragment(ctx, payload)? {
        let two_tuple_proto_ipid = 
            parse_two_tuple_proto_ipid(ctx, payload)?.ok_or_else(|| {
                warn!(
                    "Could not parse TwoTupleProtoId, expected fragmented IPv6 packet but could not parse at index {}",
                    ctx.pcap_index
                );
                Error::DataParser(
                    "Could not parse TwoTupleProtoId, expected fragmented IPv6 packet but could not parse",
                )
            }
        )?;
        if fragmentation_test::is_ipv6_first_fragment(ctx, payload)? {
            match key_parse(ctx, payload)? {
                Some(key) => {
                    Ok(KeyFragmentationMatching::FirstFragment(
                        two_tuple_proto_ipid,
                        Some(key)
                    ))
                },
                // NB
                // This case happens when the first fragment does have enough data to parse transport header.
                // The clean approach would be to a full IP fragmentation reassembly.
                // We hope this case is rare. :)
                None => {
                    Ok(KeyFragmentationMatching::FragmentAfterFirst(
                        two_tuple_proto_ipid,
                    ))
                }
            }
        } else {
            Ok(KeyFragmentationMatching::FragmentAfterFirst(
                two_tuple_proto_ipid,
            ))
        }
    } else {
        Ok(KeyFragmentationMatching::NotFragment(
            key_parse(ctx, payload)?,
        ))
    }
}

pub fn parse_key_fragmentation_transport_five_tuple(
    ctx: &ParseContext,
    payload: &[u8],
) -> Result<KeyFragmentationMatching<Option<FiveTuple>>, Error> {
    parse_key_fragmentation_transport(parse_five_tuple, ctx, payload)
}
