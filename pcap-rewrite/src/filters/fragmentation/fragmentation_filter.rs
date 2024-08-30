use std::collections::HashSet;
use std::io;
use std::net::IpAddr;

use log::warn;
use pcap_parser::data::PacketData;
use pnet_packet::ethernet::{EtherType, EtherTypes};

use libpcap_tools::{Error, Packet, ParseContext};

use super::convert_fn;
use crate::container::five_tuple_container::FiveTupleC;
use crate::container::ipaddr_container::IpAddrC;
use crate::container::ipaddr_proto_port_container::{IpAddrProtoPort, IpAddrProtoPortC};
use crate::container::two_tuple_proto_ipid_container::TwoTupleProtoIpidC;
use crate::filters::filter::Filter;
use crate::filters::filter::{FResult, Verdict};
use crate::filters::filter_utils;
use crate::filters::filtering_action::FilteringAction;
use crate::filters::filtering_key::FilteringKey;
use crate::filters::fragmentation::fragmentation_test;
use crate::filters::fragmentation::key_fragmentation_matching::KeyFragmentationMatching;
use crate::filters::fragmentation::two_tuple_proto_ipid_five_tuple::TwoTupleProtoIpidFiveTuple;
use crate::filters::ipaddr_pair::IpAddrPair;
use crate::filters::key_parser_ipv4;
use crate::filters::key_parser_ipv6;

/// Function to convert TwoTupleProtoIpid/FiveTuple data to key container
pub type ConvertFn<Container> = fn(&HashSet<TwoTupleProtoIpidFiveTuple>) -> Container;
/// Function to extract key from data
pub type GetKeyFn<Key> = fn(&ParseContext, &[u8]) -> Result<Key, Error>;
/// Function to keep/drop extract key from container
pub type KeepFn<Container, Key> = fn(&Container, &Key) -> Result<bool, Error>;

pub struct FragmentationFilter<Container, Key> {
    data_hs: HashSet<TwoTupleProtoIpidFiveTuple>,
    convert_data_hs_c: ConvertFn<Container>,
    key_container: Container,

    get_key_from_ipv4_l3_data: GetKeyFn<Key>,
    get_key_from_ipv6_l3_data: GetKeyFn<Key>,
    keep: KeepFn<Container, Key>,
}

impl<Container, Key> FragmentationFilter<Container, Key> {
    pub fn new(
        data_hs: HashSet<TwoTupleProtoIpidFiveTuple>,
        convert_data_hs_c: ConvertFn<Container>,
        key_container: Container,

        get_key_from_ipv4_l3_data: GetKeyFn<Key>,
        get_key_from_ipv6_l3_data: GetKeyFn<Key>,
        keep: KeepFn<Container, Key>,
    ) -> Self {
        FragmentationFilter {
            data_hs,
            convert_data_hs_c,
            key_container,

            get_key_from_ipv4_l3_data,
            get_key_from_ipv6_l3_data,
            keep,
        }
    }

    fn test_fragmentation_and_save(
        &mut self,
        ctx: &ParseContext,
        packet: &Packet,
    ) -> Result<(), Error> {
        // Note: we only test the first fragment to be sure to capture the IP ID value.
        // Subsequent fragment with TCP/UDP/ICMP are always dropped because header parsing fails on all packets/fragments after the first.
        let is_first_fragment = match packet.data {
            PacketData::L2(data) => {
                if data.len() < 14 {
                    warn!("L2 data too small for ethernet at index {}", ctx.pcap_index);
                    return Err(Error::DataParser("L2 data too small for ethernet"));
                }

                // If returned value is None, it means that EtherType was neither IPv4 nor IPv6.
                // E.g.: ARP
                filter_utils::extract_callback_ethernet(
                    ctx,
                    fragmentation_test::is_ipv4_first_fragment,
                    fragmentation_test::is_ipv6_first_fragment,
                    data,
                )?
                .unwrap_or(false)
            }
            PacketData::L3(l3_layer_value_u8, data) => {
                let ether_type = EtherType::new(l3_layer_value_u8);
                match ether_type {
                    EtherTypes::Arp => false,
                    EtherTypes::Ipv4 => (fragmentation_test::is_ipv4_first_fragment)(ctx, data)?,
                    EtherTypes::Ipv6 => (fragmentation_test::is_ipv6_first_fragment)(ctx, data)?,
                    EtherTypes::Ipx => false,
                    EtherTypes::Lldp => false,
                    _ => {
                        warn!(
                            "Unimplemented Ethertype in L3 at index {}: {:?}/{:x}",
                            ctx.pcap_index, ether_type, ether_type.0
                        );
                        return Err(Error::Unimplemented("Unimplemented EtherType in L3"));
                    }
                }
            }
            PacketData::L4(_, _) => unimplemented!(),
            PacketData::Unsupported(_) => unimplemented!(),
        };

        if is_first_fragment {
            let data_option: Option<TwoTupleProtoIpidFiveTuple> = match packet.data {
                PacketData::L2(data) => {
                    if data.len() < 14 {
                        warn!("L2 data too small for ethernet at index {}", ctx.pcap_index);
                        return Err(Error::DataParser("L2 data too small for ethernet"));
                    }

                    filter_utils::extract_callback_ethernet(
                        ctx,
                        key_parser_ipv4::parse_two_tuple_proto_ipid_five_tuple,
                        key_parser_ipv6::parse_two_tuple_proto_ipid_five_tuple,
                        data,
                    )?
                }
                PacketData::L3(l3_layer_value_u8, data) => {
                    let ether_type = EtherType::new(l3_layer_value_u8);
                    match ether_type {
                        EtherTypes::Arp => None,
                        EtherTypes::Ipv4 => Some(
                            (key_parser_ipv4::parse_two_tuple_proto_ipid_five_tuple)(ctx, data)?,
                        ),
                        EtherTypes::Ipv6 => Some(
                            (key_parser_ipv6::parse_two_tuple_proto_ipid_five_tuple)(ctx, data)?,
                        ),
                        EtherTypes::Ipx => None,
                        EtherTypes::Lldp => None,
                        _ => {
                            warn!(
                                "Unimplemented Ethertype in L3 at index {}: {:?}/{:x}",
                                ctx.pcap_index, ether_type, ether_type.0
                            );
                            return Err(Error::Unimplemented("Unimplemented Ethertype in L3"));
                        }
                    }
                }
                PacketData::L4(_, _) => unimplemented!(),
                PacketData::Unsupported(_) => unimplemented!(),
            };

            match data_option {
                None => Err(Error::DataParser(
                    "Could find a first IP fragment but could not find two tuple/proto/IP id",
                ))?,
                Some(data) => self.data_hs.insert(data),
            };
        }
        Ok(())
    }

    pub fn keep<'j>(
        &self,
        ctx: &ParseContext,
        packet_data: PacketData<'j>,
    ) -> FResult<PacketData<'j>, Error> {
        let key_option = match packet_data {
            PacketData::L2(data) => {
                if data.len() < 14 {
                    warn!("L2 data too small for ethernet at index {}", ctx.pcap_index);
                    return Err(Error::DataParser("L2 data too small for ethernet"));
                }

                filter_utils::extract_callback_ethernet(
                    ctx,
                    self.get_key_from_ipv4_l3_data,
                    self.get_key_from_ipv6_l3_data,
                    data,
                )?
            }
            PacketData::L3(l3_layer_value_u8, data) => {
                let ether_type = EtherType::new(l3_layer_value_u8);
                match ether_type {
                    EtherTypes::Arp => None,
                    EtherTypes::Ipv4 => Some((self.get_key_from_ipv4_l3_data)(ctx, data)?),
                    EtherTypes::Ipv6 => Some((self.get_key_from_ipv6_l3_data)(ctx, data)?),
                    EtherTypes::Ipx => None,
                    EtherTypes::Lldp => None,
                    _ => {
                        warn!(
                            "Unimplemented Ethertype in L3 at index {}: {:?}/{:x}",
                            ctx.pcap_index, ether_type, ether_type.0
                        );
                        return Err(Error::Unimplemented("Unimplemented Ethertype in L3"));
                    }
                }
            }
            PacketData::L4(_, _) => unimplemented!(),
            PacketData::Unsupported(_) => unimplemented!(),
        };

        match key_option {
            None => Ok(Verdict::Accept(packet_data)),
            Some(key) => match (self.keep)(&self.key_container, &key) {
                Ok(b) => {
                    if b {
                        Ok(Verdict::Accept(packet_data))
                    } else {
                        Ok(Verdict::Drop)
                    }
                }
                Err(s) => Err(s),
            },
        }
    }
}

impl<Container, Key> Filter for FragmentationFilter<Container, Key> {
    fn filter<'i>(&self, ctx: &ParseContext, i: PacketData<'i>) -> FResult<PacketData<'i>, Error> {
        self.keep(ctx, i)
    }

    fn require_pre_analysis(&self) -> bool {
        true
    }

    fn pre_analyze(&mut self, ctx: &ParseContext, packet: &Packet) -> Result<(), Error> {
        self.test_fragmentation_and_save(ctx, packet)
    }

    fn preanalysis_done(&mut self) -> Result<(), Error> {
        self.key_container = (self.convert_data_hs_c)(&self.data_hs);
        Ok(())
    }
}

pub fn test_key_fragmentation_transport_in_container(
    container_tuple: &(TwoTupleProtoIpidC, FiveTupleC),
    key_fragmentation_matching: &KeyFragmentationMatching,
) -> Result<bool, Error> {
    let (two_tuple_proto_ipid_c, five_tuple_c) = container_tuple;

    let in_0 = match key_fragmentation_matching.get_two_tuple_proto_ipid_option() {
        Some(two_tuple_proto_ipid) => two_tuple_proto_ipid_c.contains(two_tuple_proto_ipid),
        None => false,
    };

    let in_1 = match key_fragmentation_matching.get_five_tuple_option() {
        Some(five_tuple) => five_tuple_c.contains(five_tuple),
        None => false,
    };

    Ok(in_0 || in_1)
}

pub struct FragmentationFilterBuilder;

impl FragmentationFilterBuilder {
    pub fn from_args(
        filtering_key: FilteringKey,
        filtering_action: FilteringAction,
    ) -> Result<Box<dyn Filter>, io::Error> {
        match filtering_key {
            FilteringKey::SrcIpaddr => {
                let ipaddr_container = IpAddrC::new(HashSet::new());

                let keep: KeepFn<IpAddrC, IpAddr> = match filtering_action {
                    FilteringAction::Keep => |c: &IpAddrC, ipaddr| Ok(c.contains(ipaddr)),
                    FilteringAction::Drop => |c: &IpAddrC, ipaddr| Ok(!c.contains(ipaddr)),
                };

                Ok(Box::new(FragmentationFilter::new(
                    HashSet::new(),
                    convert_fn::convert_data_hs_to_src_ipaddrc,
                    ipaddr_container,
                    key_parser_ipv4::parse_src_ipaddr,
                    key_parser_ipv6::parse_src_ipaddr,
                    keep,
                )))
            }
            FilteringKey::DstIpaddr => {
                let ipaddr_container = IpAddrC::new(HashSet::new());

                let keep: KeepFn<IpAddrC, IpAddr> = match filtering_action {
                    FilteringAction::Keep => |c: &IpAddrC, ipaddr| Ok(c.contains(ipaddr)),
                    FilteringAction::Drop => |c: &IpAddrC, ipaddr| Ok(!c.contains(ipaddr)),
                };

                Ok(Box::new(FragmentationFilter::new(
                    HashSet::new(),
                    convert_fn::convert_data_hs_to_dst_ipaddrc,
                    ipaddr_container,
                    key_parser_ipv4::parse_dst_ipaddr,
                    key_parser_ipv6::parse_dst_ipaddr,
                    keep,
                )))
            }
            FilteringKey::SrcDstIpaddr => {
                let ipaddr_container = IpAddrC::new(HashSet::new());

                let keep: KeepFn<IpAddrC, IpAddrPair> = match filtering_action {
                    FilteringAction::Keep => {
                        |c, ipaddr_pair| Ok(c.contains(&ipaddr_pair.0) || c.contains(&ipaddr_pair.1))
                    }
                    FilteringAction::Drop => |c, ipaddr_pair| {
                        Ok(!c.contains(&ipaddr_pair.0) && !c.contains(&ipaddr_pair.1))
                    },
                };

                Ok(Box::new(FragmentationFilter::new(
                    HashSet::new(),
                    convert_fn::convert_data_hs_to_src_dst_ipaddrc,
                    ipaddr_container,
                    key_parser_ipv4::parse_src_dst_ipaddr,
                    key_parser_ipv6::parse_src_dst_ipaddr,
                    keep,
                )))
            }
            FilteringKey::SrcIpaddrProtoDstPort => {
                let ipaddr_proto_port_container = IpAddrProtoPortC::new(HashSet::new());

                let keep: KeepFn<IpAddrProtoPortC, IpAddrProtoPort> = match filtering_action {
                    FilteringAction::Keep => {
                        |c: &IpAddrProtoPortC, ipaddr_proto_port| Ok(c.contains(ipaddr_proto_port))
                    }
                    FilteringAction::Drop => {
                        |c, ipaddr_proto_port| Ok(!c.contains(ipaddr_proto_port))
                    }
                };

                Ok(Box::new(FragmentationFilter::new(
                    HashSet::new(),
                    convert_fn::convert_data_hs_to_src_ipaddr_proto_dst_port_container,
                    ipaddr_proto_port_container,
                    key_parser_ipv4::parse_src_ipaddr_proto_dst_port,
                    key_parser_ipv6::parse_src_ipaddr_proto_dst_port,
                    keep,
                )))
            }
            FilteringKey::SrcDstIpaddrProtoSrcDstPort => {
                let two_tuple_proto_proto_ipid_c =
                    TwoTupleProtoIpidC::new(HashSet::new());
                let five_tuple_container = FiveTupleC::new(HashSet::new(), HashSet::new());

                let keep: KeepFn<(TwoTupleProtoIpidC, FiveTupleC), KeyFragmentationMatching> =
                    match filtering_action {
                        FilteringAction::Keep => |c, key_fragmentation_matching| {
                            test_key_fragmentation_transport_in_container(
                                c,
                                key_fragmentation_matching,
                            )
                        },
                        FilteringAction::Drop => |c, key_fragmentation_matching| {
                            Ok(!(test_key_fragmentation_transport_in_container(
                                c,
                                key_fragmentation_matching,
                            )?))
                        },
                    };

                Ok(Box::new(FragmentationFilter::new(
                    HashSet::new(),
                    convert_fn::convert_data_hs_to_ctuple,
                    (two_tuple_proto_proto_ipid_c, five_tuple_container),
                    key_parser_ipv4::parse_key_fragmentation_transport,
                    key_parser_ipv6::parse_key_fragmentation_transport,
                    keep,
                )))
            }
        }
    }
}
