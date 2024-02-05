use std::collections::HashSet;
use std::io;
use std::net::IpAddr;

use pcap_parser::data::PacketData;
use pnet_packet::ethernet::{EtherType, EtherTypes};
use pnet_packet::ip::IpNextHeaderProtocol;

use libpcap_tools::Packet;

use crate::container::five_tuple_container::FiveTupleC;
use crate::container::ipaddr_container::IpAddrC;
use crate::container::ipaddr_proto_port_container::IpAddrProtoPortC;
use crate::container::two_tuple_proto_ipid_container::TwoTupleProtoIpidC;
use crate::filters::filter::Filter;
use crate::filters::filter::{FResult, Verdict};
use crate::filters::filter_utils;
use crate::filters::filtering_action::FilteringAction;
use crate::filters::filtering_key::FilteringKey;
use crate::filters::key_parser_ipv4;
use crate::filters::key_parser_ipv6;

use crate::filters::fragmentation::fragmentation_test;
use crate::filters::fragmentation::two_tuple_proto_ipid_five_tuple::TwoTupleProtoIpidFiveTuple;

use super::convert_fn;

/// Function to convert TwoTupleProtoIpid/FiveTuple data to key container
pub type ConvertFn<Container> = Box<dyn Fn(&HashSet<TwoTupleProtoIpidFiveTuple>) -> Container>;
/// Function to extract key from data
pub type GetKeyFn<Key> = Box<dyn Fn(&[u8]) -> Result<Key, String>>;
/// Function to keep/drop extract key from container
pub type KeepFn<Container, Key> = Box<dyn Fn(&Container, &Key) -> Result<bool, String>>;

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

    fn test_fragmentation_and_save(&mut self, packet: &Packet) -> Result<(), String> {
        // Note: we only test the first fragment to be sure to capture the IP ID value.
        // Subsequent fragment with TCP/UDP/ICMP are always dropped because header parsing fails on all packets/fragments after the first.
        let is_first_fragment = match packet.data {
            PacketData::L2(data) => {
                if data.len() < 14 {
                    return Err("L2 data too small for ethernet".to_string());
                }

                filter_utils::extract_callback_ethernet(
                    &fragmentation_test::is_ipv4_first_fragment,
                    &fragmentation_test::is_ipv6_first_fragment,
                    data,
                )?
            }
            PacketData::L3(l3_layer_value_u8, data) => {
                let ether_type = EtherType::new(l3_layer_value_u8);
                match ether_type {
                    EtherTypes::Ipv4 => (fragmentation_test::is_ipv4_first_fragment)(data)?,
                    EtherTypes::Ipv6 => (fragmentation_test::is_ipv6_first_fragment)(data)?,
                    _ => return Err(format!("{} is not implmented", ether_type)),
                }
            }
            PacketData::L4(_, _) => unimplemented!(),
            PacketData::Unsupported(_) => unimplemented!(),
        };

        if is_first_fragment {
            let data_option: Option<TwoTupleProtoIpidFiveTuple> = match packet.data {
                PacketData::L2(data) => {
                    if data.len() < 14 {
                        return Err("L2 data too small for ethernet".to_string());
                    }

                    Some(filter_utils::extract_callback_ethernet(
                        &key_parser_ipv4::parse_two_tuple_proto_ipid_five_tuple,
                        &key_parser_ipv6::parse_two_tuple_proto_ipid_five_tuple,
                        data,
                    )?)
                }
                PacketData::L3(l3_layer_value_u8, data) => {
                    let ether_type = EtherType::new(l3_layer_value_u8);
                    match ether_type {
                        EtherTypes::Ipv4 => Some(
                            (key_parser_ipv4::parse_two_tuple_proto_ipid_five_tuple)(data)?,
                        ),
                        EtherTypes::Ipv6 => Some(
                            (key_parser_ipv6::parse_two_tuple_proto_ipid_five_tuple)(data)?,
                        ),
                        _ => {
                            return Err(format!(
                                "Unimplemented Ethertype in L3 {:?}/{:x}",
                                ether_type, ether_type.0
                            ))
                        }
                    }
                }
                PacketData::L4(_, _) => unimplemented!(),
                PacketData::Unsupported(_) => unimplemented!(),
            };

            match data_option {
                None => Err("Could find a first IP fragment but could not two tuple/proto/IP id")?,
                Some(data) => self.data_hs.insert(data),
            };
        }
        Ok(())
    }

    pub fn keep<'j>(&self, packet_data: PacketData<'j>) -> FResult<PacketData<'j>, String> {
        let key = match packet_data {
            PacketData::L2(data) => {
                if data.len() < 14 {
                    return Err("L2 data too small for ethernet".to_owned());
                }

                filter_utils::extract_callback_ethernet(
                    &self.get_key_from_ipv4_l3_data,
                    &self.get_key_from_ipv6_l3_data,
                    data,
                )?
            }
            PacketData::L3(l3_layer_value_u8, data) => {
                let ether_type = EtherType::new(l3_layer_value_u8);
                match ether_type {
                    EtherTypes::Ipv4 => (self.get_key_from_ipv4_l3_data)(data)?,
                    EtherTypes::Ipv6 => (self.get_key_from_ipv6_l3_data)(data)?,
                    _ => Err(format!(
                        "Unimplemented Ethertype in L3 {:?}/{:x}",
                        ether_type, ether_type.0
                    ))?,
                }
            }
            PacketData::L4(_, _) => unimplemented!(),
            PacketData::Unsupported(_) => unimplemented!(),
        };

        match (self.keep)(&self.key_container, &key) {
            Ok(b) => {
                if b {
                    Ok(Verdict::Accept(packet_data))
                } else {
                    Ok(Verdict::Drop)
                }
            }
            Err(s) => Err(s),
        }
    }
}

impl<Container, Key> Filter for FragmentationFilter<Container, Key> {
    fn filter<'i>(&self, i: PacketData<'i>) -> FResult<PacketData<'i>, String> {
        self.keep(i)
    }

    fn require_pre_analysis(&self) -> bool {
        true
    }

    fn pre_analyze(&mut self, _packet: &Packet) -> Result<(), String> {
        self.test_fragmentation_and_save(_packet)
    }

    fn preanalysis_done(&mut self) -> Result<(), String> {
        self.key_container = (self.convert_data_hs_c)(&self.data_hs);
        Ok(())
    }
}

pub fn test_two_tuple_proto_ipid_five_tuple_option_in_container(
    container_tuple: &(TwoTupleProtoIpidC, FiveTupleC),
    two_tuple_proto_ipid_five_tuple: &TwoTupleProtoIpidFiveTuple,
) -> Result<bool, String> {
    let (two_tuple_proto_ipid_c, five_tuple_c) = container_tuple;

    let in_0 = match two_tuple_proto_ipid_five_tuple.get_two_tuple_proto_ipid_option() {
        Some(two_tuple_proto_ipid) => two_tuple_proto_ipid_c.contains(two_tuple_proto_ipid),
        None => true,
    };

    let in_1 = match two_tuple_proto_ipid_five_tuple.get_five_tuple_option() {
        Some(five_tuple) => five_tuple_c.contains(five_tuple),
        None => true,
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
                    FilteringAction::Keep => Box::new(|c: &IpAddrC, ipaddr| Ok(c.contains(ipaddr))),
                    FilteringAction::Drop => {
                        Box::new(|c: &IpAddrC, ipaddr| Ok(!c.contains(ipaddr)))
                    }
                };

                Ok(Box::new(FragmentationFilter::new(
                    HashSet::new(),
                    Box::new(convert_fn::convert_data_hs_to_src_ipaddrc),
                    ipaddr_container,
                    Box::new(key_parser_ipv4::parse_src_ipaddr),
                    Box::new(key_parser_ipv6::parse_src_ipaddr),
                    keep,
                )))
            }
            FilteringKey::DstIpaddr => {
                let ipaddr_container = IpAddrC::new(HashSet::new());

                let keep: KeepFn<IpAddrC, IpAddr> = match filtering_action {
                    FilteringAction::Keep => Box::new(|c: &IpAddrC, ipaddr| Ok(c.contains(ipaddr))),
                    FilteringAction::Drop => {
                        Box::new(|c: &IpAddrC, ipaddr| Ok(!c.contains(ipaddr)))
                    }
                };

                Ok(Box::new(FragmentationFilter::new(
                    HashSet::new(),
                    Box::new(convert_fn::convert_data_hs_to_dst_ipaddrc),
                    ipaddr_container,
                    Box::new(key_parser_ipv4::parse_dst_ipaddr),
                    Box::new(key_parser_ipv6::parse_dst_ipaddr),
                    keep,
                )))
            }
            FilteringKey::SrcDstIpaddr => {
                let ipaddr_container = IpAddrC::new(HashSet::new());

                let keep: KeepFn<IpAddrC, (IpAddr, IpAddr)> = match filtering_action {
                    FilteringAction::Keep => Box::new(|c, ipaddr_tuple| {
                        Ok(c.contains(&ipaddr_tuple.0) || c.contains(&ipaddr_tuple.1))
                    }),
                    FilteringAction::Drop => Box::new(|c, ipaddr_tuple| {
                        Ok(!c.contains(&ipaddr_tuple.0) && !c.contains(&ipaddr_tuple.1))
                    }),
                };

                Ok(Box::new(FragmentationFilter::new(
                    HashSet::new(),
                    Box::new(convert_fn::convert_data_hs_to_src_dst_ipaddrc),
                    ipaddr_container,
                    Box::new(key_parser_ipv4::parse_src_dst_ipaddr),
                    Box::new(key_parser_ipv6::parse_src_dst_ipaddr),
                    keep,
                )))
            }
            FilteringKey::SrcIpaddrProtoDstPort => {
                let ipaddr_proto_port_container = IpAddrProtoPortC::new(HashSet::new());

                let keep: KeepFn<IpAddrProtoPortC, (IpAddr, IpNextHeaderProtocol, u16)> =
                    match filtering_action {
                        FilteringAction::Keep => {
                            Box::new(|c, tuple| Ok(c.contains(&tuple.0, &tuple.1, tuple.2)))
                        }
                        FilteringAction::Drop => {
                            Box::new(|c, tuple| Ok(!c.contains(&tuple.0, &tuple.1, tuple.2)))
                        }
                    };

                Ok(Box::new(FragmentationFilter::new(
                    HashSet::new(),
                    Box::new(convert_fn::convert_data_hs_to_src_ipaddr_proto_dst_port_container),
                    ipaddr_proto_port_container,
                    Box::new(key_parser_ipv4::parse_src_ipaddr_proto_dst_port),
                    Box::new(key_parser_ipv6::parse_src_ipaddr_proto_dst_port),
                    keep,
                )))
            }
            FilteringKey::SrcDstIpaddrProtoSrcDstPort => {
                let two_tuple_proto_proto_ipid_c =
                    TwoTupleProtoIpidC::new(HashSet::new(), HashSet::new());
                let five_tuple_container = FiveTupleC::new(HashSet::new(), HashSet::new());

                let keep: KeepFn<(TwoTupleProtoIpidC, FiveTupleC), TwoTupleProtoIpidFiveTuple> =
                    match filtering_action {
                        FilteringAction::Keep => Box::new(|c, two_tuple_proto_ipid_five_tuple| {
                            test_two_tuple_proto_ipid_five_tuple_option_in_container(
                                c,
                                two_tuple_proto_ipid_five_tuple,
                            )
                        }),
                        FilteringAction::Drop => Box::new(|c, two_tuple_proto_ipid_five_tuple| {
                            Ok(!(test_two_tuple_proto_ipid_five_tuple_option_in_container(
                                c,
                                two_tuple_proto_ipid_five_tuple,
                            )?))
                        }),
                    };

                Ok(Box::new(FragmentationFilter::new(
                    HashSet::new(),
                    Box::new(convert_fn::convert_data_hs_to_ctuple),
                    (two_tuple_proto_proto_ipid_c, five_tuple_container),
                    Box::new(key_parser_ipv4::parse_two_tuple_proto_ipid_five_tuple),
                    Box::new(key_parser_ipv6::parse_two_tuple_proto_ipid_five_tuple),
                    keep,
                )))
            }
        }
    }
}
