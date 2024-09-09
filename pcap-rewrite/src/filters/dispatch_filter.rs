use log::warn;
use std::io;
use std::net::IpAddr;
use std::path::Path;

use libpcap_tools::{Error, FiveTuple, ParseContext};
use pcap_parser::data::PacketData;
use pnet_packet::ethernet::{EtherType, EtherTypes};
use pnet_packet::PrimitiveValues;

use crate::container::five_tuple_container::FiveTupleC;
use crate::container::ipaddr_container::IpAddrC;
use crate::container::ipaddr_proto_port_container::{IpAddrProtoPort, IpAddrProtoPortC};
use crate::filters::filter::{FResult, Filter, Verdict};
use crate::filters::filter_utils;
use crate::filters::filtering_action::FilteringAction;
use crate::filters::filtering_key::FilteringKey;
use crate::filters::ipaddr_pair::IpAddrPair;
use crate::filters::key_parser_ipv4;
use crate::filters::key_parser_ipv6;

/// Function to extract key from data
pub type GetKeyFn<Key> = fn(&ParseContext, &[u8]) -> Result<Key, Error>;
/// Function to keep/drop extract key from container
pub type KeepFn<Container, Key> = Box<dyn Fn(&Container, &Key) -> Result<bool, Error>>;

pub struct DispatchFilter<Container, Key> {
    key_container: Container,
    get_key_from_ipv4_l3_data: GetKeyFn<Key>,
    get_key_from_ipv6_l3_data: GetKeyFn<Key>,
    keep: KeepFn<Container, Key>,
}

impl<Container, Key> DispatchFilter<Container, Key> {
    pub fn new(
        key_container: Container,
        get_key_from_ipv4_l3_data: GetKeyFn<Key>,
        get_key_from_ipv6_l3_data: GetKeyFn<Key>,
        keep: KeepFn<Container, Key>,
    ) -> Self {
        DispatchFilter {
            key_container,
            get_key_from_ipv4_l3_data,
            get_key_from_ipv6_l3_data,
            keep,
        }
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
                    EtherTypes::Ipv6 => Some((self.get_key_from_ipv4_l3_data)(ctx, data)?),
                    EtherTypes::Ipx => None,
                    EtherTypes::Lldp => None,
                    _ => {
                        warn!(
                            "Unimplemented Ethertype in L3 at index {}: {:?}/{:x}",
                            ctx.pcap_index,
                            ether_type,
                            ether_type.to_primitive_values().0
                        );
                        Err(Error::Unimplemented("Unimplemented Ethertype in L3"))?
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

impl<Container, Key> Filter for DispatchFilter<Container, Key> {
    fn filter<'i>(&self, ctx: &ParseContext, i: PacketData<'i>) -> FResult<PacketData<'i>, Error> {
        self.keep(ctx, i)
    }
}

pub struct DispatchFilterBuilder;

impl DispatchFilterBuilder {
    pub fn from_args(
        filtering_key: FilteringKey,
        filtering_action: FilteringAction,
        key_file_path: &str,
    ) -> Result<Box<dyn Filter>, io::Error> {
        match filtering_key {
            FilteringKey::SrcIpaddr => {
                let ipaddr_container = IpAddrC::of_file_path(Path::new(key_file_path))
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

                let keep: KeepFn<IpAddrC, IpAddr> = match filtering_action {
                    FilteringAction::Keep => Box::new(|c: &IpAddrC, ipaddr| Ok(c.contains(ipaddr))),
                    FilteringAction::Drop => {
                        Box::new(|c: &IpAddrC, ipaddr| Ok(!c.contains(ipaddr)))
                    }
                };

                Ok(Box::new(DispatchFilter::new(
                    ipaddr_container,
                    key_parser_ipv4::parse_src_ipaddr,
                    key_parser_ipv6::parse_src_ipaddr,
                    Box::new(keep),
                )))
            }
            FilteringKey::DstIpaddr => {
                let ipaddr_container = IpAddrC::of_file_path(Path::new(key_file_path))
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

                let keep: KeepFn<IpAddrC, IpAddr> = match filtering_action {
                    FilteringAction::Keep => Box::new(|c: &IpAddrC, ipaddr| Ok(c.contains(ipaddr))),
                    FilteringAction::Drop => {
                        Box::new(|c: &IpAddrC, ipaddr| Ok(!c.contains(ipaddr)))
                    }
                };

                Ok(Box::new(DispatchFilter::new(
                    ipaddr_container,
                    key_parser_ipv4::parse_dst_ipaddr,
                    key_parser_ipv6::parse_dst_ipaddr,
                    keep,
                )))
            }
            FilteringKey::SrcDstIpaddr => {
                let ipaddr_container = IpAddrC::of_file_path(Path::new(key_file_path))
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

                let keep: KeepFn<IpAddrC, IpAddrPair> = match filtering_action {
                    FilteringAction::Keep => Box::new(|c, ipaddr_pair| {
                        Ok(c.contains(&ipaddr_pair.0) || c.contains(&ipaddr_pair.1))
                    }),
                    FilteringAction::Drop => Box::new(|c, ipaddr_pair| {
                        Ok(!c.contains(&ipaddr_pair.0) && !c.contains(&ipaddr_pair.1))
                    }),
                };

                Ok(Box::new(DispatchFilter::new(
                    ipaddr_container,
                    key_parser_ipv4::parse_src_dst_ipaddr,
                    key_parser_ipv6::parse_src_dst_ipaddr,
                    keep,
                )))
            }
            FilteringKey::SrcIpaddrProtoDstPort => {
                let ipaddr_proto_port_container =
                    IpAddrProtoPortC::of_file_path(Path::new(key_file_path))
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

                let keep: KeepFn<IpAddrProtoPortC, Option<IpAddrProtoPort>> = match filtering_action
                {
                    FilteringAction::Keep => Box::new(|c, ipaddr_proto_port_option| {
                        Ok(ipaddr_proto_port_option
                            .as_ref()
                            .map_or(false, |ipaddr_proto_port| c.contains(ipaddr_proto_port)))
                    }),
                    FilteringAction::Drop => Box::new(|c, ipaddr_proto_port_option| {
                        Ok(ipaddr_proto_port_option
                            .as_ref()
                            .map_or(false, |ipaddr_proto_port| !c.contains(ipaddr_proto_port)))
                    }),
                };

                Ok(Box::new(DispatchFilter::new(
                    ipaddr_proto_port_container,
                    key_parser_ipv4::parse_src_ipaddr_proto_dst_port,
                    key_parser_ipv6::parse_src_ipaddr_proto_dst_port,
                    keep,
                )))
            }
            FilteringKey::SrcDstIpaddrProtoSrcDstPort => {
                let five_tuple_container = FiveTupleC::of_file_path(Path::new(key_file_path))
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

                let keep: KeepFn<FiveTupleC, Option<FiveTuple>> = match filtering_action {
                    FilteringAction::Keep => Box::new(|c, five_tuple_option| {
                        Ok(five_tuple_option
                            .as_ref()
                            .map_or(false, |five_tuple| c.contains(five_tuple)))
                    }),
                    FilteringAction::Drop => Box::new(|c, five_tuple_option| {
                        Ok(five_tuple_option
                            .as_ref()
                            .map_or(false, |five_tuple| !c.contains(five_tuple)))
                    }),
                };

                Ok(Box::new(DispatchFilter::new(
                    five_tuple_container,
                    key_parser_ipv4::parse_five_tuple,
                    key_parser_ipv6::parse_five_tuple,
                    keep,
                )))
            }
        }
    }
}
