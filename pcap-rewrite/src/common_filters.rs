use crate::filter::*;
use pcap_parser::data::{PacketData, ETHERTYPE_IPV4, ETHERTYPE_IPV6};
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::ipv6::Ipv6Packet;
use std::net::IpAddr;

pub struct SourceFilter {
    ip: IpAddr,
    exclude: bool,
}

impl Filter for SourceFilter {
    fn filter<'i>(&self, i: PacketData<'i>) -> FResult<PacketData<'i>, String> {
        match i {
            PacketData::L2(_) => FResult::Ok(i),
            PacketData::L3(ethertype, data) => {
                let matched = {
                    if ethertype == ETHERTYPE_IPV4 {
                        Ipv4Packet::new(data)
                            .map(|ipv4| ipv4.get_source() == self.ip)
                            .unwrap_or(false)
                    } else if ethertype == ETHERTYPE_IPV6 {
                        Ipv6Packet::new(data)
                            .map(|ipv6| ipv6.get_source() == self.ip)
                            .unwrap_or(false)
                    } else {
                        false
                    }
                };
                if matched ^ self.exclude {
                    FResult::Ok(i)
                } else {
                    FResult::Drop
                }
            }
            PacketData::L4(_, _) => FResult::Error("Cannot filter source, L4 content".to_owned()),
            PacketData::Unsupported(_) => {
                FResult::Error("Cannot filter source, unsupported data".to_owned())
            }
        }
    }
}
