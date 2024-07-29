use crate::filters::filter::*;
use libpcap_tools::ParseContext;
use pcap_parser::data::{PacketData, ETHERTYPE_IPV4, ETHERTYPE_IPV6};
use pnet_packet::ethernet::EthernetPacket;
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::ipv6::Ipv6Packet;
use pnet_packet::Packet;
use std::net::IpAddr;

/// Common filter to select packets matching this IP address either as source or destination
///
/// Examples:
///   `-f 'IP:10.9.0.2'` to select packets maching this source
///   `-f 'IP:!10.9.0.2'` to select packets not maching this source
pub struct IPFilter {
    ip: IpAddr,
    exclude: bool,
}

impl Filter for IPFilter {
    fn filter<'i>(&self, _ctx: &ParseContext, i: PacketData<'i>) -> FResult<PacketData<'i>, String> {
        match i {
            PacketData::L2(data) => {
                let p = match EthernetPacket::new(data) {
                    Some(p) => p,
                    None => Err("Cannot build ethernet data")?,
                };
                if self.match_l3(p.get_ethertype().0, p.payload()) {
                    Ok(Verdict::Accept(i))
                } else {
                    Ok(Verdict::Drop)
                }
            }
            PacketData::L3(ethertype, data) => {
                let matched = {
                    if ethertype == ETHERTYPE_IPV4 {
                        Ipv4Packet::new(data)
                            .map(|ipv4| {
                                ipv4.get_source() == self.ip || ipv4.get_destination() == self.ip
                            })
                            .unwrap_or(false)
                    } else if ethertype == ETHERTYPE_IPV6 {
                        Ipv6Packet::new(data)
                            .map(|ipv6| {
                                ipv6.get_source() == self.ip || ipv6.get_destination() == self.ip
                            })
                            .unwrap_or(false)
                    } else {
                        false
                    }
                };
                if matched ^ self.exclude {
                    Ok(Verdict::Accept(i))
                } else {
                    Ok(Verdict::Drop)
                }
            }
            PacketData::L4(_, _) => Err("Cannot filter IP, L4 content")?,
            PacketData::Unsupported(_) => Err("Cannot filter IP, unsupported data".to_owned()),
        }
    }
}

impl IPFilter {
    pub fn new(args: &[&str]) -> Self {
        assert!(!args.is_empty());
        let (exclude, ip_str) = if args[0].starts_with('!') {
            (true, &args[0][1..])
        } else {
            (false, args[0])
        };
        let ip = ip_str
            .parse()
            .expect("IP: argument is not a valid IP address");
        IPFilter { ip, exclude }
    }

    fn match_l3(&self, ethertype: u16, data: &[u8]) -> bool {
        let matched = {
            if ethertype == ETHERTYPE_IPV4 {
                Ipv4Packet::new(data)
                    .map(|ipv4| ipv4.get_source() == self.ip || ipv4.get_destination() == self.ip)
                    .unwrap_or(false)
            } else if ethertype == ETHERTYPE_IPV6 {
                Ipv6Packet::new(data)
                    .map(|ipv6| ipv6.get_source() == self.ip || ipv6.get_destination() == self.ip)
                    .unwrap_or(false)
            } else {
                false
            }
        };
        matched ^ self.exclude
    }
}

/// Common filter to select packets matching only this source IP address
///
/// Examples:
///   `-f 'Source:10.9.0.2'` to select packets maching this source
///   `-f 'Source:!10.9.0.2'` to select packets not maching this source
pub struct SourceFilter {
    ip: IpAddr,
    exclude: bool,
}

impl Filter for SourceFilter {
    fn filter<'i>(&self, _ctx: &ParseContext, i: PacketData<'i>) -> FResult<PacketData<'i>, String> {
        match i {
            PacketData::L2(data) => {
                let p = match EthernetPacket::new(data) {
                    Some(p) => p,
                    None => Err("Cannot build ethernet data")?,
                };
                if self.match_l3(p.get_ethertype().0, p.payload()) {
                    Ok(Verdict::Accept(i))
                } else {
                    Ok(Verdict::Drop)
                }
            }
            PacketData::L3(ethertype, data) => {
                if self.match_l3(ethertype, data) {
                    Ok(Verdict::Accept(i))
                } else {
                    Ok(Verdict::Drop)
                }
            }
            PacketData::L4(_, _) => Err("Cannot filter source, L4 content".to_string()),
            PacketData::Unsupported(_) => Err("Cannot filter source, unsupported data".to_string()),
        }
    }
}

impl SourceFilter {
    pub fn new(args: &[&str]) -> Self {
        assert!(!args.is_empty());
        let (exclude, ip_str) = if args[0].starts_with('!') {
            (true, &args[0][1..])
        } else {
            (false, args[0])
        };
        let ip = ip_str
            .parse()
            .expect("Source: argument is not a valid IP address");
        SourceFilter { ip, exclude }
    }

    fn match_l3(&self, ethertype: u16, data: &[u8]) -> bool {
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
        matched ^ self.exclude
    }
}
