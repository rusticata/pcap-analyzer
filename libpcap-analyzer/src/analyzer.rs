use std::cmp::min;
use std::net::IpAddr;

use std::collections::HashMap;

use rand::prelude::*;

use pnet_base::MacAddr;
use pnet_packet::ethernet::{EtherType, EtherTypes, EthernetPacket};
use pnet_packet::gre::GrePacket;
use pnet_packet::icmp::IcmpPacket;
use pnet_packet::icmpv6::Icmpv6Packet;
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::{Ipv4Flags, Ipv4Packet};
use pnet_packet::ipv6::Ipv6Packet;
use pnet_packet::tcp::TcpPacket;
use pnet_packet::udp::UdpPacket;
use pnet_packet::vlan::VlanPacket;
use pnet_packet::Packet;

use pcap_parser::*;

use libpcap_tools::*;

use crate::ip6_defrag::IPv6FragmentPacket;
use crate::ip_defrag::{DefragEngine, Fragment, IPDefragEngine};
use crate::packet_data::PacketData;
use libpcap_tools::{FiveTuple, Flow, FlowID, ThreeTuple};

use crate::plugins::Plugins;

struct L3Info {
    l3_proto: u16,
    three_tuple: ThreeTuple,
}

pub struct Analyzer {
    flows: HashMap<FlowID, Flow>,
    flows_id: HashMap<FiveTuple, FlowID>,
    plugins: Plugins,
    trng: ThreadRng,

    ipv4_defrag: Box<DefragEngine>,
    ipv6_defrag: Box<DefragEngine>,
}

impl Analyzer {
    pub fn new(plugins: Plugins) -> Analyzer {
        Analyzer {
            flows: HashMap::new(),
            flows_id: HashMap::new(),
            plugins,
            trng: rand::thread_rng(),
            ipv4_defrag: Box::new(IPDefragEngine::new()),
            ipv6_defrag: Box::new(IPDefragEngine::new()),
        }
    }

    fn handle_l2(&mut self, packet: &pcap_parser::Packet, ctx: &ParseContext) -> Result<(), Error> {
        debug!("handle_l2 (idx={})", ctx.pcap_index);

        // resize slice to remove padding
        let datalen = min(packet.header.caplen as usize, packet.data.len());
        let data = &packet.data[..datalen];

        for p in self.plugins.storage.values_mut() {
            let _ = p.handle_l2(&packet, &data);
        }

        match EthernetPacket::new(data) {
            Some(eth) => {
                // debug!("    source: {}", eth.get_source());
                // debug!("    dest  : {}", eth.get_destination());
                let dest = eth.get_destination();
                if dest.0 == 1 {
                    // Multicast
                    if eth.get_destination() == MacAddr(0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc) {
                        warn!("Cisco CDP/VTP/UDLD");
                    } else if eth.get_destination() == MacAddr(0x01, 0x00, 0x0c, 0xcd, 0xcd, 0xd0) {
                        warn!("Cisco Multicast address");
                    } else {
                        warn!("Ethernet broadcast (unknown)");
                    }
                    return Ok(());
                }
                debug!("    ethertype: 0x{:x}", eth.get_ethertype().0);
                self.handle_l3(&packet, &ctx, eth.payload(), eth.get_ethertype())
            }
            None => {
                // packet too small to be ethernet
                Ok(())
            }
        }
    }

    fn handle_l3(
        &mut self,
        packet: &pcap_parser::Packet,
        ctx: &ParseContext,
        data: &[u8],
        ethertype: EtherType,
    ) -> Result<(), Error> {
        if data.is_empty() {
            return Ok(());
        }

        match ethertype {
            EtherTypes::Ipv4 => self.handle_l3_ipv4(packet, ctx, data, ethertype),
            EtherTypes::Ipv6 => self.handle_l3_ipv6(packet, ctx, data, ethertype),
            EtherTypes::Vlan => self.handle_l3_vlan_801q(packet, ctx, data, ethertype),
            _ => {
                warn!("Unsupported ethertype {} (0x{:x})", ethertype, ethertype.0);
                self.handle_l3_generic(packet, ctx, data, ethertype)
            }
        }
    }

    fn handle_l3_ipv4(
        &mut self,
        packet: &pcap_parser::Packet,
        ctx: &ParseContext,
        data: &[u8],
        ethertype: EtherType,
    ) -> Result<(), Error> {
        debug!("handle_l3_ipv4 (idx={})", ctx.pcap_index);
        let ipv4 = Ipv4Packet::new(data).ok_or("Could not build IPv4 packet from data")?;

        // remove padding
        let (data, ipv4) = {
            if (ipv4.get_total_length() as usize) < data.len() {
                let d = &data[..ipv4.get_total_length() as usize];
                let ipv4 = Ipv4Packet::new(data).ok_or("Could not build IPv4 packet from data")?;
                (d, ipv4)
            } else {
                (data, ipv4)
            }
        };

        let l4_proto = ipv4.get_next_level_protocol();
        let t3 = ThreeTuple {
            proto: l4_proto.0,
            src: IpAddr::V4(ipv4.get_source()),
            dst: IpAddr::V4(ipv4.get_destination()),
        };

        // handle l3
        for p in self.plugins.storage.values_mut() {
            let _ = p.handle_l3(packet, data, ethertype.0, &t3);
        }

        // check IP fragmentation before calling handle_l4
        let frag_offset = (ipv4.get_fragment_offset() * 8) as usize;
        let more_fragments = ipv4.get_flags() & Ipv4Flags::MoreFragments != 0;
        let defrag = self.ipv4_defrag.update(
            ipv4.get_identification().into(),
            frag_offset,
            more_fragments,
            ipv4.payload(),
        );
        let data = match defrag {
            Fragment::NoFrag(d) => d,
            Fragment::Complete(ref v) => {
                warn!("IPv4 defrag done, using defrag buffer len={}", v.len());
                &v
            }
            Fragment::Incomplete => {
                debug!("IPv4 defragmentation incomplete");
                return Ok(());
            }
            Fragment::Error => {
                warn!("IPv4 defragmentation error");
                return Ok(());
            }
        };

        let l3_info = L3Info {
            three_tuple: t3,
            l3_proto: ethertype.0,
        };

        match l4_proto {
            IpNextHeaderProtocols::Tcp => self.handle_l4_tcp(packet, ctx, data, &l3_info),
            IpNextHeaderProtocols::Udp => self.handle_l4_udp(packet, ctx, data, &l3_info),
            IpNextHeaderProtocols::Icmp => self.handle_l4_icmp(packet, ctx, data, &l3_info),
            IpNextHeaderProtocols::Esp => self.handle_l4_generic(packet, ctx, data, &l3_info),
            IpNextHeaderProtocols::Gre => self.handle_l4_gre(packet, ctx, data, &l3_info),
            IpNextHeaderProtocols::Ipv6 => self.handle_l3(packet, ctx, data, EtherTypes::Ipv6),
            _ => {
                warn!("Unsupported L4 proto {}", l4_proto);
                self.handle_l4_generic(packet, ctx, data, &l3_info)
            }
        }
    }

    fn handle_l3_ipv6(
        &mut self,
        packet: &pcap_parser::Packet,
        ctx: &ParseContext,
        data: &[u8],
        ethertype: EtherType,
    ) -> Result<(), Error> {
        debug!("handle_l3_ipv6 (idx={})", ctx.pcap_index);
        let ipv6 = Ipv6Packet::new(data).ok_or("Could not build IPv6 packet from data")?;
        let l4_proto = ipv6.get_next_header();

        // XXX remove padding ?

        let t3 = ThreeTuple {
            proto: l4_proto.0,
            src: IpAddr::V6(ipv6.get_source()),
            dst: IpAddr::V6(ipv6.get_destination()),
        };

        for p in self.plugins.storage.values_mut() {
            let _ = p.handle_l3(&packet, data, ethertype.0, &t3);
        }

        let l3_info = L3Info {
            three_tuple: t3,
            l3_proto: ethertype.0,
        };

        let data = ipv6.payload();

        match l4_proto {
            IpNextHeaderProtocols::Tcp => self.handle_l4_tcp(packet, ctx, data, &l3_info),
            IpNextHeaderProtocols::Udp => self.handle_l4_udp(packet, ctx, data, &l3_info),
            IpNextHeaderProtocols::Icmpv6 => self.handle_l4_icmpv6(packet, ctx, data, &l3_info),
            IpNextHeaderProtocols::Esp => self.handle_l4_generic(packet, ctx, data, &l3_info),
            IpNextHeaderProtocols::Ipv4 => self.handle_l3(packet, ctx, data, EtherTypes::Ipv4),
            IpNextHeaderProtocols::Ipv6Frag => self.handle_l4_ipv6frag(packet, ctx, data, &l3_info),
            _ => {
                warn!("IPv6: Unsupported L4 proto {}", l4_proto);
                self.handle_l4_generic(packet, ctx, data, &l3_info)
            }
        }
    }

    fn handle_l3_vlan_801q(
        &mut self,
        packet: &pcap_parser::Packet,
        ctx: &ParseContext,
        data: &[u8],
        _ethertype: EtherType,
    ) -> Result<(), Error> {
        debug!("handle_l3_vlan_801q (idx={})", ctx.pcap_index);
        let vlan = VlanPacket::new(data).ok_or("Could not build 802.1Q Vlan packet from data")?;
        let next_ethertype = vlan.get_ethertype();
        debug!("    802.1q: VLAN id={}", vlan.get_vlan_identifier());

        self.handle_l3(&packet, &ctx, vlan.payload(), next_ethertype)
    }

    // Called when L3 layer is unknown
    fn handle_l3_generic(
        &mut self,
        packet: &pcap_parser::Packet,
        ctx: &ParseContext,
        data: &[u8],
        ethertype: EtherType,
    ) -> Result<(), Error> {
        debug!("handle_l3_generic (idx={})", ctx.pcap_index);
        // we don't know if there is padding to remove

        let t3 = ThreeTuple::default();

        // handle l3
        for p in self.plugins.storage.values_mut() {
            let _ = p.handle_l3(packet, data, ethertype.0, &t3);
        }

        // don't try to parse l4, we don't know how to get L4 data
        Ok(())
    }

    fn handle_l4_tcp(
        &mut self,
        packet: &pcap_parser::Packet,
        ctx: &ParseContext,
        data: &[u8],
        l3_info: &L3Info,
    ) -> Result<(), Error> {
        debug!("handle_l4_tcp (idx={})", ctx.pcap_index);
        let l3_data = data;
        debug!("    l3_data len: {}", l3_data.len());
        let tcp = TcpPacket::new(l3_data).ok_or("Could not build TCP packet from data")?;

        // XXX handle TCP defrag
        let l4_data = Some(tcp.payload());
        let src_port = tcp.get_source();
        let dst_port = tcp.get_destination();

        self.handle_l4_common(packet, ctx, l3_data, l3_info, src_port, dst_port, l4_data)
    }

    fn handle_l4_udp(
        &mut self,
        packet: &pcap_parser::Packet,
        ctx: &ParseContext,
        data: &[u8],
        l3_info: &L3Info,
    ) -> Result<(), Error> {
        debug!("handle_l4_udp (idx={})", ctx.pcap_index);
        let l3_data = data;
        debug!("    l3_data len: {}", l3_data.len());
        let udp = UdpPacket::new(l3_data).ok_or("Could not build UDP packet from data")?;

        let l4_data = Some(udp.payload());
        let src_port = udp.get_source();
        let dst_port = udp.get_destination();

        self.handle_l4_common(packet, ctx, l3_data, l3_info, src_port, dst_port, l4_data)
    }

    fn handle_l4_icmp(
        &mut self,
        packet: &pcap_parser::Packet,
        ctx: &ParseContext,
        data: &[u8],
        l3_info: &L3Info,
    ) -> Result<(), Error> {
        debug!("handle_l4_icmp (idx={})", ctx.pcap_index);
        let l3_data = data;

        let icmp = IcmpPacket::new(l3_data).ok_or("Could not build ICMP packet from data")?;
        debug!(
            "ICMP type={:?} code={:?}",
            icmp.get_icmp_type(),
            icmp.get_icmp_code()
        );

        let l4_data = Some(icmp.payload());
        let src_port = 0;
        let dst_port = 0;

        self.handle_l4_common(packet, ctx, l3_data, l3_info, src_port, dst_port, l4_data)
    }

    fn handle_l4_icmpv6(
        &mut self,
        packet: &pcap_parser::Packet,
        ctx: &ParseContext,
        data: &[u8],
        l3_info: &L3Info,
    ) -> Result<(), Error> {
        debug!("handle_l4_icmpv6 (idx={})", ctx.pcap_index);
        let l3_data = data;

        let icmpv6 = Icmpv6Packet::new(l3_data).ok_or("Could not build ICMPv6 packet from data")?;
        debug!(
            "ICMPv6 type={:?} code={:?}",
            icmpv6.get_icmpv6_type(),
            icmpv6.get_icmpv6_code()
        );

        let l4_data = Some(icmpv6.payload());
        let src_port = 0;
        let dst_port = 0;

        self.handle_l4_common(packet, ctx, l3_data, l3_info, src_port, dst_port, l4_data)
    }

    fn handle_l4_gre(
        &mut self,
        packet: &pcap_parser::Packet,
        ctx: &ParseContext,
        data: &[u8],
        _l3_info: &L3Info,
    ) -> Result<(), Error> {
        debug!("handle_l4_gre (idx={})", ctx.pcap_index);
        let l3_data = data;

        let gre = GrePacket::new(l3_data).ok_or("Could not build GRE packet from data")?;

        let next_proto = gre.get_protocol_type();
        let data = gre.payload();

        self.handle_l3(packet, ctx, data, EtherType(next_proto))
    }

    fn handle_l4_ipv6frag(
        &mut self,
        packet: &pcap_parser::Packet,
        ctx: &ParseContext,
        data: &[u8],
        l3_info: &L3Info,
    ) -> Result<(), Error> {
        debug!("handle_l4_ipv6frag (idx={})", ctx.pcap_index);
        let l3_data = data;

        let ip6frag = IPv6FragmentPacket::new(l3_data)
            .ok_or("Could not build IPv6FragmentPacket packet from data")?;
        debug!(
            "IPv6FragmentPacket more_fragments={} next_header={} id=0x{:x}",
            ip6frag.more_fragments(),
            ip6frag.get_next_header(),
            ip6frag.get_identification()
        );

        // check IP fragmentation before calling handle_l4
        let frag_offset = (ip6frag.get_fragment_offset() * 8) as usize;
        let more_fragments = ip6frag.more_fragments();
        let defrag = self.ipv6_defrag.update(
            ip6frag.get_identification().into(),
            frag_offset,
            more_fragments,
            ip6frag.payload(),
        );
        let data = match defrag {
            Fragment::NoFrag(d) => d,
            Fragment::Complete(ref v) => {
                warn!("IPv6Fragment defrag done, using defrag buffer len={}", v.len());
                &v
            }
            Fragment::Incomplete => {
                debug!("IPv6Fragment defragmentation incomplete");
                return Ok(());
            }
            Fragment::Error => {
                warn!("IPv6Fragment defragmentation error");
                return Ok(());
            }
        };

        let l4_proto = ip6frag.get_next_header();

        match l4_proto {
            IpNextHeaderProtocols::Tcp => self.handle_l4_tcp(packet, ctx, data, &l3_info),
            IpNextHeaderProtocols::Udp => self.handle_l4_udp(packet, ctx, data, &l3_info),
            IpNextHeaderProtocols::Icmp => self.handle_l4_icmp(packet, ctx, data, &l3_info),
            _ => {
                warn!("IPv6Fragment: Unsupported L4 proto {}", l4_proto);
                self.handle_l4_generic(packet, ctx, data, &l3_info)
            }
        }
    }

    fn handle_l4_generic(
        &mut self,
        packet: &pcap_parser::Packet,
        ctx: &ParseContext,
        data: &[u8],
        l3_info: &L3Info,
    ) -> Result<(), Error> {
        debug!(
            "handle_l4_generic (idx={}, l4_proto={})",
            ctx.pcap_index, l3_info.three_tuple.proto
        );
        let l3_data = data;
        // in generic function, we don't know how to get l4_data
        let l4_data = None;
        let src_port = 0;
        let dst_port = 0;

        self.handle_l4_common(packet, ctx, l3_data, l3_info, src_port, dst_port, l4_data)
    }

    fn handle_l4_common(
        &mut self,
        packet: &pcap_parser::Packet,
        _ctx: &ParseContext,
        l3_data: &[u8],
        l3_info: &L3Info,
        src_port: u16,
        dst_port: u16,
        l4_data: Option<&[u8]>,
    ) -> Result<(), Error> {
        let five_tuple = FiveTuple::from_three_tuple(&l3_info.three_tuple, src_port, dst_port);
        debug!("5t: {:?}", five_tuple);
        let now = Duration::new(packet.header.ts_sec, packet.header.ts_usec);

        // lookup flow
        let flow_id = match self.lookup_flow(&five_tuple) {
            Some(id) => id,
            None => {
                let flow = Flow::new(&five_tuple, packet.header.ts_sec, packet.header.ts_usec);
                self.insert_flow(five_tuple.clone(), flow)
            }
        };

        // take flow ownership
        let flow = self
            .flows
            .get_mut(&flow_id)
            .ok_or("could not get flow from ID")?;
        flow.flow_id = flow_id;
        flow.last_seen = now;

        let to_server = flow.five_tuple == five_tuple;

        let pdata = PacketData {
            five_tuple: &five_tuple,
            to_server,
            l3_type: l3_info.l3_proto,
            l3_data,
            l4_type: l3_info.three_tuple.proto,
            l4_data,
            flow: Some(flow),
        };
        for p in self.plugins.storage.values_mut() {
            let _ = p.handle_l4(&packet, &pdata);
        }

        // XXX do other stuff

        // XXX check session expiration
        // const FLOW_EXPIRATION: u32 = 100;
        // for (flow_id, flow) in self.flows.iter() {
        //     if (now - flow.last_seen).secs > FLOW_EXPIRATION {
        //         warn!(
        //             "Flow {} candidate for expiration (delay: {} secs)",
        //             flow_id,
        //             (now - flow.last_seen).secs
        //         );
        //     }
        // }

        Ok(())
    }

    fn lookup_flow(&mut self, five_t: &FiveTuple) -> Option<FlowID> {
        self.flows_id.get(&five_t).map(|&id| id)
    }

    /// Insert a flow in the hash tables.
    /// Takes ownership of five_t and flow
    fn insert_flow(&mut self, five_t: FiveTuple, flow: Flow) -> FlowID {
        // try reverse flow first
        // self.flows_id.entry(&five_t.get_reverse())
        //     .or_insert_with(
        //         );
        let rev_id = self.flows_id.get(&five_t.get_reverse()).map(|&id| id);
        match rev_id {
            Some(id) => {
                // insert reverse flow ID
                debug!("inserting reverse flow ID {}", id);
                self.flows_id.insert(five_t, id);
                return id;
            }
            _ => (),
        }
        // get a new flow index (XXX currently: random number)
        let id = self.trng.gen();
        debug!("Inserting new flow (id={})", id);
        debug!("    flow: {:?}", flow);
        self.flows.insert(id, flow);
        self.flows_id.insert(five_t, id);
        id
    }
}

impl PcapAnalyzer for Analyzer {
    /// Initialize all plugins
    fn init(&mut self) -> Result<(), Error> {
        self.plugins
            .storage
            .values_mut()
            .for_each(|plugin| plugin.pre_process());
        Ok(())
    }

    /// Dispatch function: given a packet, use link type to get the real data, and
    /// call the matching handling function (some pcap blocks encode ethernet, or IPv4 etc.)
    fn handle_packet(
        &mut self,
        packet: &pcap_parser::Packet,
        ctx: &ParseContext,
    ) -> Result<(), Error> {
        let link_type = match ctx.interfaces.get(packet.interface as usize) {
            Some(if_info) => if_info.link_type,
            None => {
                warn!(
                    "Could not get link_type (missing interface info) for packet idx={}",
                    ctx.pcap_index
                );
                return Err(Error::Generic("Missing interface info"));
            }
        };
        debug!("linktype: {}", link_type);
        match link_type {
            Linktype::NULL => {
                // XXX read first u32 in *host order*: 2 if IPv4, etc.
                self.handle_l3(&packet, &ctx, &packet.data[4..], EtherTypes::Ipv4) // XXX overflow
            }
            Linktype::RAW => {
                // XXX may be IPv4 or IPv6, check IP header ...
                self.handle_l3(&packet, &ctx, &packet.data, EtherTypes::Ipv4)
            }
            Linktype(228) /* IPV4 */ => self.handle_l3(&packet, &ctx, &packet.data, EtherTypes::Ipv4),
            Linktype(229) /* IPV6 */ => self.handle_l3(&packet, &ctx, &packet.data, EtherTypes::Ipv6),
            Linktype::ETHERNET => self.handle_l2(&packet, &ctx),
            Linktype::FDDI => self.handle_l3(&packet, &ctx, &packet.data[21..], EtherTypes::Ipv4),
            Linktype::NFLOG => match pcap_parser::data::parse_nflog(packet.data) {
                Ok((_, nf)) => {
                    let ethertype = match nf.header.af {
                        2 => EtherTypes::Ipv4,
                        10 => EtherTypes::Ipv6,
                        af => {
                            warn!("NFLOG: unsupported address family {}", af);
                            EtherType::new(0)
                        }
                    };
                    let data = nf
                        .get_payload()
                        .ok_or("Unable to get payload from nflog data")?;
                    self.handle_l3(&packet, &ctx, &data, ethertype)
                }
                _ => Ok(()),
            },
            l => {
                warn!("Unsupported link type {}", l);
                Ok(())
            }
        }
    }

    /// Finalize analysis and notify plugins
    fn teardown(&mut self) {
        // expire remaining flows
        debug!("{} flows remaining in table", self.flows.len());
        for f in self.flows.values() {
            for p in self.plugins.storage.values_mut() {
                p.flow_terminate(&f);
            }
        }
        self.flows.clear();
        self.flows_id.clear();

        self.plugins
            .storage
            .values_mut()
            .for_each(|plugin| plugin.post_process());
    }
}
