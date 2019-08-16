use crate::plugin_registry::PluginRegistry;
use crate::ip6_defrag::IPv6FragmentPacket;
use crate::ip_defrag::{DefragEngine, Fragment, IPDefragEngine};
use crate::packet_info::PacketInfo;
use crate::plugin::*;
use libpcap_tools::*;

use pcap_parser::data::PacketData;
use rand::prelude::*;
use rand_chacha::*;
use std::cell::RefCell;
use std::cmp::min;
use std::collections::HashMap;
use std::net::IpAddr;

use pnet_base::MacAddr;
use pnet_packet::ethernet::{EtherType, EtherTypes, EthernetPacket};
use pnet_packet::gre::GrePacket;
use pnet_packet::icmp::IcmpPacket;
use pnet_packet::icmpv6::Icmpv6Packet;
use pnet_packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet_packet::ipv4::{Ipv4Flags, Ipv4Packet};
use pnet_packet::ipv6::Ipv6Packet;
use pnet_packet::tcp::TcpPacket;
use pnet_packet::udp::UdpPacket;
use pnet_packet::vlan::VlanPacket;
use pnet_packet::Packet as PnetPacket;

thread_local!(pub(crate) static TAD : RefCell<ThreadAnalyzerData> = RefCell::new(ThreadAnalyzerData::new()));

struct L3Info {
    l3_proto: u16,
    three_tuple: ThreeTuple,
}

pub(crate) struct ThreadAnalyzerData {
    pub(crate) flows: HashMap<FlowID, Flow>,
    flows_id: HashMap<FiveTuple, FlowID>,
    trng: ChaChaRng,

    ipv4_defrag: Box<dyn DefragEngine>,
    ipv6_defrag: Box<dyn DefragEngine>,
}

/// Pcap/Pcap-ng analyzer
///
/// Read input pcap/pcap-ng data, parse it and call plugin callbacks
/// for each ISO layer (L2 if available, L3 and L4).
/// Flows are created for L4 sessions. Events are sent when plugins
/// are created or destroyed.
///
/// The number of worker threads can be configured from the `num_threads`
/// configuration variable. By default, it is 0 (auto-detect the number
/// of cores and create the same number of threads).
///
/// All callbacks for a single ISO layer will be called concurrently before
/// calling the next level callbacks.
pub struct Analyzer {
    registry: PluginRegistry,
}

impl Analyzer {
    pub fn new(registry: PluginRegistry, _config: &Config) -> Analyzer {
        Analyzer {
            registry,
        }
    }

    fn handle_l2(&mut self, packet: &Packet, ctx: &ParseContext, data: &[u8]) -> Result<(), Error> {
        debug!("handle_l2 (idx={})", ctx.pcap_index);

        // resize slice to remove padding
        let datalen = min(packet.caplen as usize, data.len());
        let data = &data[..datalen];

        // let start = ::std::time::Instant::now();
        self.registry.run_plugins_l2(&packet, &data);
        // let elapsed = start.elapsed();
        // debug!("Time to run l2 plugins: {}.{}", elapsed.as_secs(), elapsed.as_millis());

        match EthernetPacket::new(data) {
            Some(eth) => {
                // debug!("    source: {}", eth.get_source());
                // debug!("    dest  : {}", eth.get_destination());
                let dest = eth.get_destination();
                if dest.0 == 1 {
                    // Multicast
                    if eth.get_destination() == MacAddr(0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc) {
                        info!("Cisco CDP/VTP/UDLD");
                        return Ok(());
                    } else if eth.get_destination() == MacAddr(0x01, 0x00, 0x0c, 0xcd, 0xcd, 0xd0) {
                        info!("Cisco Multicast address");
                        return Ok(());
                    } else {
                        info!("Ethernet broadcast (unknown type) (idx={})", ctx.pcap_index);
                    }
                }
                debug!("    ethertype: 0x{:x}", eth.get_ethertype().0);
                handle_l3(
                    &packet,
                    &ctx,
                    eth.payload(),
                    eth.get_ethertype(),
                    &self.registry,
                )
            }
            None => {
                // packet too small to be ethernet
                Ok(())
            }
        }
    }
}

pub(crate) fn handle_l3(
    packet: &Packet,
    ctx: &ParseContext,
    data: &[u8],
    ethertype: EtherType,
    registry: &PluginRegistry,
) -> Result<(), Error> {
    if data.is_empty() {
        return Ok(());
    }

    match ethertype {
        EtherTypes::Ipv4 => handle_l3_ipv4(packet, ctx, data, ethertype, registry),
        EtherTypes::Ipv6 => handle_l3_ipv6(packet, ctx, data, ethertype, registry),
        EtherTypes::Vlan => handle_l3_vlan_801q(packet, ctx, data, ethertype, registry),
        // ignore ARP packets
        EtherTypes::Arp => Ok(()),
        e => {
            warn!("Unsupported ethertype {} (0x{:x})", e, e.0);
            handle_l3_generic(packet, ctx, data, e, registry)
        }
    }
}

fn handle_l3_ipv4(
    packet: &Packet,
    ctx: &ParseContext,
    data: &[u8],
    ethertype: EtherType,
    registry: &PluginRegistry,
) -> Result<(), Error> {
    debug!("handle_l3_ipv4 (idx={})", ctx.pcap_index);
    let ipv4 = Ipv4Packet::new(data).ok_or("Could not build IPv4 packet from data")?;
    // eprintln!("ABORT pkt {:?}", ipv4);
    let orig_len = data.len();

    let ip_len = ipv4.get_total_length() as usize;

    // remove padding
    let (data, ipv4) = {
        if ip_len < data.len() && ip_len > 0 {
            let d = &data[..ip_len];
            let ipv4 = Ipv4Packet::new(d).ok_or("Could not build IPv4 packet from data")?;
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

    run_l3_plugins(packet, data, ethertype.0, &t3, &registry);

    // if get_total_length is 0, assume TSO offloading and no padding
    let payload = if ip_len == 0 {
        warn!(
            "IPv4: packet reported length is 0. Assuming TSO (idx={})",
            ctx.pcap_index
        );
        // the payload() function from pnet will fail
        let start = ipv4.get_header_length() as usize * 4;
        if start > data.len() {
            warn!("IPv4: ip_len == 0 and ipv4.get_header_length is invalid!");
            return Ok(());
        }
        &data[start..]
    } else {
        ipv4.payload()
    };

    // check IP fragmentation before calling handle_l4
    let frag_offset = (ipv4.get_fragment_offset() * 8) as usize;
    let more_fragments = ipv4.get_flags() & Ipv4Flags::MoreFragments != 0;
    let defrag = TAD.with(|f| {
        let mut f = f.borrow_mut();
        f.ipv4_defrag.update(
            ipv4.get_identification().into(),
            frag_offset,
            more_fragments,
            payload,
        )
    });
    let payload = match defrag {
        Fragment::NoFrag(d) => {
            debug_assert!(d.len() < orig_len);
            d
        },
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

    handle_l3_common(packet, ctx, payload, &l3_info, &registry)
}

fn handle_l3_ipv6(
    packet: &Packet,
    ctx: &ParseContext,
    data: &[u8],
    ethertype: EtherType,
    registry: &PluginRegistry,
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

    run_l3_plugins(packet, data, ethertype.0, &t3, registry);

    let l3_info = L3Info {
        three_tuple: t3,
        l3_proto: ethertype.0,
    };

    let data = ipv6.payload();
    handle_l3_common(packet, ctx, data, &l3_info, &registry)
}

fn handle_l3_vlan_801q(
    packet: &Packet,
    ctx: &ParseContext,
    data: &[u8],
    _ethertype: EtherType,
    registry: &PluginRegistry,
) -> Result<(), Error> {
    debug!("handle_l3_vlan_801q (idx={})", ctx.pcap_index);
    let vlan = VlanPacket::new(data).ok_or("Could not build 802.1Q Vlan packet from data")?;
    let next_ethertype = vlan.get_ethertype();
    debug!("    802.1q: VLAN id={}", vlan.get_vlan_identifier());

    handle_l3(&packet, &ctx, vlan.payload(), next_ethertype, registry)
}

// Called when L3 layer is unknown
fn handle_l3_generic(
    packet: &Packet,
    ctx: &ParseContext,
    data: &[u8],
    ethertype: EtherType,
    registry: &PluginRegistry,
) -> Result<(), Error> {
    debug!("handle_l3_generic (idx={})", ctx.pcap_index);
    // we don't know if there is padding to remove
    //run Layer 3 plugins
    // self.run_l3_plugins(packet, data, ethertype.0, &ThreeTuple::default());
    // run l3 plugins
    // let start = ::std::time::Instant::now();
    registry.run_plugins_ethertype(packet, ethertype.0, &ThreeTuple::default(), data);
    // let elapsed = start.elapsed();
    // debug!("Time to run l3 plugins: {}.{}", elapsed.as_secs(), elapsed.as_millis());
    // don't try to parse l4, we don't know how to get L4 data
    Ok(())
}

fn handle_l3_common(
    packet: &Packet,
    ctx: &ParseContext,
    data: &[u8],
    l3_info: &L3Info,
    registry: &PluginRegistry,
) -> Result<(), Error> {
    match IpNextHeaderProtocol(l3_info.three_tuple.proto) {
        IpNextHeaderProtocols::Tcp => handle_l4_tcp(packet, ctx, data, &l3_info, registry),
        IpNextHeaderProtocols::Udp => handle_l4_udp(packet, ctx, data, &l3_info, registry),
        IpNextHeaderProtocols::Icmp => handle_l4_icmp(packet, ctx, data, &l3_info, registry),
        IpNextHeaderProtocols::Icmpv6 => handle_l4_icmpv6(packet, ctx, data, &l3_info, registry),
        IpNextHeaderProtocols::Esp => handle_l4_generic(packet, ctx, data, &l3_info, registry),
        IpNextHeaderProtocols::Gre => handle_l4_gre(packet, ctx, data, &l3_info, registry),
        IpNextHeaderProtocols::Ipv4 => handle_l3(packet, ctx, data, EtherTypes::Ipv4, registry),
        IpNextHeaderProtocols::Ipv6 => handle_l3(packet, ctx, data, EtherTypes::Ipv6, registry),
        IpNextHeaderProtocols::Ipv6Frag => {
            handle_l4_ipv6frag(packet, ctx, data, &l3_info, registry)
        }
        p => {
            warn!("Unsupported L4 proto {}", p);
            handle_l4_generic(packet, ctx, data, &l3_info, registry)
        }
    }
}

fn handle_l4_tcp(
    packet: &Packet,
    ctx: &ParseContext,
    data: &[u8],
    l3_info: &L3Info,
    registry: &PluginRegistry,
) -> Result<(), Error> {
    debug!("handle_l4_tcp (idx={})", ctx.pcap_index);
    debug!("    l4_data len: {}", data.len());
    let tcp = TcpPacket::new(data).ok_or("Could not build TCP packet from data")?;

    // XXX handle TCP defrag
    let l4_payload = Some(tcp.payload());
    let src_port = tcp.get_source();
    let dst_port = tcp.get_destination();

    handle_l4_common(
        packet, ctx, data, l3_info, src_port, dst_port, l4_payload, &registry,
    )
}

fn handle_l4_udp(
    packet: &Packet,
    ctx: &ParseContext,
    data: &[u8],
    l3_info: &L3Info,
    registry: &PluginRegistry,
) -> Result<(), Error> {
    debug!("handle_l4_udp (idx={})", ctx.pcap_index);
    debug!("    l4_data len: {}", data.len());
    let udp = UdpPacket::new(data).ok_or("Could not build UDP packet from data")?;

    let l4_payload = Some(udp.payload());
    let src_port = udp.get_source();
    let dst_port = udp.get_destination();

    handle_l4_common(
        packet, ctx, data, l3_info, src_port, dst_port, l4_payload, &registry,
    )
}

fn handle_l4_icmp(
    packet: &Packet,
    ctx: &ParseContext,
    data: &[u8],
    l3_info: &L3Info,
    registry: &PluginRegistry,
) -> Result<(), Error> {
    debug!("handle_l4_icmp (idx={})", ctx.pcap_index);
    let icmp = IcmpPacket::new(data).ok_or("Could not build ICMP packet from data")?;
    debug!(
        "ICMP type={:?} code={:?}",
        icmp.get_icmp_type(),
        icmp.get_icmp_code()
    );

    let l4_payload = Some(icmp.payload());
    let src_port = icmp.get_icmp_type().0 as u16;
    let dst_port = icmp.get_icmp_code().0 as u16;

    handle_l4_common(
        packet, ctx, data, l3_info, src_port, dst_port, l4_payload, registry,
    )
}

fn handle_l4_icmpv6(
    packet: &Packet,
    ctx: &ParseContext,
    data: &[u8],
    l3_info: &L3Info,
    registry: &PluginRegistry,
) -> Result<(), Error> {
    debug!("handle_l4_icmpv6 (idx={})", ctx.pcap_index);
    let icmpv6 = Icmpv6Packet::new(data).ok_or("Could not build ICMPv6 packet from data")?;
    debug!(
        "ICMPv6 type={:?} code={:?}",
        icmpv6.get_icmpv6_type(),
        icmpv6.get_icmpv6_code()
    );

    let l4_payload = Some(icmpv6.payload());
    let src_port = 0;
    let dst_port = 0;

    handle_l4_common(
        packet, ctx, data, l3_info, src_port, dst_port, l4_payload, registry,
    )
}

fn handle_l4_gre(
    packet: &Packet,
    ctx: &ParseContext,
    data: &[u8],
    _l3_info: &L3Info,
    registry: &PluginRegistry,
) -> Result<(), Error> {
    debug!("handle_l4_gre (idx={})", ctx.pcap_index);
    let l3_data = data;

    let gre = GrePacket::new(l3_data).ok_or("Could not build GRE packet from data")?;

    let next_proto = gre.get_protocol_type();
    // XXX can panic: 'Source routed GRE packets not supported'
    let data = gre.payload();

    handle_l3(packet, ctx, data, EtherType(next_proto), registry)
}

fn handle_l4_ipv6frag(
    packet: &Packet,
    ctx: &ParseContext,
    data: &[u8],
    l3_info: &L3Info,
    registry: &PluginRegistry,
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

    let defrag = TAD.with(|f| {
        let mut f = f.borrow_mut();
        // check IP fragmentation before calling handle_l4
        let frag_offset = (ip6frag.get_fragment_offset() * 8) as usize;
        let more_fragments = ip6frag.more_fragments();
        f.ipv6_defrag.update(
            ip6frag.get_identification().into(),
            frag_offset,
            more_fragments,
            ip6frag.payload(),
        )
    });
    let data = match defrag {
        Fragment::NoFrag(d) => d,
        Fragment::Complete(ref v) => {
            warn!(
                "IPv6Fragment defrag done, using defrag buffer len={}",
                v.len()
            );
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
        IpNextHeaderProtocols::Tcp => handle_l4_tcp(packet, ctx, data, &l3_info, registry),
        IpNextHeaderProtocols::Udp => handle_l4_udp(packet, ctx, data, &l3_info, registry),
        IpNextHeaderProtocols::Icmp => handle_l4_icmp(packet, ctx, data, &l3_info, registry),
        _ => {
            warn!("IPv6Fragment: Unsupported L4 proto {}", l4_proto);
            handle_l4_generic(packet, ctx, data, &l3_info, registry)
        }
    }
}

fn handle_l4_generic(
    packet: &Packet,
    ctx: &ParseContext,
    data: &[u8],
    l3_info: &L3Info,
    registry: &PluginRegistry,
) -> Result<(), Error> {
    debug!(
        "handle_l4_generic (idx={}, l4_proto={})",
        ctx.pcap_index, l3_info.three_tuple.proto
    );
    // in generic function, we don't know how to get l4_payload
    let l4_payload = None;
    let src_port = 0;
    let dst_port = 0;

    handle_l4_common(
        packet, ctx, data, l3_info, src_port, dst_port, l4_payload, registry,
    )
}

fn handle_l4_common(
    packet: &Packet,
    ctx: &ParseContext,
    l4_data: &[u8],
    l3_info: &L3Info,
    src_port: u16,
    dst_port: u16,
    l4_payload: Option<&[u8]>,
    registry: &PluginRegistry,
) -> Result<(), Error> {
    let five_tuple = FiveTuple::from_three_tuple(&l3_info.three_tuple, src_port, dst_port);
    debug!("5t: {}", five_tuple);
    let now = packet.ts.clone();

    // lookup flow
    // let flow_id = match a.lookup_flow(&five_tuple) {
    let flow = TAD.with(|f| {
        let mut f = f.borrow_mut();
        let flow_id = match f.lookup_flow(&five_tuple) {
            Some(id) => id,
            None => {
                let flow = Flow::new(&five_tuple, packet.ts.secs, packet.ts.micros);
                gen_event_new_flow(&flow, registry);
                f.insert_flow(five_tuple.clone(), flow)
            }
        };

        // take flow ownership
        let flow = f
            .flows
            .get_mut(&flow_id)
            .expect("could not get flow from ID");
        flow.flow_id = flow_id;
        flow.last_seen = now;
        flow.clone()
    });

    let to_server = flow.five_tuple == five_tuple;

    let pinfo = PacketInfo {
        five_tuple: &five_tuple,
        to_server,
        l3_type: l3_info.l3_proto,
        l4_data,
        l4_type: l3_info.three_tuple.proto,
        l4_payload,
        flow: Some(&flow),
        pcap_index: ctx.pcap_index,
    };
    // let start = ::std::time::Instant::now();
    registry.run_plugins_transport(pinfo.l4_type, packet, &pinfo);
    // let elapsed = start.elapsed();
    // debug!("Time to run l4 plugins: {}.{}", elapsed.as_secs(), elapsed.as_millis());

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

// Run all Layer 3 plugins
pub(crate) fn run_l3_plugins(
    packet: &Packet,
    data: &[u8],
    ethertype: u16,
    three_tuple: &ThreeTuple,
    registry: &PluginRegistry,
) {
    // run l3 plugins
    // let start = ::std::time::Instant::now();
    registry.run_plugins_ethertype(packet, ethertype, three_tuple, data);
    // let elapsed = start.elapsed();
    // debug!("Time to run l3 plugins: {}.{}", elapsed.as_secs(), elapsed.as_millis());
}

pub(crate) fn gen_event_new_flow(flow: &Flow, registry: &PluginRegistry) {
    // let start = ::std::time::Instant::now();
    registry.run_plugins(
        |p| p.plugin_type() & PLUGIN_FLOW_NEW != 0,
        |p| p.flow_created(flow),
    );
    // let elapsed = start.elapsed();
    // debug!("Time to run flow_created: {}.{}", elapsed.as_secs(), elapsed.as_millis());
}

impl PcapAnalyzer for Analyzer {
    /// Initialize all plugins
    fn init(&mut self) -> Result<(), Error> {
        self.registry.run_plugins(|_| true, |p| p.pre_process());
        Ok(())
    }

    /// Dispatch function: given a packet, use link type to get the real data, and
    /// call the matching handling function (some pcap blocks encode ethernet, or IPv4 etc.)
    fn handle_packet(
        &mut self,
        packet: &Packet,
        ctx: &ParseContext,
    ) -> Result<(), Error> {
        match packet.data {
            PacketData::L2(data) => self.handle_l2(packet, &ctx, data),
            PacketData::L3(ethertype, data) => {
                handle_l3(
                    packet,
                    &ctx,
                    data,
                    EtherType(ethertype),
                    &self.registry,
                )
            }
            PacketData::L4(_,_) => unimplemented!(), // XXX
            PacketData::Unsupported(_) => unimplemented!( ), // XXX
        }
    }

    /// Finalize analysis and notify plugins
    fn teardown(&mut self) {
        TAD.with(|f| {
            let mut f = f.borrow_mut();
            let flows = &f.flows;
            // expire remaining flows
            debug!("{} flows remaining in table", flows.len());
            // let start = ::std::time::Instant::now();
            self.registry.run_plugins(
                |p| p.plugin_type() & PLUGIN_FLOW_DEL != 0,
                |p| {
                    flows.values().for_each(|flow| {
                        let _ = p.flow_destroyed(flow);
                    });
                },
                );
            // let elapsed = start.elapsed();
            // debug!("Time to run flow_destroyed {}.{}", elapsed.as_secs(), elapsed.as_millis());
            f.flows.clear();
            f.flows_id.clear();

            self.registry.run_plugins(|_| true, |p| p.post_process());
        });
    }
}

impl SafePcapAnalyzer for Analyzer {}

impl ThreadAnalyzerData {
    pub fn new() -> ThreadAnalyzerData {
        ThreadAnalyzerData {
            flows: HashMap::new(),
            flows_id: HashMap::new(),
            trng: ChaChaRng::from_rng(rand::thread_rng()).unwrap(),
            ipv4_defrag: Box::new(IPDefragEngine::new()),
            ipv6_defrag: Box::new(IPDefragEngine::new()),
        }
    }

    pub fn lookup_flow(&mut self, five_t: &FiveTuple) -> Option<FlowID> {
        self.flows_id.get(&five_t).map(|&id| id)
    }
    /// Insert a flow in the hash tables.
    /// Takes ownership of five_t and flow
    pub fn insert_flow(&mut self, five_t: FiveTuple, flow: Flow) -> FlowID {
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
