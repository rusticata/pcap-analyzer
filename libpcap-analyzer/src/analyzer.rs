use std::cmp::min;
use std::io::Read;
use std::net::IpAddr;

use std::collections::HashMap;

use rand::prelude::*;

use circular::Buffer;
use nom::HexDisplay;
use nom::{IResult, Needed, Offset};

use pnet::packet::ethernet::{EtherType, EtherTypes, EthernetPacket};
use pnet::packet::gre::GrePacket;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Flags, Ipv4Packet};
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::vlan::VlanPacket;
use pnet::packet::Packet;
use pnet::util::MacAddr;

use pcap_parser::*;

use crate::pcapng_extra::{pcapng_build_interface, pcapng_build_packet, InterfaceInfo};

use crate::five_tuple::FiveTuple;
use crate::flow::{Flow, FlowID};
use crate::ip_defrag::{DefragEngine, Fragment, IP4DefragEngine};
use crate::packet_data::PacketData;
use crate::three_tuple::ThreeTuple;

use crate::plugins::Plugins;

use crate::duration::Duration;

enum PcapType {
    // Unknown,
    Pcap,
    PcapNG,
}

struct L3Info {
    l3_proto: u16,
    three_tuple: ThreeTuple,
}

struct ParseContext {
    if_info: InterfaceInfo,
    link_type: Linktype,

    pcap_index: usize,

    first_packet_ts: Duration,
    rel_ts: Duration,
}

pub struct Analyzer<'a> {
    flows: HashMap<FlowID, Flow>,
    flows_id: HashMap<FiveTuple, FlowID>,
    plugins: &'a mut Plugins,
    trng: ThreadRng,

    ipv4_defrag: Box<DefragEngine>,
}

impl<'a> Analyzer<'a> {
    pub fn new(plugins: &mut Plugins) -> Analyzer {
        Analyzer {
            flows: HashMap::new(),
            flows_id: HashMap::new(),
            plugins,
            trng: rand::thread_rng(),
            ipv4_defrag: Box::new(IP4DefragEngine::new()),
        }
    }

    /// Main function: for a reader, read all pcap data and run all plugins
    pub fn run<R: Read>(&mut self, f: &mut R) -> Result<(), &'static str> {
        let mut capacity = 16384 * 8;
        let buffer_max_size = 65536 * 8;
        let mut b = Buffer::with_capacity(capacity);
        let sz = f.read(b.space()).or(Err("unable to read data"))?;
        b.fill(sz);

        let mut context = ParseContext {
            if_info: InterfaceInfo::new(),
            link_type: Linktype(0),
            pcap_index: 1,
            first_packet_ts: Duration::new(0, 0),
            rel_ts: Duration::new(0, 0),
        };

        let (length, in_pcap_type) = {
            if let Ok((remaining, _h)) = pcapng::parse_sectionheaderblock(b.data()) {
                (b.data().offset(remaining), PcapType::PcapNG)
            } else if let Ok((remaining, h)) = pcap::parse_pcap_header(b.data()) {
                context.link_type = Linktype(h.network);
                (b.data().offset(remaining), PcapType::Pcap)
            } else {
                return Err("couldn't parse input file header");
            }
        };

        // println!("consumed {} bytes", length);
        b.consume(length);

        let mut consumed = length;
        let mut last_incomplete_offset = 0;

        self.plugins
            .storage
            .values_mut()
            .for_each(|plugin| plugin.pre_process());

        let get_next_packet = match in_pcap_type {
            PcapType::Pcap => pcap_get_raw_data,
            PcapType::PcapNG => pcapng_get_raw_data,
        };

        loop {
            let needed: Option<Needed>;

            // println!("{}", (&b.data()[..min(b.available_data(), 128)]).to_hex(16));

            loop {
                let length = {
                    // read block
                    match get_next_packet(b.data(), &mut context) {
                        Ok((remaining, opt_packet)) => {
                            // eprintln!("parse_block ok, index {}", pcap_index);
                            // println!("parsed packet: {:?}", packet);

                            if let Some(packet) = opt_packet {
                                debug!("**************************************************************");
                                let ts = Duration::new(packet.header.ts_sec, packet.header.ts_usec);
                                if context.pcap_index == 1 {
                                    context.first_packet_ts = ts;
                                }
                                debug!(
                                    "    time  : {} / {}",
                                    packet.header.ts_sec, packet.header.ts_usec
                                );
                                context.rel_ts = ts - context.first_packet_ts; // an underflow is weird but not critical
                                debug!(
                                    "    reltime  : {}.{}",
                                    context.rel_ts.secs, context.rel_ts.micros
                                );
                                self.handle_packet(&packet, &context);
                                context.pcap_index += 1;
                            }

                            b.data().offset(remaining)
                        }
                        Err(nom::Err::Incomplete(n)) => {
                            // println!("not enough data, needs a refill: {:?}", n);

                            needed = Some(n);
                            break;
                        }
                        Err(nom::Err::Failure(e)) => {
                            eprintln!("parse failure: {:?}", e);
                            return Err("parse error");
                        }
                        Err(nom::Err::Error(_e)) => {
                            // panic!("parse error: {:?}", e);
                            eprintln!("parse error");
                            eprintln!("{}", (&b.data()[..min(b.available_data(), 128)]).to_hex(16));
                            return Err("parse error");
                        }
                    }
                };
                // println!("consuming {} of {} bytes", length, b.available_data());
                b.consume(length);
                consumed += length;
            }

            if let Some(Needed::Size(sz)) = needed {
                if sz > b.capacity() {
                    // println!("growing buffer capacity from {} bytes to {} bytes", capacity, capacity*2);
                    capacity = (capacity * 3) / 2;
                    if capacity > buffer_max_size {
                        warn!(
                            "requesting capacity {} over buffer_max_size {}",
                            capacity, buffer_max_size
                        );
                        return Err("buffer size too small");
                    }
                    b.grow(capacity);
                } else {
                    // eprintln!("incomplete, but less missing bytes {} than buffer size {} consumed {}", sz, capacity, consumed);
                    if last_incomplete_offset == consumed {
                        warn!("seems file is truncated, exiting");
                        break;
                    }
                    last_incomplete_offset = consumed;
                    // refill the buffer
                    let sz = f.read(b.space()).or(Err("unable to read data"))?;
                    b.fill(sz);
                    // println!("refill: {} more bytes, available data: {} bytes, consumed: {} bytes",
                    //          sz, b.available_data(), consumed);

                    // if there's no more available data in the buffer after a write, that means we reached
                    // the end of the file
                    if b.available_data() == 0 {
                        // println!("no more data to read or parse, stopping the reading loop");
                        break;
                    }
                }
            }
        }

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

        Ok(())
    }

    /// Dispatch function: given a packet, use link type to get the real data, and
    /// call the matching handling function (some pcap blocks encode ethernet, or IPv4 etc.)
    fn handle_packet(&mut self, packet: &pcap_parser::Packet, ctx: &ParseContext) {
        debug!("linktype: {}", ctx.link_type);
        match ctx.link_type {
            Linktype::NULL => {
                // XXX read first u32 in *host order*: 2 if IPv4, etc.
                self.handle_l3(&packet, &ctx, &packet.data[4..], EtherTypes::Ipv4); // XXX overflow
            }
            Linktype::RAW => {
                // XXX may be IPv4 or IPv6, check IP header ...
                self.handle_l3(&packet, &ctx, &packet.data, EtherTypes::Ipv4);
            }
            Linktype::ETHERNET => {
                self.handle_l2(&packet, &ctx);
            }
            Linktype(10) /* FDDI */ => {
                self.handle_l3(&packet, &ctx, &packet.data[21..], EtherTypes::Ipv4);
            }
            Linktype::NFLOG => {
                // first byte is family
                if packet.data.len() > 0 {
                    let af = packet.data[0];
                    let ethertype = match af {
                        2  => EtherTypes::Ipv4,
                        10 => EtherTypes::Ipv6,
                        af => {
                            warn!("NFLOG: unsupported address family {}", af);
                            EtherType::new(0)
                        }
                    };
                    let data = pcap_parser::data::get_data_nflog(&packet);
                    // XXX could not be IPv4. We should look at address family
                    self.handle_l3(&packet, &ctx, &data, ethertype);
                }
            }
            l => warn!("Unsupported link type {}", l)
        }
    }

    fn handle_l2(&mut self, packet: &pcap_parser::Packet, ctx: &ParseContext) {
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
                    return;
                }
                debug!("    ethertype: 0x{:x}", eth.get_ethertype().0);
                self.handle_l3(&packet, &ctx, eth.payload(), eth.get_ethertype());
            }
            None => {
                // packet too small to be ethernet
            }
        }
    }

    fn handle_l3(
        &mut self,
        packet: &pcap_parser::Packet,
        ctx: &ParseContext,
        data: &[u8],
        ethertype: EtherType,
    ) {
        if data.is_empty() {
            return;
        }

        match ethertype {
            EtherTypes::Ipv4 => {
                self.handle_l3_ipv4(packet, ctx, data, ethertype);
            }
            EtherTypes::Ipv6 => {
                self.handle_l3_ipv6(packet, ctx, data, ethertype);
            }
            EtherTypes::Vlan => {
                self.handle_l3_vlan_801q(packet, ctx, data, ethertype);
            }
            _ => {
                warn!("Unsupported ethertype {} (0x{:x})", ethertype, ethertype.0);
                self.handle_l3_generic(packet, ctx, data, ethertype);
            }
        }
    }

    fn handle_l3_ipv4(
        &mut self,
        packet: &pcap_parser::Packet,
        ctx: &ParseContext,
        data: &[u8],
        ethertype: EtherType,
    ) {
        debug!("handle_l3_ipv4 (idx={})", ctx.pcap_index);
        let ipv4 = match Ipv4Packet::new(data) {
            Some(ipv4) => ipv4,
            None => {
                warn!("Could not build IPv4 packet from data");
                return;
            }
        };

        // remove padding
        let (data,ipv4) = {
            if (ipv4.get_total_length() as usize) < data.len() {
                let d = &data[..ipv4.get_total_length() as usize];
                let ipv4 = match Ipv4Packet::new(d) {
                    Some(ipv4) => ipv4,
                    None => {
                        warn!("Could not build IPv4 packet from data");
                        return;
                    }
                };
                (d,ipv4)
            } else {
                (data,ipv4)
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
            ipv4.get_identification(),
            frag_offset,
            more_fragments,
            ipv4.payload(),
        );
        let data = match defrag {
            Fragment::NoFrag(d) => d,
            Fragment::Complete(ref v) => {
                warn!("Using defrag buffer len={}", v.len());
                &v
            }
            Fragment::Incomplete => {
                return;
            }
            Fragment::Error => {
                warn!("Defragmentation error");
                return;
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
    ) {
        debug!("handle_l3_ipv6 (idx={})", ctx.pcap_index);
        let ipv6 = match Ipv6Packet::new(data) {
            Some(ipv4) => ipv4,
            None => {
                warn!("Could not build IPv6 packet from data");
                return;
            }
        };
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
    ) {
        debug!("handle_l3_vlan_801q (idx={})", ctx.pcap_index);
        let vlan = match VlanPacket::new(data) {
            Some(vlan) => vlan,
            None => {
                warn!("Could not build 802.1Q Vlan packet from data");
                return;
            }
        };
        let next_ethertype = vlan.get_ethertype();

        self.handle_l3(&packet, &ctx, vlan.payload(), next_ethertype);
    }

    // Called when L3 layer is unknown
    fn handle_l3_generic(
        &mut self,
        packet: &pcap_parser::Packet,
        ctx: &ParseContext,
        data: &[u8],
        ethertype: EtherType,
    ) {
        debug!("handle_l3_generic (idx={})", ctx.pcap_index);
        // we don't know if there is padding to remove

        let t3 = ThreeTuple::default();

        // handle l3
        for p in self.plugins.storage.values_mut() {
            let _ = p.handle_l3(packet, data, ethertype.0, &t3);
        }

        // don't try to parse l4, we don't know how to get L4 data
    }

    fn handle_l4_tcp(
        &mut self,
        packet: &pcap_parser::Packet,
        ctx: &ParseContext,
        data: &[u8],
        l3_info: &L3Info,
    ) {
        debug!("handle_l4_tcp (idx={})", ctx.pcap_index);
        let l3_data = data;
        debug!("    l3_data len: {}", l3_data.len());
        let tcp = match TcpPacket::new(l3_data) {
            Some(tcp) => tcp,
            None => {
                warn!("Could not build TCP packet from data");
                return;
            }
        };

        // XXX handle TCP defrag
        let l4_data = Some(tcp.payload());
        let src_port = tcp.get_source();
        let dst_port = tcp.get_destination();

        self.handle_l4_common(packet, ctx, l3_data, l3_info, src_port, dst_port, l4_data);
    }

    fn handle_l4_udp(
        &mut self,
        packet: &pcap_parser::Packet,
        ctx: &ParseContext,
        data: &[u8],
        l3_info: &L3Info,
    ) {
        debug!("handle_l4_udp (idx={})", ctx.pcap_index);
        let l3_data = data;
        debug!("    l3_data len: {}", l3_data.len());
        let udp = match UdpPacket::new(l3_data) {
            Some(udp) => udp,
            None => {
                warn!("Could not build UDP packet from data");
                return;
            }
        };

        let l4_data = Some(udp.payload());
        let src_port = udp.get_source();
        let dst_port = udp.get_destination();

        self.handle_l4_common(packet, ctx, l3_data, l3_info, src_port, dst_port, l4_data);
    }

    fn handle_l4_icmp(
        &mut self,
        packet: &pcap_parser::Packet,
        ctx: &ParseContext,
        data: &[u8],
        l3_info: &L3Info,
    ) {
        debug!("handle_l4_icmp (idx={})", ctx.pcap_index);
        let l3_data = data;

        let icmp = match IcmpPacket::new(l3_data) {
            Some(icmp) => icmp,
            None => {
                warn!("Could not build ICMP packet from data");
                return;
            }
        };
        debug!(
            "ICMP type={:?} code={:?}",
            icmp.get_icmp_type(),
            icmp.get_icmp_code()
        );

        let l4_data = Some(icmp.payload());
        let src_port = 0;
        let dst_port = 0;

        self.handle_l4_common(packet, ctx, l3_data, l3_info, src_port, dst_port, l4_data);
    }

    fn handle_l4_icmpv6(
        &mut self,
        packet: &pcap_parser::Packet,
        ctx: &ParseContext,
        data: &[u8],
        l3_info: &L3Info,
    ) {
        debug!("handle_l4_icmpv6 (idx={})", ctx.pcap_index);
        let l3_data = data;

        let icmpv6 = match Icmpv6Packet::new(l3_data) {
            Some(icmp) => icmp,
            None => {
                warn!("Could not build ICMPv6 packet from data");
                return;
            }
        };
        debug!(
            "ICMPv6 type={:?} code={:?}",
            icmpv6.get_icmpv6_type(),
            icmpv6.get_icmpv6_code()
        );

        let l4_data = Some(icmpv6.payload());
        let src_port = 0;
        let dst_port = 0;

        self.handle_l4_common(packet, ctx, l3_data, l3_info, src_port, dst_port, l4_data);
    }

    fn handle_l4_gre(
        &mut self,
        packet: &pcap_parser::Packet,
        ctx: &ParseContext,
        data: &[u8],
        _l3_info: &L3Info,
    ) {
        debug!("handle_l4_gre (idx={})", ctx.pcap_index);
        let l3_data = data;

        let gre = match GrePacket::new(l3_data) {
            Some(gre) => gre,
            None => {
                warn!("Could not build GRE packet from data");
                return;
            }
        };

        let next_proto = gre.get_protocol_type();
        let data = gre.payload();

        self.handle_l3(packet, ctx, data, EtherType(next_proto));
    }

    fn handle_l4_generic(
        &mut self,
        packet: &pcap_parser::Packet,
        ctx: &ParseContext,
        data: &[u8],
        l3_info: &L3Info,
    ) {
        debug!(
            "handle_l4_generic (idx={}, l4_proto={})",
            ctx.pcap_index, l3_info.three_tuple.proto
        );
        let l3_data = data;
        // in generic function, we don't know how to get l4_data
        let l4_data = None;
        let src_port = 0;
        let dst_port = 0;

        self.handle_l4_common(packet, ctx, l3_data, l3_info, src_port, dst_port, l4_data);
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
    ) {
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
            .expect("could not get flow from ID");
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

fn pcap_get_raw_data<'a, 'ctx>(
    i: &'a [u8],
    _ctx: &'ctx mut ParseContext,
) -> IResult<&'a [u8], Option<pcap_parser::Packet<'a>>> {
    pcap::parse_pcap_frame(i).map(|(rem, p)| (rem, Some(p)))
}

fn pcapng_get_raw_data<'a, 'ctx>(
    i: &'a [u8],
    ctx: &'ctx mut ParseContext,
) -> IResult<&'a [u8], Option<pcap_parser::Packet<'a>>> {
    pcapng::parse_block(i).map(|(rem, block)| {
        match block {
            Block::SectionHeader(ref _hdr) => {
                warn!("new section header block");
                (rem, None)
            }
            Block::InterfaceDescription(ref ifdesc) => {
                ctx.if_info = pcapng_build_interface(ifdesc);
                ctx.link_type = ctx.if_info.link_type;
                // XXX parse_data = get_linktype_parse_fn(if_info.link_type).ok_or("could not find function to decode linktype")?;
                (rem, None)
            }
            Block::SimplePacket(_) | Block::EnhancedPacket(_) => {
                let packet = pcapng_build_packet(&ctx.if_info, block)
                    .expect("could not convert block to packet"); // XXX
                (rem, Some(packet))
            }
            _ => (rem, None),
        }
    })
}
