use std::net::IpAddr;
use std::io::Read;
use std::cmp::min;

use std::collections::HashMap;

use rand::prelude::*;

use circular::Buffer;
use nom::HexDisplay;
use nom::{Needed,Offset,IResult};

use pnet::packet::Packet;
use pnet::packet::ethernet::{EthernetPacket,EtherType,EtherTypes};
use pnet::packet::ipv4::{Ipv4Packet,Ipv4Flags};
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::ip::{IpNextHeaderProtocol,IpNextHeaderProtocols};

use pcap_parser::*;

use crate::pcapng_extra::{InterfaceInfo,pcapng_build_interface,pcapng_build_packet};

use crate::five_tuple::FiveTuple;
use crate::flow::{Flow,FlowID};
use crate::packet_data::PacketData;

use crate::plugins::Plugins;

use crate::duration::Duration;

enum PcapType {
    // Unknown,
    Pcap,
    PcapNG
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

    // XXX we need to store all fragments, with offsets
    ipv4_fragments: HashMap<u16,Vec<u8>>,
}


impl<'a> Analyzer<'a> {
    pub fn new(plugins: &mut Plugins) -> Analyzer {
        Analyzer{
            flows: HashMap::new(),
            flows_id: HashMap::new(),
            plugins,
            trng: rand::thread_rng(),
            ipv4_fragments: HashMap::new(),
        }
    }

    /// Main function: for a reader, read all pcap data and run all plugins
    pub fn run<R: Read>(&mut self, f: &mut R) -> Result<(), &'static str> {
        let mut capacity = 16384 * 8;
        let buffer_max_size = 65536 * 8;
        let mut b = Buffer::with_capacity(capacity);
        let sz = f.read(b.space()).or(Err("unable to read data"))?;
        b.fill(sz);

        let mut context = ParseContext{
            if_info: InterfaceInfo::new(),
            link_type: Linktype(0),
            pcap_index: 1,
            first_packet_ts: Duration::new(0,0),
            rel_ts: Duration::new(0,0),
        };

        let (length,in_pcap_type) = {
            if let Ok((remaining,_h)) = pcapng::parse_sectionheaderblock(b.data()) {
                (b.data().offset(remaining), PcapType::PcapNG)
            } else if let Ok((remaining,h)) = pcap::parse_pcap_header(b.data()) {
                context.link_type = Linktype(h.network);
                (b.data().offset(remaining), PcapType::Pcap)
            } else {
                return Err("couldn't parse input file header")
            }
        };

        // println!("consumed {} bytes", length);
        b.consume(length);

        let mut consumed = length;
        let mut last_incomplete_offset = 0;

        self.plugins.list.values_mut().for_each(|plugin| plugin.pre_process());

        let get_next_packet = match in_pcap_type {
            PcapType::Pcap   => pcap_get_raw_data,
            PcapType::PcapNG => pcapng_get_raw_data,
        };

        loop {
            let needed: Option<Needed>;

            // println!("{}", (&b.data()[..min(b.available_data(), 128)]).to_hex(16));

            loop {
                let length = {
                    // read block
                    match get_next_packet(b.data(), &mut context) {
                        Ok((remaining,opt_packet)) => {
                            // eprintln!("parse_block ok, index {}", pcap_index);
                            // println!("parsed packet: {:?}", packet);

                            if let Some(packet) = opt_packet {
                                debug!("**************************************************************");
                                if context.pcap_index == 1 {
                                    context.first_packet_ts = Duration::new(packet.header.ts_sec, packet.header.ts_usec);
                                }
                                debug!("    time  : {} / {}", packet.header.ts_sec, packet.header.ts_usec);
                                let ts = Duration::new(packet.header.ts_sec, packet.header.ts_usec);
                                context.rel_ts = ts - context.first_packet_ts; // an underflow is weird but not critical
                                debug!("    reltime  : {}.{}", context.rel_ts.secs, context.rel_ts.micros);
                                self.handle_packet(&packet, &context);
                                context.pcap_index += 1;
                            }

                            b.data().offset(remaining)
                        },
                        Err(nom::Err::Incomplete(n)) => {
                            // println!("not enough data, needs a refill: {:?}", n);

                            needed = Some(n);
                            break;
                        },
                        Err(nom::Err::Failure(e)) => {
                            eprintln!("parse failure: {:?}", e);
                            return Err("parse error");
                        },
                        Err(nom::Err::Error(_e)) => {
                            // panic!("parse error: {:?}", e);
                            eprintln!("parse error");
                            eprintln!("{}", (&b.data()[..min(b.available_data(), 128)]).to_hex(16));
                            return Err("parse error");
                        },
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
                        warn!("requesting capacity {} over buffer_max_size {}", capacity, buffer_max_size);
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
            for p in self.plugins.list.values_mut() {
                p.flow_terminate(&f);
            }
        }
        self.flows.clear();
        self.flows_id.clear();

        self.plugins.list.values_mut().for_each(|plugin| plugin.post_process());

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
        info!("handle_l2");

        // resize slice to remove padding
        let datalen = min(packet.header.caplen as usize, packet.data.len());
        let data = &packet.data[..datalen];

        let eth = EthernetPacket::new(data).expect("ethernet");

        debug!("    ethertype: {}", eth.get_ethertype().0);
        // debug!("    source: {}", eth.get_source());
        // debug!("    dest  : {}", eth.get_destination());

        for p in self.plugins.list.values_mut() {
            let _ = p.handle_l2(&data);
        }

        if packet.data.len() > 14 {
            self.handle_l3(&packet, &ctx, &data[14..], eth.get_ethertype());
        } // else XXX
    }

    fn handle_l3(&mut self, packet: &pcap_parser::Packet, ctx: &ParseContext, data: &[u8], ethertype: EtherType) {
        info!("handle_l3 (idx={})", ctx.pcap_index);
        if data.is_empty() { return; }

        // remove padding
        let data = match ethertype {
            EtherTypes::Ipv4 => {
                let ipv4 = &Ipv4Packet::new(data).expect("IPv4"); // XXX
                if (ipv4.get_total_length() as usize) < data.len() {
                    &data[..ipv4.get_total_length() as usize]
                } else {
                    data
                }
            }
            _ => data
        };

        // handle l3
        for p in self.plugins.list.values_mut() {
            let _ = p.handle_l3(data, ethertype.0);
        }

        // check IP fragmentation before calling handle_l4
        let maybe_ipv4 = &Ipv4Packet::new(data);
        let mut keep_f = Vec::new();
        let (frag,data) = match ethertype {
            EtherTypes::Ipv4 => {
                let ipv4 = maybe_ipv4.as_ref().expect("ipv4");
                let id = ipv4.get_identification();
                if ipv4.get_flags() & Ipv4Flags::MoreFragments != 0 {
                    debug!("more fragments {}", id);
                    if ipv4.get_fragment_offset() == 0 {
                        // first fragment
                        debug!("first fragment");
                        let v = data.to_vec();
                        warn!("inserting defrag buffer key={} len={}", id, data.len());
                        // insert ipv4 *data* but keep ipv4 header for the first packet
                        self.ipv4_fragments.insert(id, v);
                    } else {
                        match self.ipv4_fragments.get_mut(&id) {
                            Some(f) => f.extend_from_slice(ipv4.payload()),
                            None    => warn!("could not get first fragment buffer for ID {}", id),
                        }
                    }
                    (1,data)
                } else {
                    // last fragment
                    if ipv4.get_fragment_offset() > 0 {
                        debug!("last fragment {}", id);
                        match self.ipv4_fragments.remove(&id) {
                            Some(f) => {
                                keep_f = f;
                                keep_f.extend_from_slice(ipv4.payload());
                                warn!("extracting defrag buffer id={} len={}", id, keep_f.len());
                                (2,data)
                            },
                            None    => { warn!("could not get first fragment buffer for ID {}", id); (1,data) },
                        }
                    } else {
                        (0,data)
                    }
                }
            }
            _ => (0,data)
        };
        let data = match frag {
            0 => data, // no fragmentation
            1 => { return; } // partial data
            _ => {
                warn!("Using defrag buffer len={}", keep_f.len());
                &keep_f
            }
        };
        self.handle_l4(packet, ctx, data, ethertype)
    }

    fn handle_l4(&mut self, _packet: &pcap_parser::Packet, ctx: &ParseContext, data: &[u8], ethertype: EtherType) {
        info!("handle_l4 (idx={})", ctx.pcap_index);
        let mut l3_data_offset = 0;
        let mut l4_proto = IpNextHeaderProtocol(0);

        // build 5-tuple and store offsets for data layers
        let five_tuple = {
            let mut five_tuple = FiveTuple::default();
            match ethertype {
                EtherTypes::Ipv4 => {
                    let ipv4 = &Ipv4Packet::new(data).expect("IPv4"); // XXX
                    l3_data_offset = data.offset(ipv4.payload());
                    // debug!("next level proto: {:?}", ipv4.get_next_level_protocol());
                    five_tuple.src = IpAddr::V4(ipv4.get_source());
                    five_tuple.dst = IpAddr::V4(ipv4.get_destination());
                    l4_proto = ipv4.get_next_level_protocol();
                    five_tuple.proto = l4_proto.0;
                    match l4_proto {
                        IpNextHeaderProtocols::Tcp => {
                            if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                                five_tuple.src_port = tcp.get_source();
                                five_tuple.dst_port = tcp.get_destination();
                                // parse_tcp(src, dst, &tcp, ptype, globalstate);
                            }
                        }
                        IpNextHeaderProtocols::Udp => {
                            if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                                five_tuple.src_port = udp.get_source();
                                five_tuple.dst_port = udp.get_destination();
                                // parse_tcp(src, dst, &tcp, ptype, globalstate);
                            }
                        }
                        // protocols without port numbers
                        IpNextHeaderProtocols::Icmp |
                        IpNextHeaderProtocols::Esp => {
                        }
                        p => {
                            warn!("Unknown L3 protocol (IPv4) {:?}", p);
                        }
                    }
                }
                EtherTypes::Ipv6 => {
                    let ipv6 = &Ipv6Packet::new(data).expect("IPv6"); // XXX
                    l3_data_offset = data.offset(ipv6.payload());
                    debug!("next level proto: {:?}", ipv6.get_next_header());
                    five_tuple.src = IpAddr::V6(ipv6.get_source());
                    five_tuple.dst = IpAddr::V6(ipv6.get_destination());
                    l4_proto = ipv6.get_next_header();
                    five_tuple.proto = l4_proto.0;
                    match l4_proto {
                        IpNextHeaderProtocols::Tcp => {
                            if let Some(tcp) = TcpPacket::new(ipv6.payload()) {
                                five_tuple.src_port = tcp.get_source();
                                five_tuple.dst_port = tcp.get_destination();
                                // parse_tcp(src, dst, &tcp, ptype, globalstate);
                            }
                        }
                        IpNextHeaderProtocols::Udp => {
                            if let Some(udp) = UdpPacket::new(ipv6.payload()) {
                                five_tuple.src_port = udp.get_source();
                                five_tuple.dst_port = udp.get_destination();
                                // parse_tcp(src, dst, &tcp, ptype, globalstate);
                            }
                        }
                        // protocols without port numbers
                        IpNextHeaderProtocols::Icmp |
                        IpNextHeaderProtocols::Esp => {
                        }
                        p => {
                            warn!("Unknown L3 protocol (IPv6) {:?}", p);
                        }
                    }
                }
                x => {
                    warn!("warning: unknown L2 type {}", x);
                }
            }
            five_tuple
        };

        debug!("5t: {:?}", five_tuple);

        // lookup flow
        let flow_id = match self.lookup_flow(&five_tuple) {
            Some(id) => id,
            None     => {
                let flow = Flow::from(&five_tuple);
                self.insert_flow(five_tuple.clone(), flow)
            }
        };

        // take flow ownership
        let flow = self.flows.get_mut(&flow_id).expect("could not get flow from ID");
        flow.flow_id = flow_id;

        let to_server = flow.five_tuple == five_tuple;

        // get L4 data
        // XXX handle TCP defrag
        debug!("    l3_data_offset: {}", l3_data_offset);
        if l3_data_offset == 0 {
            debug!("no data in l3 layer, so no trying to handle l4");
            return;
        }
        let l3_data = &data[l3_data_offset..];
        let l4_data = match l4_proto {
            IpNextHeaderProtocols::Tcp => {
                // header length depends on options
                TcpPacket::new(&l3_data).and_then(|p| {
                    let offset = p.get_data_offset() as usize * 4;
                    if offset < l3_data.len() {
                        Some(&l3_data[offset..])
                    } else {
                        None
                    }
                })
            },
            IpNextHeaderProtocols::Udp => {
                // fixed length header
                if l3_data.len() > 8 {
                    Some(&l3_data[8..])
                } else {
                    None
                }
            },
            IpNextHeaderProtocols::Esp => {
                Some(data) // no header
            },
            _ => None
        };
        // handle L4
        debug!("    l3_data len: {}", l3_data.len());
        debug!("    l4_proto: {}", l4_proto);
        let pdata = PacketData{
            five_tuple: &five_tuple,
            to_server,
            l3_type: ethertype.0,
            l3_data,
            l4_type: l4_proto.0,
            l4_data,
            flow: Some(flow),
        };
        for p in self.plugins.list.values_mut() {
            let _ = p.handle_l4(&pdata);
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
            _ => ()
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

fn pcap_get_raw_data<'a,'ctx>(i:&'a[u8], _ctx:&'ctx mut ParseContext) -> IResult<&'a [u8],Option<pcap_parser::Packet<'a>>> {
    pcap::parse_pcap_frame(i).map(|(rem,p)| (rem,Some(p)))
}

fn pcapng_get_raw_data<'a,'ctx>(i:&'a[u8], ctx:&'ctx mut ParseContext) -> IResult<&'a [u8],Option<pcap_parser::Packet<'a>>> {
    pcapng::parse_block(i).map(|(rem,block)| {
        match block {
            Block::SectionHeader(ref _hdr) => {
                warn!("new section header block");
                (rem,None)
            },
            Block::InterfaceDescription(ref ifdesc) => {
                ctx.if_info = pcapng_build_interface(ifdesc);
                ctx.link_type = ctx.if_info.link_type;
                // XXX parse_data = get_linktype_parse_fn(if_info.link_type).ok_or("could not find function to decode linktype")?;
                (rem,None)
            },
            Block::SimplePacket(_) |
            Block::EnhancedPacket(_) => {
                let packet = pcapng_build_packet(&ctx.if_info, block).expect("could not convert block to packet"); // XXX
                (rem,Some(packet))
            },
            _ => (rem,None),
        }
    })
}
