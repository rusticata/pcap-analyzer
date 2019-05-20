use pcap_parser::Packet;

use super::Plugin;
use crate::default_plugin_builder;
use crate::packet_data::PacketData;
use crate::plugin::{PLUGIN_FLOW_DEL, PLUGIN_L4};
use libpcap_tools::{FlowID,Flow};

use std::collections::HashMap;

use pnet_packet::tcp::TcpPacket;
use pnet_packet::tcp::TcpFlags;

const TH_SYN_ACK     : u16 = 0x12;
const TH_SYN_FIN_RST : u16 = 0x07;
const TH_ARSF        : u16 = 0x17;

#[derive(Debug)]
enum TcpState {
    New,
    Established,
    Closing,
    Closed,
    Reset,
    // Bogus
}

impl Default for TcpState {
    fn default() -> TcpState { TcpState::New }
}

#[derive(Default)]
struct TcpContext {
    syn_seen: bool,
    fin_seen: bool,
    /// Seq value during SYN
    syn_seq: u32,
    last_seq: u32,
    last_ack: u32,
    next_seq: u32,
    state: TcpState,
}

#[derive(Default)]
pub struct TcpStates {
    /// Client and Server states, indexed by flow ID
    ctx_map: HashMap<FlowID,(TcpContext,TcpContext)>,
}

default_plugin_builder!(TcpStates, TcpStatesBuilder);

impl Plugin for TcpStates {
    fn name(&self) -> &'static str { "TcpStates" }
    fn plugin_type(&self) -> u16 { PLUGIN_FLOW_DEL|PLUGIN_L4 }

    fn handle_l4(&mut self, _packet:&Packet, pdata: &PacketData) {
        debug!("proto {}", pdata.five_tuple.proto);

        if pdata.l4_type != 6 { return; }

        let flow = match pdata.flow {
            Some(f) => f,
            None    => {
                warn!("TCP pdata without flow!");
                return;
            }
        };

        let e = self.ctx_map.entry(flow.flow_id).or_default();

        let tcp = TcpPacket::new(pdata.l3_data).expect("TcpPacket");
        let tcp_flags = tcp.get_flags();
        let seq = tcp.get_sequence();
        let ack = tcp.get_acknowledgement();
        debug!("flow id {}", flow.flow_id);
        debug!("    Tcp flags: 0x{:x}", tcp_flags);
        debug!("    Tcp seq 0x{:x}", seq);
        debug!("    Tcp ack 0x{:x}", ack);
        debug!("    Tcp state(before) direct {:?} / rev {:?}", e.0.state, e.1.state);

        // XXX store tcp state, last seq & ack values for client and server, key flowid

        let (mut conn, mut rev_conn) = if pdata.to_server {
            (&mut e.0, &mut e.1)
        } else {
            (&mut e.1, &mut e.0)
        };
        debug!("    Tcp rel seq {}", seq.wrapping_sub(conn.syn_seq));
        debug!("    Tcp rel ack {}", ack.wrapping_sub(rev_conn.syn_seq));
        let mut tcp_flags_s = Vec::new();
        if tcp_flags & TcpFlags::FIN != 0 { tcp_flags_s.push("FIN"); }
        if tcp_flags & TcpFlags::SYN != 0 { tcp_flags_s.push("SYN"); }
        if tcp_flags & TcpFlags::RST != 0 { tcp_flags_s.push("RST"); }
        if tcp_flags & TcpFlags::PSH != 0 { tcp_flags_s.push("PSH"); }
        if tcp_flags & TcpFlags::ACK != 0 { tcp_flags_s.push("ACK"); }
        if tcp_flags & TcpFlags::URG != 0 { tcp_flags_s.push("URG"); }
        if tcp_flags & TcpFlags::ECE != 0 { tcp_flags_s.push("ECE"); }
        if tcp_flags & TcpFlags::CWR != 0 { tcp_flags_s.push("CWR"); }
        debug!("    Tcp flags: [{}]", tcp_flags_s.join(" "));
        match conn.state {
            TcpState::New => {
                // SYN
                if tcp_flags & TH_SYN_FIN_RST == TcpFlags::SYN {
debug!("SYN");
                    conn.syn_seen = true;
                    conn.syn_seq = seq;
                    // SYN-ACK
                    if tcp_flags & TcpFlags::ACK == TcpFlags::ACK {
                        if pdata.to_server {
                            warn!("NEW/SYN-ACK in direct flow. Missed SYN ?");
                            return;
                        }
                        // check ack value
                        if ack != rev_conn.syn_seq + 1 {
                            warn!("NEW/SYN-ACK: ack number is wrong");
                            return;
                        }
                    }
                }
                // ACK as last part of 3-way handshake
                if rev_conn.syn_seen && tcp_flags & TH_ARSF == TcpFlags::ACK {
                    // check ack value
                    if ack != rev_conn.syn_seq + 1 {
                        warn!("NEW/ACK: ack number is wrong");
                        return;
                    }
                    // connection established
                    conn.state = TcpState::Established;
                    conn.last_seq = seq;
                    conn.last_ack = ack;
                    conn.next_seq = seq;
                    rev_conn.state = TcpState::Established;
                    rev_conn.last_seq = ack;
                    rev_conn.last_ack = seq;
                    rev_conn.next_seq = ack;
                }
                // XXX missing: RST-ACK, etc.
            },
            TcpState::Established => {
                // all packets should be ACKed
                if tcp_flags & TH_SYN_ACK != TcpFlags::ACK {
                    warn!("EST/ packet without ACK");
                }
                // sender initiates a teardown
                if tcp_flags & TcpFlags::FIN == TcpFlags::FIN {
                    conn.fin_seen = true;
                    conn.next_seq += 1; // receiver needs to ack FIN
                    conn.state = TcpState::Closing;
                }
                // Connection has been reset
                if tcp_flags & TcpFlags::RST == TcpFlags::RST {
                    conn.state = TcpState::Reset;
                    rev_conn.state = TcpState::Reset;
                }
                // check ack number
                if ack > rev_conn.next_seq {
                    warn!("EST/data: ack number is wrong (missed packet?)");
                    warn!("  expected ack 0x{:x}", rev_conn.next_seq);
                    warn!("  got ack 0x{:x}", ack);
                }
                // XXX debug
                if ack < rev_conn.next_seq {
                    debug!("TCP: partially ACKed data (expecting up to ACK {})", rev_conn.next_seq.wrapping_sub(rev_conn.syn_seq));
                }
                // XXX end debug
                // if pdata.to_server {
                    conn.next_seq += pdata.l4_data.map(|d| d.len() as u32).unwrap_or(0);
                // } else {
                //     rev_conn.next_ack += pdata.l4_data.map(|d| d.len() as u32).unwrap_or(0);
                // }
                debug!("    Tcp next ack 0x{:x}", conn.next_seq);
                debug!("    Tcp next rel seq {}", conn.next_seq.wrapping_sub(conn.syn_seq));
            },
            TcpState::Closing => {
                // Connection has been reset
                if tcp_flags & TcpFlags::RST == TcpFlags::RST {
                    conn.state = TcpState::Reset;
                    rev_conn.state = TcpState::Reset;
                }
                // Test if teardown is complete
                if conn.fin_seen && rev_conn.fin_seen {
                    conn.state = TcpState::Closed;
                    rev_conn.state = TcpState::Closed;
                }
            }
            TcpState::Closed => {
                // Connection has been reset
                if tcp_flags & TcpFlags::RST == TcpFlags::RST {
                    conn.state = TcpState::Reset;
                    rev_conn.state = TcpState::Reset;
                }
            }
            TcpState::Reset => {
            }
            // _ => {
            //     warn!("Bogus state");
            // }
        }
        debug!("    Tcp state(after) direct {:?} / rev {:?}", e.0.state, e.1.state);
    }

    fn flow_destroyed(&mut self, flow: &Flow) {
        debug!("flow_destroyed id={}", flow.flow_id);
        self.ctx_map.remove(&flow.flow_id);
    }

    fn post_process(&mut self) {
    }
}
