use super::{Plugin,PluginBuilder};
use crate::default_plugin_builder;
use crate::packet_data::PacketData;

use pnet::packet::tcp::TcpPacket;
use pnet::packet::tcp::TcpFlags;

#[derive(Default)]
struct TcpState {
    first_seq: u32,
    last_seq: u32,
    last_ack: u32,
}

#[derive(Default)]
pub struct TcpStates {
    // XXX will be a map indexed by flow_id
    client_state: TcpState,
}

default_plugin_builder!(TcpStates, TcpStatesBuilder);

impl Plugin for TcpStates {
    fn name(&self) -> &'static str { "TcpStates" }

    fn handle_l4(&mut self, packet: &PacketData) {
        debug!("proto {}", packet.five_tuple.proto);

        if packet.l4_type != 6 { return; }

        let flow = match packet.flow {
            Some(f) => f,
            None    => {
                warn!("TCP packet without flow!");
                return;
            }
        };

        let tcp = TcpPacket::new(packet.l3_data).expect("TcpPacket");
        let tcp_flags = tcp.get_flags();
        let seq = tcp.get_sequence();
        let ack = tcp.get_acknowledgement();
        debug!("flow id {}", flow.flow_id);
        debug!("    Tcp flags: 0x{:x}", tcp_flags);
        debug!("    Tcp seq 0x{:x}", seq);
        debug!("    Tcp ack 0x{:x}", ack);

        // XXX store tcp state, last seq & ack values for client and server, key flowid

        if tcp_flags == TcpFlags::SYN { // only SYN
            warn!("SYN");
            self.client_state = TcpState{
                first_seq: seq,
                last_seq: seq,
                last_ack: 0,
            };
        }
        if ! packet.to_server {
            if tcp_flags == (TcpFlags::SYN | TcpFlags::ACK) {
                debug!("server SYN+ACK");
                debug!("    ack {} / expected ack {}", ack, self.client_state.last_seq + 1);
            }
        }
        let _ = self.client_state.first_seq;
        let _ = self.client_state.last_ack;
    }

    fn post_process(&mut self) {
    }
}

