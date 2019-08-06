use crate::packet_info::PacketInfo;
use crate::plugin::PLUGIN_L4;
use crate::{default_plugin_builder, Plugin};
use libpcap_tools::{FiveTuple, Packet};
use rusticata::*;
use std::collections::HashMap;
use tls_parser::TlsVersion;

struct Stats<'a> {
    parser: TlsParser<'a>,
    bypass: bool,
}

/// Display statistics on SSL/TLS connections
///
/// Note: Empty fields (version, cipher, etc.) means that the connection is either
/// incomplete (alert during handshake) or that the handshake was not seen.
#[derive(Default)]
pub struct TlsStats<'a> {
    tls_conversations: HashMap<FiveTuple, Stats<'a>>,
}

default_plugin_builder!(TlsStats, TlsStatsBuilder);

impl<'a> Plugin for TlsStats<'a> {
    fn name(&self) -> &'static str {
        "TlsStats"
    }
    fn plugin_type(&self) -> u16 {
        PLUGIN_L4
    }
    fn handle_l4(&mut self, _packet: &Packet, pdata: &PacketInfo) {
        let data = match pdata.l4_payload {
            Some(data) => data,
            None => return,
        };
        let flow = match pdata.flow {
            Some(flow) => flow,
            None => return,
        };
        // test if pdata.five_tuple is in self.tls_conversations
        if let Some(stats) = self.tls_conversations.get_mut(&flow.five_tuple) {
            stats.update(data, pdata);
        } else {
            // if not, try to detect TLS
            if !tls_probe(data) {
                return;
            }
            // could be TLS. instanciate parser and add flow to tracked conversations
            let mut stats = Stats::new();
            stats.update(data, pdata);
            self.tls_conversations
                .insert(flow.five_tuple.clone(), stats);
        }
    }
    fn post_process(&mut self) {
        info!("");
        info!("TLS conversations:");
        for (t5, stats) in self.tls_conversations.iter() {
            info!(
                "  {}: client_version: {:?} cipher {:?} alert {:?}",
                t5, stats.parser.client_version, stats.parser.cipher, stats.parser.fatal_alert
            );
        }
        //
        info!("");
        info!("| SSL/TLS ports | Count   |");
        info!("---------------------------");
        let mut m = HashMap::new();
        for t5 in self.tls_conversations.keys() {
            let count_ref = m.entry(t5.dst_port).or_insert(0);
            *count_ref += 1;
        }
        for (version, count) in m.iter() {
            info!("| {0: <13} | {1: <7} |", version, count);
        }
        info!("---------------------------");
        //
        info!("");
        info!("| SSL record version   | Count   |");
        info!("----------------------------------");
        let mut m = HashMap::new();
        for stats in self.tls_conversations.values() {
            let count_ref = m.entry(stats.parser.ssl_record_version.0).or_insert(0);
            *count_ref += 1;
        }
        for (version, count) in m.iter() {
            info!(
                "| {0: <20} | {1: <7} |",
                format!("{}", TlsVersion(*version)),
                count
            );
        }
        info!("----------------------------------");
        //
        info!("");
        info!("| Client-Hello version | Count   |");
        info!("----------------------------------");
        let mut m = HashMap::new();
        for stats in self.tls_conversations.values() {
            let count_ref = m.entry(stats.parser.client_version.0).or_insert(0);
            *count_ref += 1;
        }
        for (version, count) in m.iter() {
            info!(
                "| {0: <20} | {1: <7} |",
                format!("{}", TlsVersion(*version)),
                count
            );
        }
        info!("----------------------------------");
        //
        info!("");
        info!("| Ciphers                        | Count   |");
        info!("--------------------------------------------");
        let mut m = HashMap::new();
        for stats in self.tls_conversations.values() {
            let cipher = match stats.parser.cipher {
                Some(ciphersuite) => ciphersuite.name,
                None => "<None>",
            };
            let count_ref = m.entry(cipher).or_insert(0);
            *count_ref += 1;
        }
        for (name, count) in m.iter() {
            info!("| {0: <30} | {1: <7} |", format!("{}", name), count);
        }
        info!("--------------------------------------------");
    }
}

impl<'a> Stats<'a> {
    fn new() -> Stats<'a> {
        let parser = TlsParser::new(b"tls-stats");
        Stats {
            parser,
            bypass: false,
        }
    }

    fn update(&mut self, data: &[u8], pdata: &PacketInfo) {
        if self.bypass {
            return;
        }
        let direction = if pdata.to_server {
            STREAM_TOSERVER
        } else {
            STREAM_TOCLIENT
        };
        // XXX parse only handshake messages ? we can't filter 0x16 (because fragmentation)
        let status = self.parser.parse_tcp_level(data, direction);
        if status & R_STATUS_EVENTS != 0 {
            // XXX ignore events for now
            self.parser.events.clear();
        }
        if status & R_STATUS_FAIL != 0 {
            // error, stop parsing of future packets
            debug!(
                "error while parsing tls (idx={}). Activating bypass for future packets {}",
                pdata.pcap_index, pdata.five_tuple
            );
            self.bypass = true;
            return;
        }
    }
}
