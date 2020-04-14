use crate::packet_info::PacketInfo;
use crate::plugin::{Plugin, PluginResult, PLUGIN_L4};
use crate::{output, plugin_builder};
use libpcap_tools::{FiveTuple, Packet};
use rusticata::*;
use serde_json::{self, json};
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
    output_dir: String,
    tls_conversations: HashMap<FiveTuple, Stats<'a>>,
}

// plugin_builder!(TlsStats, TlsStatsBuilder);
plugin_builder!(TlsStats, TlsStatsBuilder, |config| {
    let output_dir = output::get_output_dir(config).to_owned();
    TlsStats {
        output_dir,
        tls_conversations: HashMap::default(),
    }
});

impl<'a> Plugin for TlsStats<'a> {
    fn name(&self) -> &'static str {
        "TlsStats"
    }
    fn plugin_type(&self) -> u16 {
        PLUGIN_L4
    }
    fn handle_layer_transport<'s, 'i>(
        &'s mut self,
        _packet: &'s Packet,
        pinfo: &PacketInfo,
    ) -> PluginResult<'i> {
        let data = match pinfo.l4_payload {
            Some(data) => data,
            None => return PluginResult::None,
        };
        let flow = match pinfo.flow {
            Some(flow) => flow,
            None => return PluginResult::None,
        };
        // test if pinfo.five_tuple is in self.tls_conversations
        if let Some(stats) = self.tls_conversations.get_mut(&flow.five_tuple) {
            stats.update(data, pinfo);
        } else {
            // if not, try to detect TLS
            if !tls_probe(data) {
                return PluginResult::None;
            }
            // could be TLS. instanciate parser and add flow to tracked conversations
            let mut stats = Stats::new();
            stats.update(data, pinfo);
            self.tls_conversations
                .insert(flow.five_tuple.clone(), stats);
        }
        PluginResult::None
    }
    fn post_process(&mut self) {
        self.to_json();
    }
}

impl<'a> TlsStats<'a> {
    fn to_json(&self) {
        //
        // SSL/TLS conversations
        let conversations: Vec<_> = self
            .tls_conversations
            .iter()
            .map(|(t5, stats)| {
                let mut js = json!({
                    "five-tuple": t5,
                    "client_version": format!("{:?}", stats.parser.client_version),
                    "cipher": stats.parser.cipher.map(|c| c.name).unwrap_or(""),
                });
                if let Some(o) = js.as_object_mut() {
                    if let Some(ja3) = &stats.parser.ja3 {
                        o.insert("ja3".to_owned(), json!(ja3));
                    }
                    if let Some(alert) = &stats.parser.fatal_alert {
                        o.insert("alert".to_owned(), json!(alert.to_string()));
                    }
                }
                js
            })
            .collect();
        let json_ar = json!(conversations);
        let file = output::create_file(&self.output_dir, "tls-stats-conversations.json").expect("Cannot create output file");
        serde_json::to_writer(file, &json_ar).unwrap();
        //
        // SSL/TLS ports
        let mut m = HashMap::new();
        for t5 in self.tls_conversations.keys() {
            let count_ref = m.entry(t5.dst_port).or_insert(0);
            *count_ref += 1;
        }
        let js = json!(m);
        let file = output::create_file(&self.output_dir, "tls-stats-tls-ports.json").expect("Cannot create output file");
        serde_json::to_writer(file, &js).unwrap();
        //
        // SSL record version
        let mut m = HashMap::new();
        for stats in self.tls_conversations.values() {
            let count_ref = m.entry(stats.parser.ssl_record_version.0).or_insert(0);
            *count_ref += 1;
        }
        let m2 : HashMap<_, _> = m.iter().map(|(k,v)| {
            (TlsVersion(*k).to_string(), v)
        }).collect();
        let js = json!(m2);
        let file = output::create_file(&self.output_dir, "tls-stats-ssl-record-version.json").expect("Cannot create output file");
        serde_json::to_writer(file, &js).unwrap();
        //
        // Client-Hello version
        let mut m = HashMap::new();
        for stats in self.tls_conversations.values() {
            let count_ref = m.entry(stats.parser.client_version.0).or_insert(0);
            *count_ref += 1;
        }
        let m2 : HashMap<_, _> = m.iter().map(|(k,v)| {
            (TlsVersion(*k).to_string(), v)
        }).collect();
        let js = json!(m2);
        let file = output::create_file(&self.output_dir, "tls-stats-client-hello-version.json").expect("Cannot create output file");
        serde_json::to_writer(file, &js).unwrap();
        //
        // Ciphers
        let mut m = HashMap::new();
        for stats in self.tls_conversations.values() {
            let cipher = match stats.parser.cipher {
                Some(ciphersuite) => ciphersuite.name,
                None => "<None>",
            };
            let count_ref = m.entry(cipher).or_insert(0);
            *count_ref += 1;
        }
        let js = json!(m);
        let file = output::create_file(&self.output_dir, "tls-stats-ciphers.json").expect("Cannot create output file");
        serde_json::to_writer(file, &js).unwrap();
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
