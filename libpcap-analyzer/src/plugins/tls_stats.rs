use crate::packet_info::PacketInfo;
use crate::plugin::{Plugin, PluginResult, PLUGIN_L4};
use crate::{output, plugin_builder};
use libpcap_tools::{FiveTuple, Packet};
use rusticata::tls::*;
use rusticata::*;
use serde_json::{self, json, Value};
use std::any::Any;
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

// plugin_builder!(TlsStats, TlsStatsBuilder);
plugin_builder!(TlsStats, TlsStatsBuilder);

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
            let l4_info = rusticata::probe::L4Info {
                src_port: pinfo.five_tuple.src_port,
                dst_port: pinfo.five_tuple.dst_port,
                l4_proto: pinfo.l4_type,
            };
            // if not, try to detect TLS
            if !tls_probe(data, &l4_info).is_certain() {
                return PluginResult::None;
            }
            // could be TLS. instantiate parser and add flow to tracked conversations
            let mut stats = Stats::new();
            stats.update(data, pinfo);
            self.tls_conversations
                .insert(flow.five_tuple.clone(), stats);
        }
        PluginResult::None
    }

    fn get_results(&mut self) -> Option<Box<dyn Any>> {
        let v = self.get_results_json();
        Some(Box::new(v))
    }

    fn save_results(&mut self, path: &str) -> Result<(), &'static str> {
        let results = self.get_results_json();
        // save data to file
        for (name, stats) in results.as_object().unwrap() {
            let filename = format!("{}.json", name);
            let file = output::create_file(path, &filename)
                .or(Err("Cannot create output file"))?;
            serde_json::to_writer(file, stats).or(Err("Cannot save results to file"))?;
        }
        Ok(())
    }
}

impl<'a> TlsStats<'a> {
    fn get_results_json(&mut self) -> Value {
        let mut map = serde_json::Map::new();
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
        map.insert("tls-stats-conversations".into(), json!(conversations));
        //
        // SSL/TLS ports
        let mut m = HashMap::new();
        for t5 in self.tls_conversations.keys() {
            let count_ref = m.entry(t5.dst_port).or_insert(0);
            *count_ref += 1;
        }
        map.insert("tls-stats-tls-ports".into(), json!(m));
        //
        // SSL record version
        let mut m = HashMap::new();
        for stats in self.tls_conversations.values() {
            let count_ref = m.entry(stats.parser.ssl_record_version.0).or_insert(0);
            *count_ref += 1;
        }
        let m2: HashMap<_, _> = m
            .iter()
            .map(|(k, v)| (TlsVersion(*k).to_string(), v))
            .collect();
        map.insert("tls-stats-ssl-record-version".into(), json!(m2));
        //
        // Client-Hello version
        let mut m = HashMap::new();
        for stats in self.tls_conversations.values() {
            let count_ref = m.entry(stats.parser.client_version.0).or_insert(0);
            *count_ref += 1;
        }
        let m2: HashMap<_, _> = m
            .iter()
            .map(|(k, v)| (TlsVersion(*k).to_string(), v))
            .collect();
        map.insert("tls-stats-client-hello-version".into(), json!(m2));
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
        map.insert("tls-stats-ciphers".into(), json!(m));
        Value::Object(map)
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
            Direction::ToServer
        } else {
            Direction::ToClient
        };
        // XXX parse only handshake messages ? we can't filter 0x16 (because fragmentation)
        let status = self.parser.parse_tcp_level(data, direction);
        // if status & R_STATUS_EVENTS != 0 {
        //     // XXX ignore events for now
        //     self.parser.events.clear();
        // }
        match status {
            ParseResult::Error | ParseResult::Fatal => {
                // error, stop parsing of future packets
                debug!(
                    "error while parsing tls (idx={}). Activating bypass for future packets {}",
                    pdata.pcap_index, pdata.five_tuple
                );
                self.bypass = true;
            }
            _ => (),
        }
    }
}
