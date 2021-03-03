use crate::plugin::{Plugin, PluginResult};
use crate::plugin_builder;
use crate::output;
use crate::packet_info::PacketInfo;
use crate::plugin::{PLUGIN_L3, PLUGIN_L4};
use indexmap::IndexMap;
use libpcap_tools::{FiveTuple, FlowID, Packet, ThreeTuple};
use serde::Serialize;
use serde_json::{json, Value};
use std::any::Any;

#[derive(Default, Serialize)]
struct Stats {
    num_bytes : usize,
    num_packets : usize,
    flow_id: Option<FlowID>,
}

#[derive(Default)]
pub struct BasicStats {
    pub total_bytes_l3 : usize,
    pub total_packets : usize,

    l3_conversations: IndexMap<ThreeTuple, Stats>,
    l4_conversations: IndexMap<FiveTuple, Stats>,
}

plugin_builder!(BasicStats, BasicStatsBuilder);

impl Plugin for BasicStats {
    fn name(&self) -> &'static str { "BasicStats" }
    fn plugin_type(&self) -> u16 { PLUGIN_L3|PLUGIN_L4 }

    fn handle_layer_network<'s, 'i>(
        &'s mut self,
        _packet: &'s Packet,
        data: &'i [u8],
        t3: &'s ThreeTuple,
    ) -> PluginResult<'i> {
        // info!("BasicStats::handle_l3 (len {})", data.len());
        let entry = self.l3_conversations.entry(t3.clone()).or_insert_with(Stats::default);
        entry.num_bytes += data.len();
        entry.num_packets += 1;
        self.total_bytes_l3 += data.len();
        self.total_packets += 1;
        PluginResult::None
    }

    fn handle_layer_transport<'s, 'i>(
        &'s mut self,
        _packet: &'s Packet,
        pinfo: &PacketInfo,
    ) -> PluginResult<'i> {
        let entry = self.l4_conversations.entry(pinfo.five_tuple.clone()).or_insert_with(Stats::default);
        entry.num_bytes += pinfo.l4_payload.map(|l4| l4.len()).unwrap_or(0);
        if let Some(flow) = pinfo.flow {
            entry.flow_id = Some(flow.flow_id);
        }
        entry.num_packets += 1;
        PluginResult::None
    }

    fn get_results(&mut self) -> Option<Box<dyn Any>> {
        let v = self.get_results_json();
        Some(Box::new(v))
    }

    fn save_results(&mut self, path: &str) -> Result<(), &'static str> {
        let results = self.get_results_json();
        // save data to file
        let file = output::create_file(path, "basic-stats.json")
            .or(Err("Cannot create output file"))?;
        serde_json::to_writer(file, &results).or(Err("Cannot save results to file"))?;
        Ok(())
    }
}

impl BasicStats {
    fn get_results_json(&mut self) -> Value {
        self.l3_conversations.sort_keys();
        self.l4_conversations.sort_keys();
        let total_l4 = self.l4_conversations
            .iter()
            .map(|(_,stats)| stats.num_bytes)
            .sum::<usize>();
        let l3 : Vec<_> = self.l3_conversations.iter()
            .map(|(t3,s)| {
                if let Value::Object(mut m) = json!(t3) {
                    m.insert("num_bytes".into(), s.num_bytes.into());
                    m.insert("num_packets".into(), s.num_packets.into());
                    Value::Object(m)
                } else {
                    panic!("json! macro returned unexpected type");
                }
            })
            .collect();
        let l4 : Vec<_> = self.l4_conversations.iter()
            .map(|(t5,s)| {
                if let Value::Object(mut m) = json!(t5) {
                    m.insert("num_bytes".into(), s.num_bytes.into());
                    m.insert("num_packets".into(), s.num_packets.into());
                    if let Some(flow_id) = s.flow_id {
                        m.insert("flow_id".into(), flow_id.into());
                    }
                    Value::Object(m)
                } else {
                    panic!("json! macro returned unexpected type");
                }
            })
            .collect();
        let js = json!({
            "total_l3": self.total_bytes_l3,
            "total_l3_packets": self.total_packets,
            "l3": l3,
            "total_l4": total_l4,
            "l4": l4,
        });
        js
    }
}