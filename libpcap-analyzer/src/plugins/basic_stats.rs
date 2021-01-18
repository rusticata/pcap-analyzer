use crate::plugin::{Plugin, PluginResult};
use crate::plugin_builder;
use crate::output;
use crate::packet_info::PacketInfo;
use crate::plugin::{PLUGIN_L3, PLUGIN_L4};
use indexmap::IndexMap;
use libpcap_tools::{FiveTuple, FlowID, Packet, ThreeTuple};
use serde::Serialize;
use serde_json::{json, Value};

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

    output_dir: String,
}

plugin_builder!(BasicStats, BasicStatsBuilder, |config| {
    let output_dir = output::get_output_dir(config).to_owned();
    BasicStats {
        output_dir,
        ..Default::default()
    }
});

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

    fn post_process(&mut self) {
        self.l3_conversations.sort_keys();
        self.l4_conversations.sort_keys();
        info!("BasicStats: total packets {}", self.total_packets);
        info!("BasicStats: total bytes (L3) {}", self.total_bytes_l3);
        let total_l4 = self.l4_conversations
            .iter()
            .map(|(_,stats)| stats.num_bytes)
            .sum::<usize>();
        info!("BasicStats: total bytes (L4) {}", total_l4);
        info!("Conversions (L3):");
        for (t3,stats) in self.l3_conversations.iter() {
            info!("  {}: {} bytes, {} packets", t3, stats.num_bytes, stats.num_packets);
        }
        info!("Conversions (L4/TCP):");
        for (t5,stats) in self.l4_conversations.iter().filter(|(t5,_)| t5.proto == 6) {
            info!("  {}: {} bytes, {} packets", t5, stats.num_bytes, stats.num_packets);
        }
        info!("Conversions (L4/UDP):");
        for (t5,stats) in self.l4_conversations.iter().filter(|(t5,_)| t5.proto == 17) {
            info!("  {}: {} bytes, {} packets", t5, stats.num_bytes, stats.num_packets);
        }
        info!("Conversions (L4/other):");
        for (t5,stats) in self.l4_conversations.iter().filter(|(t5,_)| t5.proto != 6 && t5.proto != 17) {
            info!("  {}: {} bytes, {} packets", t5, stats.num_bytes, stats.num_packets);
        }
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
        let file = output::create_file(&self.output_dir, "basic-stats.json").expect("Cannot create output file");
        serde_json::to_writer(file, &js).unwrap();
    }
}
