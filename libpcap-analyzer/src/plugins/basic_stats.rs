use std::collections::HashMap;

use super::Plugin;
use crate::default_plugin_builder;
use crate::packet_info::PacketInfo;
use crate::plugin::{PLUGIN_L3, PLUGIN_L4};
use libpcap_tools::{FiveTuple, Packet, ThreeTuple};

#[derive(Default)]
pub struct Count {
    pub num_bytes : usize,
    pub num_packets : usize,
}

#[derive(Default)]
pub struct BasicStats {
    pub total_bytes_l3 : usize,
    pub total_packets : usize,

    pub l3_conversations: HashMap<ThreeTuple,Count>,
    pub l4_conversations: HashMap<FiveTuple,Count>,
}

default_plugin_builder!(BasicStats, BasicStatsBuilder);

impl Plugin for BasicStats {
    fn name(&self) -> &'static str { "BasicStats" }
    fn plugin_type(&self) -> u16 { PLUGIN_L3|PLUGIN_L4 }

    fn handle_l3(&mut self, _packet:&Packet, data: &[u8], _ethertype:u16, t3:&ThreeTuple) {
        // info!("BasicStats::handle_l3 (len {})", data.len());
        let entry = self.l3_conversations.entry(t3.clone()).or_insert_with(|| Count::default());
        entry.num_bytes += data.len();
        entry.num_packets += 1;
        self.total_bytes_l3 += data.len();
        self.total_packets += 1;
    }

    fn handle_l4(&mut self, _packet:&Packet, pdata: &PacketInfo) {
        let entry = self.l4_conversations.entry(pdata.five_tuple.clone()).or_insert_with(|| Count::default());
        entry.num_bytes += pdata.l4_payload.map(|l4| l4.len()).unwrap_or(0);
        entry.num_packets += 1;
    }

    fn post_process(&mut self) {
        info!("BasicStats: total packets {} bytes", self.total_packets);
        info!("BasicStats: total bytes (L3) {}", self.total_bytes_l3);
        let total_l4 = self.l4_conversations
            .iter()
            .map(|(_,stats)| stats.num_bytes)
            .sum::<usize>();
        info!("BasicStats: total bytes (L4) {} bytes", total_l4);
        info!("Conversions (L3):");
        for (t3,stats) in self.l3_conversations.iter() {
            info!("  {}: {} bytes, {} packets", t3, stats.num_bytes, stats.num_packets);
        }
        info!("Conversions (L4):");
        for (t5,stats) in self.l4_conversations.iter() {
            info!("  {}: {} bytes, {} packets", t5, stats.num_bytes, stats.num_packets);
        }    }
}
