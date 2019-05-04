use pcap_parser::Packet;

use std::collections::HashMap;

use super::Plugin;
use crate::default_plugin_builder;
use crate::packet_data::PacketData;
use libpcap_tools::ThreeTuple;

use nom::HexDisplay;

#[derive(Default)]
pub struct Count {
    pub num_bytes : usize,
    pub num_packets : usize,
}

#[derive(Default)]
pub struct BasicStats {
    pub total_bytes : usize,
    pub total_packets : usize,

    pub l3_conversations: HashMap<ThreeTuple,Count>,
}

default_plugin_builder!(BasicStats, BasicStatsBuilder);

impl Plugin for BasicStats {
    fn name(&self) -> &'static str { "BasicStats" }

    fn handle_l3(&mut self, packet:&Packet, data: &[u8], _ethertype:u16, t3:&ThreeTuple) {
        // info!("BasicStats::handle_l3 (len {})", data.len());
        let entry = self.l3_conversations.entry(t3.clone()).or_insert_with(|| Count::default());
        entry.num_bytes += packet.header.len as usize;
        entry.num_packets += 1;
        self.total_bytes += data.len();
        self.total_packets += 1;
    }

    fn handle_l4(&mut self, _packet:&Packet, pdata: &PacketData) {
        let five_tuple = &pdata.five_tuple;
        info!("BasicStats::handle_l4");
        debug!("    5t: proto {} / [{}]:{} -> [{}]:{}",
               five_tuple.proto,
               five_tuple.src,
               five_tuple.src_port,
               five_tuple.dst,
               five_tuple.dst_port);
        debug!("    to_server: {}", pdata.to_server);
        debug!("    l3_type: {}", pdata.l3_type);
        debug!("    l3_data_len: {}", pdata.l3_data.len());
        debug!("    l4_type: {}", pdata.l4_type);
        debug!("    l4_data_len: {}", pdata.l4_data.map_or(0, |d| d.len()));
        if let Some(flow) = pdata.flow {
            let five_tuple = &flow.five_tuple;
            debug!("    flow: [{}]:{} -> [{}]:{}",
                   five_tuple.src,
                   five_tuple.src_port,
                   five_tuple.dst,
                   five_tuple.dst_port);
        }
        debug!("    l3_data:\n{}", pdata.l3_data.to_hex(16));
        pdata.l4_data.map(|d| {
            debug!("    l4_data:\n{}", d.to_hex(16));
        });
    }

    fn post_process(&mut self) {
        info!("BasicStats: total bytes {}", self.total_bytes);
        info!("BasicStats: total packets {}", self.total_packets);
        info!("Conversions (L3):");
        for (t3,stats) in self.l3_conversations.iter() {
            info!("  {} -> {} [{}]: {} bytes, {} packets", t3.src, t3.dst, t3.proto, stats.num_bytes, stats.num_packets);
        }
    }
}
