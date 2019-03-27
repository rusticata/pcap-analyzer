use super::{Plugin,PluginBuilder};
use crate::default_plugin_builder;
use crate::packet_data::PacketData;

use nom::HexDisplay;

#[derive(Default)]
pub struct BasicStats {
    pub total_bytes : usize,
    pub total_packets : usize,
}

default_plugin_builder!(BasicStats, BasicStatsBuilder);

impl Plugin for BasicStats {
    fn name(&self) -> &'static str { "BasicStats" }

    fn handle_l3(&mut self, data: &[u8], _ethertype:u16) {
        // info!("BasicStats::handle_l3 (len {})", data.len());
        self.total_bytes += data.len();
        self.total_packets += 1;
    }

    fn handle_l4(&mut self, packet: &PacketData) {
        let five_tuple = &packet.five_tuple;
        info!("BasicStats::handle_l4");
        debug!("    5t: proto {} / [{}]:{} -> [{}]:{}",
               five_tuple.proto,
               five_tuple.src,
               five_tuple.src_port,
               five_tuple.dst,
               five_tuple.dst_port);
        debug!("    to_server: {}", packet.to_server);
        debug!("    l3_type: {}", packet.l3_type);
        debug!("    l3_data_len: {}", packet.l3_data.len());
        debug!("    l4_type: {}", packet.l4_type);
        debug!("    l4_data_len: {}", packet.l4_data.map_or(0, |d| d.len()));
        if let Some(flow) = packet.flow {
            let five_tuple = &flow.five_tuple;
            debug!("    flow: [{}]:{} -> [{}]:{}",
                   five_tuple.src,
                   five_tuple.src_port,
                   five_tuple.dst,
                   five_tuple.dst_port);
        }
        // debug!("    l3_data:\n{}", packet.l3_data.to_hex(16));
        packet.l4_data.map(|d| {
            debug!("    l4_data:\n{}", d.to_hex(16));
        });
    }

    fn post_process(&mut self) {
        info!("BasicStats: total bytes {}", self.total_bytes);
        info!("BasicStats: total packets {}", self.total_packets);
    }
}
