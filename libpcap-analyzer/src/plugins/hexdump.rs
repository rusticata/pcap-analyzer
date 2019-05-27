//! Plugin to debug packets/flows/layers by displaying hex data

use pcap_parser::Packet;
use super::Plugin;
use crate::default_plugin_builder;
use crate::packet_data::PacketData;
use crate::plugin::{PLUGIN_L3, PLUGIN_L4};
use nom::HexDisplay;
use libpcap_tools::ThreeTuple;

#[derive(Default)]
pub struct HexDump;

default_plugin_builder!(HexDump, HexDumpBuilder);

impl Plugin for HexDump {
    fn name(&self) -> &'static str {
        "HexDump"
    }
    fn plugin_type(&self) -> u16 {
        PLUGIN_L3|PLUGIN_L4
    }

    fn handle_l3(&mut self, _packet:&Packet, data: &[u8], ethertype:u16, t3:&ThreeTuple) {
        info!("HexDump::handle_l3 (len {})", data.len());
        debug!("    ethertype: {:x}", ethertype);
        debug!("    3t: {}", t3);
        debug!("    l3_data:\n{}", data.to_hex(16));
    }

    fn handle_l4(&mut self, _packet: &Packet, pdata: &PacketData) {
        let five_tuple = &pdata.five_tuple;
        info!("HexDump::handle_l4");
        debug!("    5t: {}", five_tuple);
        debug!("    to_server: {}", pdata.to_server);
        debug!("    l3_type: {}", pdata.l3_type);
        debug!("    l3_data_len: {}", pdata.l3_data.len());
        debug!("    l4_type: {}", pdata.l4_type);
        debug!("    l4_data_len: {}", pdata.l4_data.map_or(0, |d| d.len()));
        if let Some(flow) = pdata.flow {
            let five_tuple = &flow.five_tuple;
            debug!("    flow: [{}]:{} -> [{}]:{} [{}]",
                   five_tuple.src,
                   five_tuple.src_port,
                   five_tuple.dst,
                   five_tuple.dst_port,
                   five_tuple.proto);
        }
        pdata.l4_data.map(|d| {
            debug!("    l4_data:\n{}", d.to_hex(16));
        });
    }
}
