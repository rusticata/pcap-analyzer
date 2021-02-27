//! Plugin to debug packets/flows/layers by displaying hex data

use crate::default_plugin_builder;
use crate::packet_info::PacketInfo;
use crate::plugin::{Plugin, PluginResult, PLUGIN_L3, PLUGIN_L4};
use libpcap_tools::pcap_parser::nom::HexDisplay;
use libpcap_tools::{Packet, ThreeTuple};

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

    fn handle_layer_network<'s, 'i>(
        &'s mut self,
        _packet: &'s Packet,
        data: &'i [u8],
        t3: &'s ThreeTuple,
    ) -> PluginResult<'i> {
        info!("HexDump::handle_l3 (len {})", data.len());
        debug!("    3t: {}", t3);
        debug!("    l4_proto: {:x}", t3.l4_proto);
        debug!("    l3_data:\n{}", data.to_hex(16));
        PluginResult::None
    }

    fn handle_layer_transport<'s, 'i>(
        &'s mut self,
        _packet: &'s Packet,
        pinfo: &PacketInfo,
    ) -> PluginResult<'i> {
        let five_tuple = &pinfo.five_tuple;
        info!("HexDump::handle_l4");
        debug!("    5-t: {}", five_tuple);
        debug!("    to_server: {}", pinfo.to_server);
        debug!("    l3_type: 0x{:x}", pinfo.l3_type);
        debug!("    l4_data_len: {}", pinfo.l4_data.len());
        debug!("    l4_type: {}", pinfo.l4_type);
        debug!("    l4_payload_len: {}", pinfo.l4_payload.map_or(0, |d| d.len()));
        if let Some(flow) = pinfo.flow {
            let five_tuple = &flow.five_tuple;
            debug!("    flow: [{}]:{} -> [{}]:{} [{}]",
                   five_tuple.src,
                   five_tuple.src_port,
                   five_tuple.dst,
                   five_tuple.dst_port,
                   five_tuple.proto);
        }
        if let Some(d) = pinfo.l4_payload {
            debug!("    l4_payload:\n{}", d.to_hex(16));
        }
        PluginResult::None
    }
}
