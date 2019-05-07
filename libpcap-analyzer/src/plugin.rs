use pcap_parser::Packet;

use crate::config::Config;
use crate::packet_data::PacketData;
use libpcap_tools::{Flow, ThreeTuple};

pub trait PluginBuilder: Sync + Send {
    fn name(&self) -> &'static str;
    fn build(&self, config: &Config) -> Box<Plugin>;
}

pub trait Plugin: Sync + Send {
    fn name(&self) -> &'static str;

    fn handle_l2(&mut self, _packet: &Packet, _data: &[u8]) {}
    fn handle_l3(&mut self, _packet: &Packet, _data: &[u8], _ethertype: u16, _t3: &ThreeTuple) {}

    fn handle_l4(&mut self, _packet: &Packet, _pdata: &PacketData) {}

    fn flow_terminate(&mut self, _flow: &Flow) {}

    fn pre_process(&mut self) {}
    fn post_process(&mut self) {}
}

/// Derives a plugin builder relying on the Plugin::default() function
#[macro_export]
macro_rules! default_plugin_builder {
    ($name:ident,$builder:ident) => {
        pub struct $builder;

        impl $crate::plugin::PluginBuilder for $builder {
            fn name(&self) -> &'static str {
                "$builder"
            }
            fn build(&self, _config: &$crate::Config) -> Box<$crate::plugin::Plugin> {
                Box::new($name::default())
            }
        }
    };
}
