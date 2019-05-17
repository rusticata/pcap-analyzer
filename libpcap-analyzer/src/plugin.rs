use pcap_parser::Packet;

use crate::packet_data::PacketData;
use libpcap_tools::{Config, Flow, ThreeTuple};

pub trait PluginBuilder: Sync + Send {
    fn name(&self) -> &'static str;
    fn build(&self, config: &Config) -> Box<Plugin>;
}

/// Indicates the plugin does not register any callback function
pub const PLUGIN_NONE: u16 = 0;

/// Indicates the plugin register for Layer 2 data
pub const PLUGIN_L2: u16 = 0b0001;
/// Indicates the plugin register for Layer 3 data
pub const PLUGIN_L3: u16 = 0b0010;
/// Indicates the plugin register for Layer 4 data
pub const PLUGIN_L4: u16 = 0b0100;

/// Indicates the plugin register for all layers
pub const PLUGIN_ALL: u16 = 0b1111;

pub trait Plugin: Sync + Send {
    fn name(&self) -> &'static str;
    /// Returns the layers registered by this plugin
    fn plugin_type(&self) -> u16 { PLUGIN_ALL }

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
            fn build(&self, _config: &libpcap_tools::Config) -> Box<$crate::plugin::Plugin> {
                Box::new($name::default())
            }
        }
    };
}
