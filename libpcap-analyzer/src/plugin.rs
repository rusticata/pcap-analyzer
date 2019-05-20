use pcap_parser::Packet;

use crate::packet_data::PacketData;
use libpcap_tools::{Config, Flow, ThreeTuple};

/// Plugin builder
///
/// A plugin build is responsible for creating plugin instances
/// from the input configuration.
pub trait PluginBuilder: Sync + Send {
    /// Name of the plugin builder
    fn name(&self) -> &'static str;
    /// Builder function: instanciates a plugin
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

/// Indicates the plugin registers for 'flow created' events
pub const PLUGIN_FLOW_NEW: u16 = 0b0001_0000;
/// Indicates the plugin registers for 'flow destroyed' events
pub const PLUGIN_FLOW_DEL: u16 = 0b0010_0000;

/// Indicates the plugin register for all layers
pub const PLUGIN_ALL: u16 = 0b1111_1111;

/// Pcap/Pcap-ng analyzis plugin instance
///
/// Plugins must be thread-safe because functions can (and will) be called
/// concurrently from multiple threads.
pub trait Plugin: Sync + Send {
    /// Returns the name of the plugin instance
    fn name(&self) -> &'static str;
    /// Returns the layers registered by this plugin
    fn plugin_type(&self) -> u16 { PLUGIN_ALL }
    /// Plugin initialization function
    /// Called before processing a pcap file
    fn pre_process(&mut self) {}
    /// Plugin end of processing function
    /// Called after processing a pcap file
    fn post_process(&mut self) {}
    /// Callback function when layer 2 data is available
    /// `data` is the raw ethernet data
    /// `PLUGIN_L2` must be added to `plugin_type()` return
    fn handle_l2(&mut self, _packet: &Packet, _data: &[u8]) {}
    /// Callback function when layer 3 data is available
    /// `packet` is the initial layer 3 packet information
    /// `data` is the layer 3 data. It can be different from packet.data if defragmentation occured
    /// `ethertype` is the type of `data` as declared in ethernet frame
    /// `PLUGIN_L3` must be added to `plugin_type()` return
    fn handle_l3(&mut self, _packet: &Packet, _data: &[u8], _ethertype: u16, _t3: &ThreeTuple) {}
    /// Callback function when layer 4 data is available
    /// `data` is the layer 4 data, defragmented if possible
    /// `packet` is the initial layer 3 packet information
    /// `pdata` is the flow and layers information
    /// `PLUGIN_L4` must be added to `plugin_type()` return
    fn handle_l4(&mut self, _packet: &Packet, _pdata: &PacketData) {}
    /// Callback function when a new flow is created
    /// `PLUGIN_FLOW_NEW` must be added to `plugin_type()` return
    fn flow_created(&mut self, _flow: &Flow) {}
    /// Callback function when a flow is destroyed
    /// `PLUGIN_FLOW_DEL` must be added to `plugin_type()` return
    fn flow_destroyed(&mut self, _flow: &Flow) {}
}

/// Derives a plugin builder relying on the Plugin::default() function
#[macro_export]
macro_rules! default_plugin_builder {
    ($name:ident,$builder:ident) => {
        pub struct $builder;

        impl $crate::PluginBuilder for $builder {
            fn name(&self) -> &'static str {
                "$builder"
            }
            fn build(&self, _config: &libpcap_tools::Config) -> Box<$crate::Plugin> {
                Box::new($name::default())
            }
        }
    };
}
