use crate::plugin_registry::PluginRegistry;

use crate::packet_info::PacketInfo;
use libpcap_tools::{Config, Flow, Packet, ThreeTuple};

/// Plugin builder
///
/// A plugin build is responsible for creating plugin instances
/// from the input configuration.
pub trait PluginBuilder: Sync + Send {
    /// Name of the plugin builder
    fn name(&self) -> &'static str;
    /// Builder function: instanciates zero or more plugins from configuration.
    /// All created plugins must be registered to `registry`
    fn build(&self, registry:&mut PluginRegistry, config: &Config);
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

pub const ETHERTYPE_IPV4 : u16 = 0x0800;
pub const ETHERTYPE_IPV6 : u16 = 0x86dd;

pub const TRANSPORT_ICMP : u8 = 1;
pub const TRANSPORT_TCP : u8 = 6;
pub const TRANSPORT_UDP : u8 = 17;

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
    /// `pinfo` is the flow and layers information
    /// `PLUGIN_L4` must be added to `plugin_type()` return
    fn handle_l4(&mut self, _packet: &Packet, _pinfo: &PacketInfo) {}
    /// Callback function when a new flow is created
    /// `PLUGIN_FLOW_NEW` must be added to `plugin_type()` return
    fn flow_created(&mut self, _flow: &Flow) {}
    /// Callback function when a flow is destroyed
    /// `PLUGIN_FLOW_DEL` must be added to `plugin_type()` return
    fn flow_destroyed(&mut self, _flow: &Flow) {}
}

/// Derives a plugin builder
///
/// A closure can be passed as third argument. This closure receives a `Config`
/// object and must return an instance of plugin.
///
/// By default (if no closure was provided), the plugin is created
/// using the `Plugin::default()` function.
///
/// Note: the plugin builder may create plugins of different types
#[macro_export]
macro_rules! plugin_builder {
    ($name:ident, $builder_name:ident, $build_fn:expr) => {
        pub struct $builder_name;

        impl $crate::PluginBuilder for $builder_name {
            fn name(&self) -> &'static str {
                stringify!($builder_name)
            }
            fn build(&self, registry: &mut $crate::PluginRegistry, config: &libpcap_tools::Config) {
                let plugin = $build_fn(config);
                let protos = plugin.plugin_type();
                let safe_p = $crate::build_safeplugin!(plugin);
                registry.add_plugin(safe_p.clone());
                if protos & $crate::PLUGIN_L2 != 0 {
                    registry.register_l2(safe_p.clone());
                }
                if protos & $crate::PLUGIN_L3 != 0 {
                    registry.register_ethertype_all(safe_p.clone());
                }
                if protos & $crate::PLUGIN_L4 != 0 {
                    registry.register_transport_layer_all(safe_p.clone());
                }
            }
        }
    };
    ($name:ident, $builder_name:ident) => (
        $crate::plugin_builder!($name, $builder_name, |_| $name::default());
    );
}
/// Derives a plugin builder relying on the Plugin::default() function
#[macro_export]
macro_rules! default_plugin_builder {
    ($name:ident, $builder:ident) => {
        $crate::plugin_builder!($name, $builder, |_| $name::default());
    };
}
