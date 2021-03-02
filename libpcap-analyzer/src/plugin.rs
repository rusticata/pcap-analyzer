use crate::analyzer::L3Info;
use crate::packet_info::PacketInfo;
use crate::plugin_registry::PluginRegistry;
use libpcap_tools::{Config, FiveTuple, Flow, Packet, ThreeTuple};
use std::any::Any;

/// Result struct manipulated by all plugins
///
/// Layer n means the *payload* of layer n
pub enum PluginResult<'a> {
    None,
    Error(libpcap_tools::Error),
    /// Layer 2: ethertype and payload
    L2(u16, &'a [u8]),
    /// Layer 3: L3 info (includes l2_proto, src, dst, and next layer proto), and payload
    L3(&'a L3Info, &'a [u8]),
    /// Layer 4: 5-tuple and payload
    L4(FiveTuple, &'a [u8]),
}

#[derive(Debug)]
pub enum PluginBuilderError {
    RegistrationFailed(&'static str),
}

impl From<&'static str> for PluginBuilderError {
    fn from(s: &'static str) -> Self {
        PluginBuilderError::RegistrationFailed(s)
    }
}

/// Plugin builder
///
/// A plugin build is responsible for creating plugin instances
/// from the input configuration.
pub trait PluginBuilder: Sync + Send {
    /// Name of the plugin builder
    fn name(&self) -> &'static str;
    /// Builder function: instantiates zero or more plugins from configuration.
    /// All created plugins must be registered to `registry`
    fn build(
        &self,
        registry: &mut PluginRegistry,
        config: &Config,
    ) -> Result<(), PluginBuilderError>;
}

/// Indicates the plugin does not register any callback function
pub const PLUGIN_NONE: u16 = 0;

/// Indicates the plugin register for Layer 1 data
pub const PLUGIN_L1: u16 = 0b0001;
/// Indicates the plugin register for Layer 2 data
pub const PLUGIN_L2: u16 = 0b0010;
/// Indicates the plugin register for Layer 3 data
pub const PLUGIN_L3: u16 = 0b0100;
/// Indicates the plugin register for Layer 4 data
pub const PLUGIN_L4: u16 = 0b1000;

/// Indicates the plugin registers for 'flow created' events
pub const PLUGIN_FLOW_NEW: u16 = 0b0001_0000;
/// Indicates the plugin registers for 'flow destroyed' events
pub const PLUGIN_FLOW_DEL: u16 = 0b0010_0000;

/// Indicates the plugin register for all layers
pub const PLUGIN_ALL: u16 = 0b1111_1111;

/// Pcap/Pcap-ng analysis plugin instance
///
/// Plugins must be thread-safe because functions can (and will) be called
/// concurrently from multiple threads.
pub trait Plugin: Sync + Send {
    // *Note*: lifetimes means that the reference on `input` must life as long
    // as the plugin object (`'s` for `self`), while the result has a different lifetime,
    // tied only to the input (`'i`)

    /// Returns the name of the plugin instance
    fn name(&self) -> &'static str;

    /// Returns the layers registered by this plugin
    fn plugin_type(&self) -> u16 {
        PLUGIN_ALL
    }

    /// Plugin initialization function
    /// Called before processing a pcap file
    fn pre_process(&mut self) {}
    /// Plugin end of processing function
    /// Called after processing a pcap file
    fn post_process(&mut self) {}

    fn handle_layer_physical<'s, 'i>(
        &'s mut self,
        _packet: &'s Packet,
        _data: &'i [u8],
    ) -> PluginResult<'i> {
        PluginResult::None
    }

    /// Callback function when layer 2 data is available
    /// `data` is the raw ethernet data
    /// `PLUGIN_L1` must be added to `plugin_type()` return
    /// See crate::layers for possible linklayertype values
    fn handle_layer_link<'s, 'i>(
        &'s mut self,
        _packet: &'s Packet,
        _linklayertype: u16,
        _data: &'i [u8],
    ) -> PluginResult<'i> {
        PluginResult::None
    }

    /// Callback function when layer 3 data is available
    /// `packet` is the initial layer 3 packet information
    /// `payload` is the layer 3 payload. It can be different from packet.data if defragmentation occured
    /// `t3` is the three-tuple of the connection
    /// `PLUGIN_L3` must be added to `plugin_type()` return
    fn handle_layer_network<'s, 'i>(
        &'s mut self,
        _packet: &'s Packet,
        _payload: &'i [u8],
        _t3: &'s ThreeTuple,
    ) -> PluginResult<'i> {
        PluginResult::None
    }

    /// Callback function when layer 4 data is available
    /// `packet` is the initial layer 3 packet information
    /// `pinfo` is the flow and layers information, including payload
    /// `PLUGIN_L4` must be added to `plugin_type()` return
    fn handle_layer_transport<'s, 'i>(
        &'s mut self,
        _packet: &'s Packet,
        _pinfo: &PacketInfo,
    ) -> PluginResult<'i> {
        PluginResult::None
    }
    /// Callback function when a new flow is created
    /// `PLUGIN_FLOW_NEW` must be added to `plugin_type()` return
    fn flow_created(&mut self, _flow: &Flow) {}
    /// Callback function when a flow is destroyed
    /// `PLUGIN_FLOW_DEL` must be added to `plugin_type()` return
    fn flow_destroyed(&mut self, _flow: &Flow) {}

    /// Get results, if present
    fn get_results(&mut self) -> Option<Box<dyn Any>> {
        None
    }

    /// Save results to specified directory
    fn save_results(&mut self, _path: &str) -> Result<(), &'static str> {
        Ok(())
    }
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
            fn build(
                &self,
                registry: &mut $crate::PluginRegistry,
                config: &libpcap_tools::Config,
            ) -> Result<(), $crate::PluginBuilderError> {
                let plugin = $build_fn(config);
                let protos = plugin.plugin_type();
                let safe_p = $crate::build_safeplugin!(plugin);
                let id = registry.add_plugin(safe_p);
                if protos & $crate::PLUGIN_L2 != 0 {
                    // XXX no filter, so register for all
                    registry.register_layer(2, 0, id)?;
                }
                if protos & $crate::PLUGIN_L3 != 0 {
                    // XXX no filter, so register for all
                    registry.register_layer(3, 0, id)?;
                }
                if protos & $crate::PLUGIN_L4 != 0 {
                    // XXX no filter, so register for all
                    registry.register_layer(4, 0, id)?;
                }
                Ok(())
            }
        }
    };
    ($name:ident, $builder_name:ident) => {
        $crate::plugin_builder!($name, $builder_name, |_| $name::default());
    };
}
/// Derives a plugin builder relying on the Plugin::default() function
#[macro_export]
macro_rules! default_plugin_builder {
    ($name:ident, $builder:ident) => {
        $crate::plugin_builder!($name, $builder, |_| $name::default());
    };
}
