//! Example of libpcap-analyzer plugin, in an external directory

use libpcap_analyzer::default_plugin_builder;
use libpcap_analyzer::{Plugin, PLUGIN_NONE};

/// Example plugin, without configuration
#[derive(Default)]
pub struct ExEmptyPlugin;

// Derive the default builder (relies on the default() function from the plugin)
default_plugin_builder!(ExEmptyPlugin, ExEmptyPluginBuilder);

impl Plugin for ExEmptyPlugin {
    fn name(&self) -> &'static str {
        "ExEmptyPlugin"
    }
    fn plugin_type(&self) -> u16 {
        PLUGIN_NONE
    }
}
