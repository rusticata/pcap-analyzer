use crate::plugin::{Plugin, PLUGIN_NONE};
use crate::default_plugin_builder;
use libpcap_tools::Config;

/// Example plugin, without configuration
#[derive(Default)]
pub struct Empty;

// Derive the default builder (relies on the default() function from the plugin)
default_plugin_builder!(Empty, EmptyBuilder);

impl Plugin for Empty {
    fn name(&self) -> &'static str { "Empty" }
    fn plugin_type(&self) -> u16 { PLUGIN_NONE }
}

/// Example plugin, reading a configuration value
#[derive(Default)]
pub struct EmptyWithConfig {
    name: Option<String>,
}

impl Plugin for EmptyWithConfig {
    fn name(&self) -> &'static str { "EmptyWithConfig" }
    fn plugin_type(&self) -> u16 { PLUGIN_NONE }

    fn pre_process(&mut self) {
        info!("Hello, I am plugin EmptyWithConfig, with name {:?}", self.name);
    }
}

/// Implements the plugin PluginBuilder
///
/// We cannot rely on the default implementation, since we want to overload the `build` function
pub struct EmptyWithConfigBuilder;

impl crate::plugin::PluginBuilder for EmptyWithConfigBuilder {
    fn name(&self) -> &'static str { "$builder" }
    fn build(&self, config:&Config) -> Vec<Box<Plugin>> {
        let name = config.get("plugin.emptywithconfig.name");
        let plugin = EmptyWithConfig {
            name: name.map(|s| s.to_string()),
        };
        vec![Box::new(plugin)]
    }
}
