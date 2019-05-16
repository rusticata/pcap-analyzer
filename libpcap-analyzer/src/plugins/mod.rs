use std::collections::HashMap;

use crate::{Plugin, PluginBuilder};
use libpcap_tools::Config;

mod basic_stats;
#[cfg(feature = "plugin_community_id")]
mod community_id;
mod examples;
#[cfg(feature = "plugin_rusticata")]
mod rusticata;
mod tcp_states;

/// Storage of plugin instances
pub struct Plugins {
    pub storage: HashMap<String, Box<Plugin>>,
}

/// Plugin Factory
pub struct PluginsFactory {
    list: Vec<Box<PluginBuilder>>,
}

impl PluginsFactory {
    /// Create a new empty plugin factory
    pub fn new() -> PluginsFactory {
        PluginsFactory { list: Vec::new() }
    }

    /// Create a new empty plugin factory, loading all plugins
    pub fn new_all_plugins() -> PluginsFactory {
        let mut v: Vec<Box<PluginBuilder>> = Vec::new();

        v.push(Box::new(basic_stats::BasicStatsBuilder));
        #[cfg(feature = "plugin_community_id")]
        v.push(Box::new(community_id::CommunityIDBuilder));
        v.push(Box::new(tcp_states::TcpStatesBuilder));
        #[cfg(feature = "plugin_rusticata")]
        v.push(Box::new(rusticata::RusticataBuilder));
        v.push(Box::new(examples::EmptyBuilder));
        v.push(Box::new(examples::EmptyWithConfigBuilder));

        PluginsFactory { list: v }
    }

    /// Add a new plugin builder to the factory
    pub fn add_builder(&mut self, b: Box<PluginBuilder>) {
        self.list.push(b);
    }

    /// Instanciate all plugins
    pub fn build_plugins(&self, config: &Config) -> Plugins {
        let mut h: HashMap<String, Box<Plugin>> = HashMap::new();

        self.list.iter().for_each(|b| {
            let plugin = b.build(&config);
            let name = plugin.name().to_string();
            if h.contains_key(&name) {
                warn!("Attempt to insert plugin {} twice", name);
            } else {
                h.insert(plugin.name().to_string(), plugin);
            }
        });

        Plugins { storage: h }
    }
}
