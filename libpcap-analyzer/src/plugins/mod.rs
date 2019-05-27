//! Plugin factory definition and default plugins implementation

use std::collections::HashMap;

use crate::{Plugin, PluginBuilder, PluginRegistry};
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
///
/// A plugin factory stores all registered builders, and is used to
/// create all plugin instances on request.
pub struct PluginsFactory {
    list: Vec<Box<PluginBuilder>>,
}

impl PluginsFactory {
    /// Create a new empty plugin factory
    pub fn new() -> PluginsFactory {
        PluginsFactory { list: Vec::new() }
    }

    /// Add a new plugin builder to the factory
    pub fn add_builder(&mut self, b: Box<PluginBuilder>) {
        self.list.push(b);
    }

    /// Instanciate all plugins
    pub fn build_plugins(&self, config: &Config) -> PluginRegistry {
        let mut registry = PluginRegistry::new();

        self.list.iter().for_each(|b| {
            let _ = b.build(&mut registry, &config);
        });

        registry
    }

    /// Instanciate plugins if they match predicate
    pub fn build_filter_plugins<P>(&self, predicate: P, config: &Config) -> PluginRegistry
    where
        P: Fn(&str) -> bool,
    {
        let mut registry = PluginRegistry::new();

        self.list.iter().for_each(|b| {
            if predicate(b.name()) {
                let _ = b.build(&mut registry, &config);
            }
        });

        registry
    }
}

impl Default for PluginsFactory {
    /// Create a new plugin factory, with all default plugins
    fn default() -> Self {
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
}
