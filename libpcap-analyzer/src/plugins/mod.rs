use std::collections::HashMap;

use crate::config::Config;
use crate::{Plugin,PluginBuilder};

mod basic_stats;
mod tcp_states;
mod rusticata;
mod examples;

pub struct Plugins {
    pub storage: HashMap<String, Box<Plugin>>,
}

pub struct PluginsFactory {
    list: Vec<Box<PluginBuilder>>,
}

pub fn plugins_factory() -> PluginsFactory {
    let mut v: Vec<Box<PluginBuilder>> = Vec::new();

    v.push(Box::new(basic_stats::BasicStatsBuilder));
    v.push(Box::new(tcp_states::TcpStatesBuilder));
    v.push(Box::new(rusticata::RusticataBuilder));
    v.push(Box::new(examples::EmptyBuilder));
    v.push(Box::new(examples::EmptyWithConfigBuilder));

    PluginsFactory{ list:v }
}

pub fn build_plugins(factory: &PluginsFactory, config:&Config) -> Plugins {
    let mut h: HashMap<String, Box<Plugin>> = HashMap::new();

    factory.list.iter().for_each(|b| {
        let plugin = b.build(&config);
        h.insert(plugin.name().to_string(), plugin);
    });

    Plugins { storage: h }
}
