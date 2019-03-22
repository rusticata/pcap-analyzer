use std::collections::HashMap;

use crate::{Plugin,PluginBuilder};

mod basic_stats;
mod tcp_states;

pub struct Plugins {
    pub list: HashMap<String, Box<Plugin>>,
}

pub struct PluginsFactory {
    list: Vec<Box<PluginBuilder>>,
}

pub fn plugins_factory() -> PluginsFactory {
    let mut v: Vec<Box<PluginBuilder>> = Vec::new();

    v.push(Box::new(basic_stats::BasicStatsBuilder));
    v.push(Box::new(tcp_states::TcpStatesBuilder));

    PluginsFactory{ list:v }
}

pub fn plugins(factory: &PluginsFactory) -> Plugins {
    let mut h: HashMap<String, Box<Plugin>> = HashMap::new();

    factory.list.iter().for_each(|b| {
        let plugin = b.build();
        h.insert(plugin.name().to_string(), plugin);
    });

    Plugins { list: h }
}
