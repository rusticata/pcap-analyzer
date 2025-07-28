use std::sync::Arc;

use libpcap_analyzer::{
    plugins::PluginsFactory, Analyzer, PLUGIN_FLOW_DEL, PLUGIN_FLOW_NEW, PLUGIN_L2, PLUGIN_L3,
    PLUGIN_L4,
};
use libpcap_tools::Config;
use tracing::debug;

use crate::data_engine::PcapLiveDataEngine;

mod data_engine;

pub fn create_engine_live(
    interface_name: &str,
    config: &Config,
) -> Result<PcapLiveDataEngine<Analyzer>, pcap::Error> {
    // try to open interface

    let factory = PluginsFactory::default();
    let registry = factory
        .build_plugins(config)
        .expect("Could not build factory");
    debug!("test-analyzer instantiated plugins:");
    registry.run_plugins(
        |_| true,
        |p| {
            debug!("  {}", p.name());
            let t = p.plugin_type();
            let mut s = "    layers: ".to_owned();
            if t & PLUGIN_L2 != 0 {
                s += "  L2";
            }
            if t & PLUGIN_L3 != 0 {
                s += "  L3";
            }
            if t & PLUGIN_L4 != 0 {
                s += "  L4";
            }
            debug!("{s}");
            let mut s = "    events: ".to_owned();
            if t & PLUGIN_FLOW_NEW != 0 {
                s += "  FLOW_NEW";
            }
            if t & PLUGIN_FLOW_DEL != 0 {
                s += "  FLOW_DEL";
            }
            debug!("{s}");
        },
    );
    let analyzer = Analyzer::new(Arc::new(registry), config);

    PcapLiveDataEngine::new(interface_name, analyzer, config)
}
