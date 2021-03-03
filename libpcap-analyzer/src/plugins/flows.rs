//! Plugin to get/save information on flows

use crate::plugin::Plugin;
use crate::{output, plugin_builder, PLUGIN_FLOW_DEL, PLUGIN_FLOW_NEW};
use indexmap::IndexMap;
use libpcap_tools::{Flow, FlowID};
use serde_json::{json, Value};
use std::any::Any;

#[derive(Default)]
pub struct FlowsInfo {
    pub flows: IndexMap<FlowID, Flow>,
}

plugin_builder!(FlowsInfo, FlowsInfoBuilder);

impl Plugin for FlowsInfo {
    fn name(&self) -> &'static str {
        "FlowsInfo"
    }
    fn plugin_type(&self) -> u16 {
        PLUGIN_FLOW_NEW | PLUGIN_FLOW_DEL
    }

    fn flow_destroyed(&mut self, flow: &Flow) {
        let f = flow.clone();
        self.flows.insert(f.flow_id, f);
    }

    fn get_results(&mut self) -> Option<Box<dyn Any>> {
        let v = self.get_results_json();
        Some(Box::new(v))
    }

    fn save_results(&mut self, path: &str) -> Result<(), &'static str> {
        let results = self.get_results_json();
        // save data to file
        let file = output::create_file(path, "flows.json").or(Err("Cannot create output file"))?;
        serde_json::to_writer(file, &results).or(Err("Cannot save results to file"))?;
        Ok(())
    }
}

impl FlowsInfo {
    fn get_results_json(&mut self) -> Value {
        let iter = self.flows.iter().map(|(&flow_id, f)| {
            if let Value::Object(mut m) = json!(f.five_tuple) {
                m.insert("flow_id".into(), json!(flow_id));
                let first_seen = format!("{}.{}", f.first_seen.secs, f.first_seen.micros);
                m.insert("first_seen".into(), json!(first_seen));
                let last_seen = format!("{}.{}", f.last_seen.secs, f.last_seen.micros);
                m.insert("last_seen".into(), json!(last_seen));
                (flow_id.to_string(), Value::Object(m))
            } else {
                panic!("json! macro returned unexpected type");
            }
        });
        let map = iter.collect();
        Value::Object(map)
    }
}
