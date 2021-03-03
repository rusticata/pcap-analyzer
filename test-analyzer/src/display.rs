use libpcap_analyzer::Plugin;
use serde_json::{json, Value};
use std::any::Any;

pub fn display_json_basicstats(any: Box<dyn Any>) {
    let results = any.downcast::<Value>().expect("Plugin result is not JSON");
    info!("BasicStats: total packets {}", results["total_l3_packets"]);
    info!("BasicStats: total bytes (L3) {}", results["total_l3"]);
    info!("BasicStats: total bytes (L4) {}", results["total_l4"]);
    info!("Conversions (L3):");
    if let Some(l3) = results["l3"].as_array() {
        for m in l3 {
            info!(
                "  {} -> {} [{}]: {} bytes, {} packets",
                m["src"].as_str().unwrap(),
                m["dst"].as_str().unwrap(),
                m["l4_proto"],
                m["num_bytes"],
                m["num_packets"]
            );
        }
    }
    let print_l4 = |m: &Value| {
        info!(
            "  {}:{} -> {}:{} [{}]: {} bytes, {} packets",
            m["src"].as_str().unwrap(),
            m["src_port"],
            m["dst"].as_str().unwrap(),
            m["dst_port"],
            m["proto"],
            m["num_bytes"],
            m["num_packets"]
        )
    };
    if let Some(l4) = results["l4"].as_array() {
        info!("Conversions (L4/TCP):");
        for m in l4.iter().filter(|entry| entry["proto"] == json!(6)) {
            print_l4(m);
        }
        info!("Conversions (L4/UDP):");
        for m in l4.iter().filter(|entry| entry["proto"] == json!(17)) {
            print_l4(m);
        }
        info!("Conversions (L4/other):");
        for m in l4
            .iter()
            .filter(|entry| entry["proto"] != json!(6) && entry["proto"] != json!(17))
        {
            print_l4(m);
        }
    }
}

pub fn display_json_communityid(any: Box<dyn Any>) {
    let results = any.downcast::<Value>().expect("Plugin result is not JSON");
    info!("Community IDs:");
    if let Some(map) = results.as_object() {
        for (k, v) in map {
            info!("  {}: {}", k, v.as_str().unwrap());
        }
    }
}

pub fn display_json_rusticata(any: Box<dyn Any>) {
    let results = any.downcast::<Value>().expect("Plugin result is not JSON");
    info!("Rusticata:");
    if let Some(map) = results.as_object() {
        for (flow_id, m) in map {
            info!("  Flow {}:", flow_id);
            let m = m.as_object().unwrap();
            for (k, v) in m {
                info!("    {}: {}", k, v);
            }
        }
    }
}

pub fn display_json_tlsstats(any: Box<dyn Any>) {
    let results = any.downcast::<Value>().expect("Plugin result is not JSON");
    info!("TLS Stats:");
    if let Some(map) = results.as_object() {
        for (k, v) in map {
            info!("  {}: {}", k, v);
        }
    }
}

pub fn display_generic(p: &mut dyn Plugin, any: Box<dyn Any>) {
    if let Ok(v) = any.downcast::<Value>() {
        //
        let s = serde_json::to_string_pretty(&v).unwrap();
        info!("{}: {}", p.name(), s);
    } else {
        warn!("{}: result has unknown type", p.name());
    }
}
