use crate::packet_info::PacketInfo;
use crate::plugin::*;
use libpcap_tools::{Packet, ThreeTuple};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Shorthand definition for wrapped plugin
pub type SafePlugin = Arc<Mutex<Plugin>>;
/// Unique identifier for a plugin instance
pub type PluginID = usize;

#[macro_export]
macro_rules! build_safeplugin {
    ($p:expr) => {
        ::std::sync::Arc::new(::std::sync::Mutex::new($p))
    };
}

#[derive(Default, Clone)]
pub struct PluginRegistry {
    plugins_l2: Vec<SafePlugin>,
    plugins_ethertype_ipv4: Vec<SafePlugin>,
    plugins_ethertype_ipv6: Vec<SafePlugin>,
    // OSI 3: network layer protocol (IPv4, IPv6, etc.)
    plugins_ethertype: HashMap<u16, Vec<SafePlugin>>,
    // plugins registered for all network layer protocols
    plugins_ethertype_all: Vec<SafePlugin>,
    // OSI 4: Transport layer (TCP, UDP, etc.)
    // Note: fixed-size (256)
    plugins_transport: Vec<Vec<SafePlugin>>,
    // plugins registered for all transport layer protocols
    plugins_transport_all: Vec<SafePlugin>,
    plugins_all: Vec<SafePlugin>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        let mut v = Vec::with_capacity(256);
        for _ in 0..256 {
            v.push(Vec::new());
        }
        PluginRegistry {
            plugins_transport: v,
            ..PluginRegistry::default()
        }
    }

    pub fn num_plugins(&self) -> usize {
        self.plugins_all.len()
    }

    pub fn add_plugin(&mut self, plugin: SafePlugin) -> PluginID {
        let id = self.plugins_all.len();
        self.plugins_all.push(plugin);
        id
    }

    pub fn register_l2(&mut self, plugin: SafePlugin) {
        self.plugins_l2.push(plugin);
    }

    pub fn register_ethertype(&mut self, ethertype: u16, plugin: SafePlugin) {
        if ethertype == ETHERTYPE_IPV4 {
            self.plugins_ethertype_ipv4.push(plugin);
        } else if ethertype == ETHERTYPE_IPV6 {
            self.plugins_ethertype_ipv6.push(plugin);
        } else {
            let l = &mut self
                .plugins_ethertype
                .entry(ethertype)
                .or_insert_with(|| Vec::new());
            l.push(plugin);
        }
    }

    pub fn register_ethertype_all(&mut self, plugin: SafePlugin) {
        self.plugins_ethertype_all.push(plugin);
    }

    pub fn register_transport_layer(&mut self, proto: u8, plugin: SafePlugin) {
        let l = &mut self.plugins_transport[proto as usize];
        l.push(plugin);
    }

    pub fn register_transport_layer_all(&mut self, plugin: SafePlugin) {
        self.plugins_transport_all.push(plugin);
    }

    pub fn run_plugins_l2(&self, packet: &Packet, data: &[u8]) {
        for p in &self.plugins_l2 {
            let _ = p.lock().unwrap().handle_l2(&packet, &data);
        }
    }

    pub fn run_plugins_ethertype(
        &self,
        packet: &Packet,
        ethertype: u16,
        three_tuple: &ThreeTuple,
        data: &[u8],
    ) {
        if ethertype == ETHERTYPE_IPV4 {
            for p in &self.plugins_ethertype_ipv4 {
                let _ = p
                    .lock()
                    .unwrap()
                    .handle_l3(packet, data, ethertype, three_tuple);
            }
        } else if ethertype == ETHERTYPE_IPV6 {
            for p in &self.plugins_ethertype_ipv6 {
                let _ = p
                    .lock()
                    .unwrap()
                    .handle_l3(packet, data, ethertype, three_tuple);
            }
        } else {
            self.plugins_ethertype.get(&ethertype).map(|l| {
                for p in &*l {
                    let _ = p
                        .lock()
                        .unwrap()
                        .handle_l3(packet, data, ethertype, three_tuple);
                }
            });
        }
        for p in &self.plugins_ethertype_all {
            let _ = p
                .lock()
                .unwrap()
                .handle_l3(packet, data, ethertype, three_tuple);
        }
    }

    pub fn run_plugins_transport(&self, proto: u8, packet: &Packet, pinfo: &PacketInfo) {
        let l = &self.plugins_transport[proto as usize];
        for p in &*l {
            let _ = p.lock().unwrap().handle_l4(&packet, &pinfo);
        }
        for p in &self.plugins_transport_all {
            let _ = p.lock().unwrap().handle_l4(&packet, &pinfo);
        }
    }

    pub fn run_plugins<F, P>(&self, mut predicate: P, mut f: F)
    where
        F: FnMut(&mut Plugin) -> (),
        P: FnMut(&Plugin) -> bool,
    {
        self.plugins_all.iter().for_each(|p| {
            let mut p = p.lock().unwrap();
            if predicate(&*p) {
                // debug!("Running callback for plugin {}", p.name());
                f(&mut *p);
            }
        });
    }
}
