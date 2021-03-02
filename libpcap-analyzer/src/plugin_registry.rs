// use crate::packet_info::PacketInfo;
use crate::plugin::*;
// use libpcap_tools::{Packet, ThreeTuple};
use multimap::MultiMap;
// use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Shorthand definition for wrapped plugin
pub type SafePlugin = Arc<Mutex<dyn Plugin>>;
/// Unique identifier for a plugin instance
pub type PluginID = usize;

#[macro_export]
macro_rules! build_safeplugin {
    ($p:expr) => {
        ::std::sync::Arc::new(::std::sync::Mutex::new($p))
    };
}

#[derive(Clone, Eq, PartialEq, Hash)]
pub struct PluginInfo {
    pub layer: u8,
    pub layer_filter: u16,
}

#[derive(Default)]
pub struct PluginRegistry {
    // plugins_l2: Vec<SafePlugin>,
    // plugins_ethertype_ipv4: Vec<SafePlugin>,
    // plugins_ethertype_ipv6: Vec<SafePlugin>,
    // // OSI 3: network layer protocol (IPv4, IPv6, etc.)
    // plugins_ethertype: HashMap<u16, Vec<SafePlugin>>,
    // // plugins registered for all network layer protocols
    // plugins_ethertype_all: Vec<SafePlugin>,
    // // OSI 4: Transport layer (TCP, UDP, etc.)
    // // Note: fixed-size (256)
    // plugins_transport: Vec<Vec<SafePlugin>>,
    // // plugins registered for all transport layer protocols
    // plugins_transport_all: Vec<SafePlugin>,
    plugins_all: Vec<SafePlugin>,

    plugins: MultiMap<PluginInfo, SafePlugin>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        // let mut v = Vec::with_capacity(256);
        // for _ in 0..256 {
        //     v.push(Vec::new());
        // }
        // PluginRegistry {
        //     plugins_transport: v,
        //     ..PluginRegistry::default()
        // }
        PluginRegistry::default()
    }

    /// Return the count of different plugins
    ///
    /// A plugin can be registered for several layers, but it will count as one.
    pub fn num_plugins(&self) -> usize {
        self.plugins_all.len()
    }

    /// Add a plugin to the registry, and return the identifier
    pub fn add_plugin(&mut self, plugin: SafePlugin) -> PluginID {
        let id = self.plugins_all.len();
        self.plugins_all.push(plugin);
        id
    }

    // pub fn register_l2(&mut self, plugin: SafePlugin) {
    //     self.plugins_l2.push(plugin);
    // }

    // pub fn register_ethertype(&mut self, ethertype: u16, plugin: SafePlugin) {
    //     if ethertype == ETHERTYPE_IPV4 {
    //         self.plugins_ethertype_ipv4.push(plugin);
    //     } else if ethertype == ETHERTYPE_IPV6 {
    //         self.plugins_ethertype_ipv6.push(plugin);
    //     } else {
    //         let l = &mut self
    //             .plugins_ethertype
    //             .entry(ethertype)
    //             .or_insert_with(Vec::new);
    //         l.push(plugin);
    //     }
    // }

    // pub fn register_ethertype_all(&mut self, plugin: SafePlugin) {
    //     self.plugins_ethertype_all.push(plugin);
    // }

    // pub fn register_transport_layer(&mut self, proto: u8, plugin: SafePlugin) {
    //     let l = &mut self.plugins_transport[proto as usize];
    //     l.push(plugin);
    // }

    // pub fn register_transport_layer_all(&mut self, plugin: SafePlugin) {
    //     self.plugins_transport_all.push(plugin);
    // }

    // pub fn run_plugins_l2(&self, packet: &Packet, data: &[u8]) {
    //     for p in &self.plugins_l2 {
    //         p.lock().unwrap().handle_l2(&packet, &data);
    //     }
    // }

    // pub fn run_plugins_ethertype(
    //     &self,
    //     packet: &Packet,
    //     ethertype: u16,
    //     three_tuple: &ThreeTuple,
    //     data: &[u8],
    // ) {
    //     if ethertype == ETHERTYPE_IPV4 {
    //         for p in &self.plugins_ethertype_ipv4 {
    //             p.lock()
    //                 .unwrap()
    //                 .handle_l3(packet, data, ethertype, three_tuple);
    //         }
    //     } else if ethertype == ETHERTYPE_IPV6 {
    //         for p in &self.plugins_ethertype_ipv6 {
    //             p.lock()
    //                 .unwrap()
    //                 .handle_l3(packet, data, ethertype, three_tuple);
    //         }
    //     } else if let Some(l) = self.plugins_ethertype.get(&ethertype) {
    //         for p in &*l {
    //             p.lock()
    //                 .unwrap()
    //                 .handle_l3(packet, data, ethertype, three_tuple);
    //         }
    //     }
    //     for p in &self.plugins_ethertype_all {
    //         p.lock()
    //             .unwrap()
    //             .handle_l3(packet, data, ethertype, three_tuple);
    //     }
    // }

    // pub fn run_plugins_transport(&self, proto: u8, packet: &Packet, pinfo: &PacketInfo) {
    //     let l = &self.plugins_transport[proto as usize];
    //     for p in &*l {
    //         p.lock().unwrap().handle_l4(&packet, &pinfo);
    //     }
    //     for p in &self.plugins_transport_all {
    //         p.lock().unwrap().handle_l4(&packet, &pinfo);
    //     }
    // }

    /// Run function `F` on all known plugins (registered or not) matching `P`
    pub fn run_plugins<F, P>(&self, mut predicate: P, mut f: F)
    where
        F: FnMut(&mut dyn Plugin),
        P: FnMut(&dyn Plugin) -> bool,
    {
        self.plugins_all.iter().for_each(|p| {
            let mut p = p.lock().unwrap();
            if predicate(&*p) {
                // debug!("Running callback for plugin {}", p.name());
                f(&mut *p);
            }
        });
    }

    /// Register a layer for analysis, for the identified plugin
    ///
    /// `layer_filter` is a filter on the value relative to the layer: for L3,
    /// use for ex. ETHERNET_IPV4, for L4, TRANSPORT_TCP, etc.
    /// Special value `0` for `layer_filter` means all possible values.
    pub fn register_layer(
        &mut self,
        layer: u8,
        layer_filter: u16,
        plugin_id: PluginID,
    ) -> Result<(), &'static str> {
        if plugin_id >= self.plugins_all.len() {
            return Err("Invalid Plugin ID");
        }
        trace!(
            "registering plugin for layer={} filter=0x{:04x}",
            layer,
            layer_filter
        );
        let plugin = &self.plugins_all[plugin_id];
        let plugin_info = PluginInfo {
            layer,
            layer_filter,
        };
        self.plugins.insert(plugin_info, plugin.clone());
        Ok(())
    }

    /// Get plugins matching the given `layer` and `layer_filter`
    pub fn get_plugins_for_layer(&self, layer: u8, layer_filter: u16) -> Option<&Vec<SafePlugin>> {
        let plugin_info = PluginInfo {
            layer,
            layer_filter,
        };
        self.plugins.get_vec(&plugin_info)
    }

    /// Return an iterator on registered plugins
    ///
    /// The same plugin instance can be present multiple times, if registered with different `PluginInfo`
    /// (for ex. layer filters).
    pub fn iter_registered_plugins(&self) -> impl Iterator<Item = (&PluginInfo, &SafePlugin)> {
        self.plugins.iter()
    }

    /// Return an iterator on all known plugins
    ///
    /// Known plugins are plugins present in the registry (registered or not for layers)
    pub fn iter_plugins(&self) -> impl Iterator<Item = &SafePlugin> {
        self.plugins_all.iter()
    }
}
