//! Plugin to build Community ID Flow Hash
//! See https://github.com/corelight/community-id-spec

use crate::output;
use crate::plugin_registry::PluginRegistry;
use libpcap_tools::{Config, FlowID};

use crate::plugin::{Plugin, PluginBuilderError, PluginResult};
use crate::packet_info::PacketInfo;
use crate::plugin::PLUGIN_L4;
use base64;
use indexmap::IndexMap;
use libpcap_tools::{FiveTuple, Packet};
use serde_json::json;
use sha1::Sha1;
use std::net::IpAddr;

#[derive(Default)]
pub struct CommunityID {
    seed: u16,
    ids: IndexMap<FlowID, String>,
    output_dir: String,
}

pub struct CommunityIDBuilder;

impl crate::plugin::PluginBuilder for CommunityIDBuilder {
    fn name(&self) -> &'static str { "CommunityIDBuilder" }
    fn build(&self, registry:&mut PluginRegistry, config:&Config) -> Result<(), PluginBuilderError> {
        let seed = config.get_usize("plugin.community_id.seed").unwrap_or(0) as u16;
        let output_dir = output::get_output_dir(config).to_owned();
        let plugin = CommunityID{
            seed,
            ids:IndexMap::new(),
            output_dir
        };
        let safe_p = build_safeplugin!(plugin);
        let id = registry.add_plugin(safe_p);
        registry.register_layer(4, 0, id)?;
        Ok(())
    }
}

#[inline]
fn update(m: &mut Sha1, d: &[u8]) {
    // debug!("update: {:x?}", d);
    m.update(d);
}

#[inline]
fn is_lt(addr1: IpAddr, addr2: IpAddr, port1: u16, port2: u16) -> bool {
    addr1.lt(&addr2) || (addr1.eq(&addr2) && port1 < port2)
}

fn hash_community_id(five_tuple: &FiveTuple, l4_type: u8, seed: u16) -> String {
    let community_id_version = 1;
    let do_base64 = true;
    let padbyte = 0;
    let (a1, a2, p1, p2) = (
        five_tuple.src,
        five_tuple.dst,
        five_tuple.src_port,
        five_tuple.dst_port,
    );
    let (a1, a2, p1, p2) = if is_lt(a1, a2, p1, p2) {
        (a1, a2, p1, p2)
    } else {
        (a2, a1, p2, p1)
    };
    let mut m = Sha1::new();
    update(&mut m, &seed.to_be_bytes());
    match a1 {
        IpAddr::V4(v4) => update(&mut m, &v4.octets()),
        IpAddr::V6(v6) => update(&mut m, &v6.octets()),
    }
    match a2 {
        IpAddr::V4(v4) => update(&mut m, &v4.octets()),
        IpAddr::V6(v6) => update(&mut m, &v6.octets()),
    }
    update(&mut m, &[five_tuple.proto]);
    update(&mut m, &[padbyte]);
    match l4_type {
        1 | 6 | 17 => {
            update(&mut m, &p1.to_be_bytes());
            update(&mut m, &p2.to_be_bytes());
        }
        _ => (),
    }
    let digest = if do_base64 {
        base64::encode(&m.digest().bytes())
    } else {
        m.hexdigest()
    };
    format!("{}:{}", community_id_version, digest)
}

impl Plugin for CommunityID {
    fn name(&self) -> &'static str {
        "CommunityID"
    }
    fn plugin_type(&self) -> u16 {
        PLUGIN_L4
    }

    fn handle_layer_transport<'s, 'i>(
        &'s mut self,
        _packet: &'s Packet,
        pinfo: &PacketInfo,
    ) -> PluginResult<'i> {
        if let Some(flow) = pinfo.flow {
            let hash = hash_community_id(&pinfo.five_tuple, pinfo.l4_type, self.seed);
            self.ids.insert(flow.flow_id, hash);
        }
        PluginResult::None
    }

    fn post_process(&mut self) {
        self.ids.sort_keys();
        info!("Community IDs:");
        for (t5, id) in self.ids.iter() {
            info!("    {}: {}", t5, id);
        }
        let js = json!({"community_ids:": self.ids});
        let file = output::create_file(&self.output_dir, "community-ids.json").expect("Cannot create output file");
        serde_json::to_writer(file, &js).unwrap();
    }
}
