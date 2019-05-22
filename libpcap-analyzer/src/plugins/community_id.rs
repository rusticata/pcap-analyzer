//! Plugin to build Community ID Flow Hash
//! See https://github.com/corelight/community-id-spec

use libpcap_tools::Config;
use pcap_parser::Packet;

use super::Plugin;
use crate::packet_data::PacketData;
use crate::plugin::PLUGIN_L4;
use base64;
use libpcap_tools::FiveTuple;
use sha1::Sha1;
use std::net::IpAddr;

#[derive(Default)]
pub struct CommunityID {
    seed: u16,
}

pub struct CommunityIDBuilder;

impl crate::plugin::PluginBuilder for CommunityIDBuilder {
    fn name(&self) -> &'static str { "$builder" }
    fn build(&self, config:&Config) -> Vec<Box<Plugin>> {
        let seed = config.get_usize("plugin.community_id.seed").unwrap_or(0) as u16;
        let plugin = CommunityID{ seed };
        vec![Box::new(plugin)]
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

    fn handle_l4(&mut self, _packet: &Packet, pdata: &PacketData) {
        debug!("five_tuple: {}", pdata.five_tuple);
        let hash = hash_community_id(&pdata.five_tuple, pdata.l4_type, self.seed);
        debug!("flow community ID: {}", hash);
    }
}
