use super::Plugin;
use crate::default_plugin_builder;
use crate::packet_info::PacketInfo;
use crate::plugin::PLUGIN_L4;
use libpcap_tools::{FlowID, Packet};

use std::collections::{BTreeMap, HashMap};

use rusticata::*;

type ProbeFn = fn(&[u8]) -> bool;

const PROBE_TCP: u32 = 0x0600;
const PROBE_UDP: u32 = 0x1100;

// This enum defines the order TCP probes will be applied
#[repr(u8)]
enum tcp_probe_order {
    Dns,
    Tls,
    Ssh,
    Kerberos,
    OpenVpn,
}

// This enum defines the order UDP probes will be applied
#[repr(u8)]
enum udp_probe_order {
    Dhcp,
    Dns,
    Ikev2,
    Ikev2Natt,
    Kerberos,
    Ntp,
    OpenVpn,
    Radius,
    Snmpv1,
    Snmpv2c,
    Snmpv3,
}

#[derive(Default)]
pub struct Rusticata {
    builder_map: HashMap<&'static str, Box<dyn RBuilder>>,
    probe_map: BTreeMap<u32, (&'static str, ProbeFn)>,

    flow_parsers: HashMap<FlowID, Box<dyn RParser>>,
}

default_plugin_builder!(Rusticata, RusticataBuilder);

macro_rules! add_parser {
    (tcp $name:expr, $pat:expr, $builder:expr, $probe:ident, $bmap:ident, $pmap:ident) => {
        $bmap.insert($name, Box::new($builder) as Box<_>);
        $pmap.insert(PROBE_TCP | ($pat as u32), ($name, $probe));
    };
    (udp $name:expr, $pat:expr, $builder:expr, $probe:ident, $bmap:ident, $pmap:ident) => {
        $bmap.insert($name, Box::new($builder) as Box<_>);
        $pmap.insert(PROBE_UDP | ($pat as u32), ($name, $probe));
    };
}

impl Plugin for Rusticata {
    fn name(&self) -> &'static str {
        "Rusticata"
    }
    fn plugin_type(&self) -> u16 {
        PLUGIN_L4
    }

    fn pre_process(&mut self) {
        let mut builder_map: HashMap<&'static str, Box<dyn RBuilder>> = HashMap::new();
        let mut probe_map: BTreeMap<u32, (&'static str, ProbeFn)> = BTreeMap::new();

        // TCP
        add_parser!(tcp "dns_tcp", tcp_probe_order::Dns, DnsTCPBuilder {}, dns_probe_tcp, builder_map, probe_map);
        add_parser!(tcp "kerberos_tcp", tcp_probe_order::Kerberos, KerberosTCPBuilder {}, kerberos_probe_tcp, builder_map, probe_map);
        add_parser!(udp "openvpn_tcp", tcp_probe_order::OpenVpn, OpenVPNTCPBuilder {}, openvpn_tcp_probe, builder_map, probe_map);
        add_parser!(tcp "ssh", tcp_probe_order::Ssh, SSHBuilder {}, ssh_probe, builder_map, probe_map);
        add_parser!(tcp "tls", tcp_probe_order::Tls, TLSBuilder {}, tls_probe, builder_map, probe_map);
        // UDP
        add_parser!(udp "dhcp", udp_probe_order::Dhcp, DHCPBuilder {}, dhcp_probe, builder_map, probe_map);
        add_parser!(udp "dns_udp", udp_probe_order::Dns, DnsUDPBuilder {}, dns_probe_udp, builder_map, probe_map);
        add_parser!(udp "ikev2", udp_probe_order::Ikev2, IPsecBuilder {}, ipsec_probe, builder_map, probe_map);
        add_parser!(udp "ikev2_natt", udp_probe_order::Ikev2Natt, IPsecNatTBuilder {}, ikev2_natt_probe, builder_map, probe_map);
        add_parser!(udp "kerberos_udp", udp_probe_order::Kerberos, KerberosUDPBuilder {}, kerberos_probe_udp, builder_map, probe_map);
        add_parser!(udp "ntp", udp_probe_order::Ntp, NTPBuilder {}, ntp_probe, builder_map, probe_map);
        add_parser!(udp "openvpn_udp", udp_probe_order::OpenVpn, OpenVPNUDPBuilder {}, openvpn_udp_probe, builder_map, probe_map);
        // add_parser!(udp "radius", udp_probe_order::Radius, RadiusBuilder {}, radius_probe, builder_map, probe_map);
        add_parser!(udp "snmpv1", udp_probe_order::Snmpv1, SNMPv1Builder {}, snmpv1_probe, builder_map, probe_map);
        add_parser!(udp "snmpv2c", udp_probe_order::Snmpv2c, SNMPv2cBuilder {}, snmpv2c_probe, builder_map, probe_map);
        add_parser!(udp "snmpv3", udp_probe_order::Snmpv3, SNMPv3Builder {}, snmpv3_probe, builder_map, probe_map);

        self.builder_map = builder_map;
        self.probe_map = probe_map;
    }

    fn handle_l4(&mut self, _packet: &Packet, pdata: &PacketInfo) {
        let flow_id = match pdata.flow {
            Some(f) => f.flow_id,
            None => {
                info!("No flow");
                return;
            }
        };
        if let Some(d) = pdata.l4_payload {
            if d.is_empty() {
                return;
            }
            let parser = {
                // check if we already have a parser
                if let Some(parser) = self.flow_parsers.get_mut(&flow_id) {
                    parser
                } else {
                    // no parser, try to probe protocol
                    let maybe_s = self.probe(d, pdata.l4_type);
                    if let Some(parser_name) = maybe_s {
                        debug!("Protocol recognized as {}", parser_name);
                        // warn!("Protocol recognized as {} (5t: {})", parser_name, pdata.five_tuple);
                        if let Some(builder) = self.builder_map.get((&parser_name) as &str) {
                            self.flow_parsers.insert(flow_id, builder.build());
                            self.flow_parsers.get_mut(&flow_id).unwrap()
                        } else {
                            warn!("Could not build parser for proto {}", parser_name);
                            return;
                        }
                    } else {
                        // proto not recognized
                        return;
                    }
                }
            };
            let direction = if pdata.to_server {
                STREAM_TOSERVER
            } else {
                STREAM_TOCLIENT
            };
            let res = parser.parse(d, direction);
            if res == R_STATUS_FAIL {
                warn!(
                    "rusticata: parser failed (idx={}) (5t: {})",
                    pdata.pcap_index, pdata.five_tuple
                );
                // remove or disable parser for flow?
                let _ = self.flow_parsers.remove(&flow_id);
            }
        }
    }

    fn post_process(&mut self) {
        for (flow_id, parser) in self.flow_parsers.iter() {
            info!("Flow: 0x{:x}", flow_id);
            for key in parser.keys() {
                info!("  [{}] => {:?}", key, parser.get(key));
            }
        }
    }
}

impl Rusticata {
    fn probe(&self, i: &[u8], l4_type: u8) -> Option<String> {
        if l4_type == 6 {
            for (_prio, (name, probe)) in
                self.probe_map.iter().filter(|(&id, _)| id & PROBE_TCP != 0)
            {
                // debug!("trying probe {}", name);
                if probe(i) {
                    trace!("probe {} MATCHED", name);
                    return Some((*name).to_string());
                }
            }
        }
        if l4_type == 17 {
            for (_prio, (name, probe)) in
                self.probe_map.iter().filter(|(&id, _)| id & PROBE_UDP != 0)
            {
                // debug!("trying probe {}", name);
                if probe(i) {
                    trace!("probe {} MATCHED", name);
                    return Some((*name).to_string());
                }
            }
        }
        None
    }
}
