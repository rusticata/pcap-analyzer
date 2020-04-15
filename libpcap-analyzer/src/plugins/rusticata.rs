use crate::default_plugin_builder;
use crate::packet_info::PacketInfo;
use crate::plugin::{Plugin, PluginResult, PLUGIN_L4};
use libpcap_tools::{FlowID, Packet};

use std::collections::{BTreeMap, HashMap};

use rusticata::*;

type ProbeFn = fn(&[u8]) -> bool;

const PROBE_TCP: u32 = 0x0600_0000;
const PROBE_UDP: u32 = 0x1100_0000;

// This enum defines the order TCP probes will be applied
#[repr(u16)]
enum TcpProbeOrder {
    Dns,
    Tls,
    Ssh,
    Kerberos,
    OpenVpn,
}

// This enum defines the order UDP probes will be applied
#[repr(u16)]
#[allow(dead_code)]
enum UdpProbeOrder {
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
        add_parser!(tcp "dns_tcp", TcpProbeOrder::Dns, DnsTCPBuilder {}, dns_probe_tcp, builder_map, probe_map);
        add_parser!(tcp "kerberos_tcp", TcpProbeOrder::Kerberos, KerberosTCPBuilder {}, kerberos_probe_tcp, builder_map, probe_map);
        add_parser!(udp "openvpn_tcp", TcpProbeOrder::OpenVpn, OpenVPNTCPBuilder {}, openvpn_tcp_probe, builder_map, probe_map);
        add_parser!(tcp "ssh", TcpProbeOrder::Ssh, SSHBuilder {}, ssh_probe, builder_map, probe_map);
        add_parser!(tcp "tls", TcpProbeOrder::Tls, TLSBuilder {}, tls_probe, builder_map, probe_map);
        // UDP
        add_parser!(udp "dhcp", UdpProbeOrder::Dhcp, DHCPBuilder {}, dhcp_probe, builder_map, probe_map);
        add_parser!(udp "dns_udp", UdpProbeOrder::Dns, DnsUDPBuilder {}, dns_probe_udp, builder_map, probe_map);
        add_parser!(udp "ikev2", UdpProbeOrder::Ikev2, IPsecBuilder {}, ipsec_probe, builder_map, probe_map);
        add_parser!(udp "ikev2_natt", UdpProbeOrder::Ikev2Natt, IPsecNatTBuilder {}, ikev2_natt_probe, builder_map, probe_map);
        add_parser!(udp "kerberos_udp", UdpProbeOrder::Kerberos, KerberosUDPBuilder {}, kerberos_probe_udp, builder_map, probe_map);
        add_parser!(udp "ntp", UdpProbeOrder::Ntp, NTPBuilder {}, ntp_probe, builder_map, probe_map);
        add_parser!(udp "openvpn_udp", UdpProbeOrder::OpenVpn, OpenVPNUDPBuilder {}, openvpn_udp_probe, builder_map, probe_map);
        // add_parser!(udp "radius", UdpProbeOrder::Radius, RadiusBuilder {}, radius_probe, builder_map, probe_map);
        add_parser!(udp "snmpv1", UdpProbeOrder::Snmpv1, SNMPv1Builder {}, snmpv1_probe, builder_map, probe_map);
        add_parser!(udp "snmpv2c", UdpProbeOrder::Snmpv2c, SNMPv2cBuilder {}, snmpv2c_probe, builder_map, probe_map);
        add_parser!(udp "snmpv3", UdpProbeOrder::Snmpv3, SNMPv3Builder {}, snmpv3_probe, builder_map, probe_map);

        self.builder_map = builder_map;
        self.probe_map = probe_map;
    }

    fn handle_layer_transport<'s, 'i>(
        &'s mut self,
        _packet: &'s Packet,
        pinfo: &PacketInfo,
    ) -> PluginResult<'i> {
        let flow_id = match pinfo.flow {
            Some(f) => f.flow_id,
            None => {
                info!("No flow");
                return PluginResult::None;
            }
        };
        if let Some(d) = pinfo.l4_payload {
            if d.is_empty() {
                return PluginResult::None;
            }
            let parser = {
                // check if we already have a parser
                if let Some(parser) = self.flow_parsers.get_mut(&flow_id) {
                    parser
                } else {
                    // no parser, try to probe protocol
                    let maybe_s = self.probe(d, pinfo.l4_type);
                    if let Some(parser_name) = maybe_s {
                        debug!("Protocol recognized as {}", parser_name);
                        // warn!("Protocol recognized as {} (5t: {})", parser_name, pinfo.five_tuple);
                        if let Some(builder) = self.builder_map.get((&parser_name) as &str) {
                            self.flow_parsers.insert(flow_id, builder.build());
                            self.flow_parsers.get_mut(&flow_id).unwrap()
                        } else {
                            warn!("Could not build parser for proto {}", parser_name);
                            return PluginResult::None;
                        }
                    } else {
                        // proto not recognized
                        return PluginResult::None;
                    }
                }
            };
            let direction = if pinfo.to_server {
                STREAM_TOSERVER
            } else {
                STREAM_TOCLIENT
            };
            let res = parser.parse(d, direction);
            if res == R_STATUS_FAIL {
                warn!(
                    "rusticata: parser failed (idx={}) (5t: {})",
                    pinfo.pcap_index, pinfo.five_tuple
                );
                // remove or disable parser for flow?
                let _ = self.flow_parsers.remove(&flow_id);
            }
        }
        PluginResult::None
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
