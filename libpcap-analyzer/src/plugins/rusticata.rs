use pcap_parser::Packet;

use super::Plugin;
use crate::default_plugin_builder;
use crate::packet_data::PacketData;
use crate::plugin::PLUGIN_L4;
use libpcap_tools::FlowID;

use std::collections::HashMap;

use rusticata::*;

#[derive(Default)]
pub struct Rusticata {
    builder_map: HashMap<&'static str, Box<RBuilder>>,

    flow_parsers: HashMap<FlowID, Box<RParser>>,
}

default_plugin_builder!(Rusticata, RusticataBuilder);

impl Plugin for Rusticata {
    fn name(&self) -> &'static str { "Rusticata" }
    fn plugin_type(&self) -> u16 { PLUGIN_L4 }

    fn pre_process(&mut self) {
        let mut m : HashMap<&'static str, Box<RBuilder>> = HashMap::new();
        m.insert("dns_udp", Box::new(DnsUDPBuilder{}) as Box<_>);
        m.insert("dns_tcp", Box::new(DnsTCPBuilder{}) as Box<_>);
        m.insert("ikev2", Box::new(IPsecBuilder{}) as Box<_>);
        m.insert("ikev2_natt", Box::new(IPsecNatTBuilder{}) as Box<_>);
        m.insert("kerberos_tcp", Box::new(KerberosTCPBuilder{}) as Box<_>);
        m.insert("kerberos_udp", Box::new(KerberosUDPBuilder{}) as Box<_>);
        m.insert("ntp", Box::new(NTPBuilder{}) as Box<_>);
        m.insert("openvpn_tcp", Box::new(OpenVPNTCPBuilder{}) as Box<_>);
        m.insert("openvpn_udp", Box::new(OpenVPNUDPBuilder{}) as Box<_>);
        m.insert("radius", Box::new(RadiusBuilder{}) as Box<_>);
        m.insert("snmpv1", Box::new(SNMPv1Builder{}) as Box<_>);
        m.insert("snmpv2c", Box::new(SNMPv2cBuilder{}) as Box<_>);
        m.insert("snmpv3", Box::new(SNMPv3Builder{}) as Box<_>);
        m.insert("ssh", Box::new(SSHBuilder{}) as Box<_>);
        m.insert("tls", Box::new(TLSBuilder{}) as Box<_>);
        self.builder_map = m;
    }

    fn handle_l4(&mut self, _packet:&Packet, pdata: &PacketData) {
        let flow_id = match pdata.flow {
                Some(f) => f.flow_id,
                None => {
                    info!("No flow");
                    return;
                }
        };
        pdata.l4_payload.map(|d| {
            if d.is_empty() { return; }
            let parser = {
                // check if we already have a parser
                if let Some(parser) = self.flow_parsers.get_mut(&flow_id) {
                    parser
                } else {
                    // no parser, try to probe protocol
                    let maybe_s = probe(d, pdata.l4_type);
                    if let Some(parser_name) = maybe_s {
                        debug!("Protocol recognized as {}", parser_name);
                        if let Some(builder) = self.builder_map.get( (&parser_name) as &str) {
                            self.flow_parsers.insert(flow_id, builder.new());
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
            let direction = if pdata.to_server { STREAM_TOSERVER } else { STREAM_TOCLIENT };
            let res = parser.parse(d, direction);
            if res == R_STATUS_FAIL {
                warn!("rusticata: parser failed");
                // remove or disable parser for flow?
            }
        });
    }
}

fn probe(i:&[u8], l4_type: u8) -> Option<String> {
    if l4_type == 6 {
        if dns_probe_tcp(i) { return Some("dns_tcp".to_string()); }
        if tls_probe(i) { return Some("tls".to_string()); }
        if ssh_probe(i) { return Some("ssh".to_string()); }
        if kerberos_probe_tcp(i) { return Some("kerberos_tcp".to_string()); }
        if openvpn_tcp_probe(i) { return Some("openvpn_tcp".to_string()); }
    }
    if l4_type == 17 {
        if dns_probe_udp(i) { return Some("dns_udp".to_string()); }
        if ipsec_probe(i) { return Some("ikev2".to_string()); }
        if ikev2_natt_probe(i) { return Some("ikev2_natt".to_string()); }
        if kerberos_probe_udp(i) { return Some("kerberos_udp".to_string()); }
        if ntp_probe(i) { return Some("ntp".to_string()); }
        if openvpn_udp_probe(i) { return Some("openvpn_udp".to_string()); }
        if snmpv1_probe(i) { return Some("snmpv1".to_string()); }
        if snmpv2c_probe(i) { return Some("snmpv2c".to_string()); }
        if snmpv3_probe(i) { return Some("snmpv3".to_string()); }
    }
    None
}
