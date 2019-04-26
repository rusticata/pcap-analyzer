use pcap_parser::Packet;

use super::Plugin;
use crate::default_plugin_builder;
use crate::packet_data::PacketData;
use crate::flow::FlowID;

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

    fn pre_process(&mut self) {
        let mut m : HashMap<&'static str, Box<RBuilder>> = HashMap::new();
        m.insert("ikev2", Box::new(IPsecBuilder{}) as Box<_>);
        m.insert("kerberos_probe_tcp", Box::new(KerberosTCPBuilder{}) as Box<_>);
        m.insert("kerberos_probe_udp", Box::new(KerberosUDPBuilder{}) as Box<_>);
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
        let five_tuple = &pdata.five_tuple;
        info!("BasicStats::handle_l4");
        debug!("    5t: proto {} / [{}]:{} -> [{}]:{}",
               five_tuple.proto,
               five_tuple.src,
               five_tuple.src_port,
               five_tuple.dst,
               five_tuple.dst_port);
        debug!("    to_server: {}", pdata.to_server);
        debug!("    l3_type: {}", pdata.l3_type);
        debug!("    l3_data_len: {}", pdata.l3_data.len());
        debug!("    l4_type: {}", pdata.l4_type);
        debug!("    l4_data_len: {}", pdata.l4_data.map_or(0, |d| d.len()));
        if let Some(flow) = pdata.flow {
            let five_tuple = &flow.five_tuple;
            debug!("    flow: [{}]:{} -> [{}]:{}",
                   five_tuple.src,
                   five_tuple.src_port,
                   five_tuple.dst,
                   five_tuple.dst_port);
        }
        let flow_id = match pdata.flow {
                Some(f) => f.flow_id,
                None => {
                    info!("No flow");
                    return;
                }
        };
        pdata.l4_data.map(|d| {
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
            parser.parse(d, direction);
        });
    }
}

fn probe(i:&[u8], l4_type: u8) -> Option<String> {
    if l4_type == 6 {
        if tls_probe(i) { return Some("tls".to_string()); }
        if ssh_probe(i) { return Some("ssh".to_string()); }
        if kerberos_probe_tcp(i) { return Some("kerberos_tcp".to_string()); }
        if openvpn_tcp_probe(i) { return Some("openvpn_tcp".to_string()); }
    }
    if l4_type == 17 {
        if ipsec_probe(i) { return Some("ikev2".to_string()); }
        if kerberos_probe_udp(i) { return Some("kerberos_udp".to_string()); }
        if ntp_probe(i) { return Some("ntp".to_string()); }
        if openvpn_udp_probe(i) { return Some("openvpn_udp".to_string()); }
        if snmpv1_probe(i) { return Some("snmpv1".to_string()); }
        if snmpv2c_probe(i) { return Some("snmpv2c".to_string()); }
        if snmpv3_probe(i) { return Some("snmpv3".to_string()); }
    }
    None
}
