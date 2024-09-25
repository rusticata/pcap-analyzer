use crate::layers::NetworkLayerType;
use crate::plugin::{Plugin, PluginBuilderError, PluginResult, PLUGIN_L3};
use crate::plugin_registry::PluginRegistry;
use libpcap_tools::{Config, Packet, ThreeTuple};
use ospf_parser::*;

pub struct OspfLog {}

impl OspfLog {
    fn log_packet_v2(&self, ospf: &Ospfv2Packet) {
        // debug!("OSPFv2: {:?}", ospf);
        match ospf {
            Ospfv2Packet::Hello(p) => {
                debug!(
                    "Hello v2 src={} priority={} designated_router={}",
                    p.header.source_router(),
                    p.router_priority,
                    p.designated_router(),
                );
            }
            Ospfv2Packet::DatabaseDescription(p) => {
                debug!(
                    "DB Description v2 src={} interface MTU={}",
                    p.header.source_router(),
                    p.if_mtu
                );
                for lsa_h in &p.lsa_headers {
                    self.log_lsa_header(lsa_h);
                }
                // missing: options, db description (init, more, master, ...), DD sequence number
            }
            Ospfv2Packet::LinkStateRequest(p) => {
                debug!("LS Request v2 src={}", p.header.source_router());
                for lsa in &p.requests {
                    debug!(
                        "    LSA Req: ls_type={} ls_id={} adv_router={}",
                        lsa.link_state_type,
                        lsa.link_state_id(),
                        lsa.advertising_router()
                    );
                }
            }
            Ospfv2Packet::LinkStateUpdate(p) => {
                debug!("LS Update v2 src={}", p.header.source_router());
                for lsa in &p.lsa {
                    self.log_lsa(lsa);
                }
            }
            Ospfv2Packet::LinkStateAcknowledgment(p) => {
                debug!("LS Ack v2 src={}", p.header.source_router());
                for lsa_h in &p.lsa_headers {
                    self.log_lsa_header(lsa_h);
                }
            }
        }
    }

    fn log_packet_v3(&self, ospf: &Ospfv3Packet) {
        // debug!("OSPFv3: {:?}", ospf);
        match ospf {
            Ospfv3Packet::Hello(p) => {
                debug!(
                    "Hello v3 src={} priority={} designated_router={}",
                    p.header.source_router(),
                    p.router_priority,
                    p.designated_router(),
                );
            }
            Ospfv3Packet::DatabaseDescription(p) => {
                debug!(
                    "DB Description v3 src={} interface MTU={}",
                    p.header.source_router(),
                    p.if_mtu
                );
                for lsa_h in &p.lsa_headers {
                    self.log_lsa_v3_header(lsa_h);
                }
                // missing: options, db description (init, more, master, ...), DD sequence number
            }
            Ospfv3Packet::LinkStateRequest(p) => {
                debug!("LS Request v3 src={}", p.header.source_router());
                for lsa in &p.requests {
                    debug!(
                        "    LSA Req: ls_type={} ls_id={} adv_router={}",
                        lsa.link_state_type,
                        lsa.link_state_id(),
                        lsa.advertising_router()
                    );
                }
            }
            Ospfv3Packet::LinkStateUpdate(p) => {
                debug!("LS Update v3 src={}", p.header.source_router());
                for lsa in &p.lsa {
                    self.log_lsa_v3(lsa);
                }
            }
            Ospfv3Packet::LinkStateAcknowledgment(p) => {
                debug!("LS Ack v3 src={}", p.header.source_router());
                for lsa_h in &p.lsa_headers {
                    self.log_lsa_v3_header(lsa_h);
                }
            }
        }
    }

    fn log_lsa(&self, lsa: &OspfLinkStateAdvertisement) {
        match lsa {
            OspfLinkStateAdvertisement::RouterLinks(l) => {
                debug!("    RouterLinks #={}", l.num_links);
                for lnk in &l.links {
                    debug!(
                        "        link type={} id={} data={} metric={}",
                        lnk.link_type,
                        lnk.link_id(),
                        lnk.link_data(),
                        lnk.tos_0_metric,
                    );
                }
            }
            OspfLinkStateAdvertisement::NetworkLinks(l) => {
                debug!("    NetworkLinks mask={}", l.network_mask());
            }
            OspfLinkStateAdvertisement::SummaryLinkIpNetwork(l)
            | OspfLinkStateAdvertisement::SummaryLinkAsbr(l) => {
                debug!(
                    "    Summary Link type={} netmask={}",
                    l.header.link_state_type.0,
                    l.network_mask()
                );
                for route in &l.tos_routes {
                    debug!(
                        "        Tos route tos={} metric={}",
                        route.tos, route.metric,
                    );
                }
            }
            OspfLinkStateAdvertisement::ASExternalLink(l) => {
                debug!(
                    "    AS External Link fwd={} netmask={} metric={}",
                    l.forwarding_address(),
                    l.network_mask(),
                    l.metric
                );
                for route in &l.tos_list {
                    debug!(
                        "        External tos route tos={} metric={} fwd={} tag={}",
                        route.tos,
                        route.metric,
                        route.forwarding_address(),
                        route.external_route_tag,
                    );
                }
            }
            OspfLinkStateAdvertisement::NSSAASExternal(l) => {
                debug!(
                    "    NSSA AS External Link fwd={} netmask={} metric={}",
                    l.forwarding_address(),
                    l.network_mask(),
                    l.metric
                );
                for route in &l.tos_list {
                    debug!(
                        "        External tos route tos={} metric={} fwd={} tag={}",
                        route.tos,
                        route.metric,
                        route.forwarding_address(),
                        route.external_route_tag,
                    );
                }
            }
            OspfLinkStateAdvertisement::OpaqueLinkLocalScope(_lsa) => {
                debug!("    Opaque LinkLocalScope");
            }
            OspfLinkStateAdvertisement::OpaqueAreaLocalScope(_lsa) => {
                debug!("    Opaque AreaLocalScope");
            }
            OspfLinkStateAdvertisement::OpaqueASWideScope(_lsa) => {
                debug!("    Opaque ASWideScope");
            }
        }
    }

    fn log_lsa_v3(&self, lsa: &Ospfv3LinkStateAdvertisement) {
        match lsa {
            Ospfv3LinkStateAdvertisement::Router(l) => {
                debug!("    RouterLSA #={}", l.links.len());
                for lnk in &l.links {
                    debug!(
                        "        link type={} id={} metric={}",
                        lnk.link_type, lnk.interface_id, lnk.metric,
                    );
                }
            }
            Ospfv3LinkStateAdvertisement::Network(l) => {
                debug!("    NetworkLSA #routers={}", l.attached_routers.len());
            }
            Ospfv3LinkStateAdvertisement::InterAreaPrefix(l) => {
                debug!(
                    "    InterAreaPrefixLSA metric={} prefix={:02x?}/{}",
                    l.metric, &l.prefix.address_prefix, l.prefix.prefix_length
                );
            }
            Ospfv3LinkStateAdvertisement::InterAreaRouter(l) => {
                debug!(
                    "    InterAreaRouterLSA metric={} destination_router_id={}",
                    l.metric, l.destination_router_id
                );
            }
            Ospfv3LinkStateAdvertisement::ASExternal(l) | Ospfv3LinkStateAdvertisement::NSSA(l) => {
                debug!("    type={} metric={}", l.header.link_state_type, l.metric);
            }
            Ospfv3LinkStateAdvertisement::Link(l) => {
                debug!(
                    "    LinksLSA link_local_interface_address={:x?} #prefixes={}",
                    &l.link_local_interface_address, l.num_prefixes,
                );
                for prefix in &l.address_prefixes {
                    debug!(
                        "        IPv6 prefix {:02x?}/{}",
                        prefix.address_prefix, prefix.prefix_length,
                    );
                }
            }
            Ospfv3LinkStateAdvertisement::IntraAreaPrefix(l) => {
                debug!(
                    "    IntraAreaPrefixLSA referenced_ls_type={} #prefixes={}",
                    l.referenced_ls_type, l.num_prefixes,
                );
                for prefix in &l.address_prefixes {
                    debug!(
                        "        IPv6 prefix {:02x?}/{} metric={}",
                        prefix.address_prefix, prefix.prefix_length, prefix.reserved,
                    );
                }
            }
        }
    }

    fn log_lsa_header(&self, header: &OspfLinkStateAdvertisementHeader) {
        debug!(
            "    LSA header type={}, age={} ls_id={}, adv={} ",
            header.link_state_type,
            header.ls_age,
            header.link_state_id(),
            header.advertising_router(),
        );
    }

    fn log_lsa_v3_header(&self, header: &Ospfv3LinkStateAdvertisementHeader) {
        debug!(
            "    LSA v3 header type={}, age={} ls_id={}, adv={} ",
            header.link_state_type,
            header.ls_age,
            header.link_state_id(),
            header.advertising_router(),
        );
    }
}

impl Plugin for OspfLog {
    fn name(&self) -> &'static str {
        "OSPF"
    }
    fn plugin_type(&self) -> u16 {
        PLUGIN_L3
    }
    fn handle_layer_network<'s, 'i>(
        &'s mut self,
        packet: &'s Packet,
        payload: &'i [u8],
        t3: &'s ThreeTuple,
    ) -> PluginResult<'i> {
        if t3.l4_proto != 89 || payload.is_empty()
        /* OSPFIGP */
        {
            return PluginResult::None;
        }
        match payload[0] {
            2 => match parse_ospfv2_packet(payload) {
                Ok((_, ospf)) => self.log_packet_v2(&ospf),
                Err(e) => {
                    warn!(
                        "OSPFv2 packet parsing failed (idx={}): {:?}",
                        packet.pcap_index, e
                    );
                }
            },
            3 => match parse_ospfv3_packet(payload) {
                Ok((_, ospf)) => self.log_packet_v3(&ospf),
                Err(e) => {
                    warn!(
                        "OSPFv3 packet parsing failed (idx={}): {:?}",
                        packet.pcap_index, e
                    );
                }
            },
            _ => {
                warn!("Not OSPF data (invalid version {})", payload[0]);
            }
        }
        PluginResult::None
    }
}

pub struct OspfLogBuilder;

impl crate::plugin::PluginBuilder for OspfLogBuilder {
    fn name(&self) -> &'static str {
        "OspfLogBuilder"
    }
    fn build(
        &self,
        registry: &mut PluginRegistry,
        _config: &Config,
    ) -> Result<(), PluginBuilderError> {
        let plugin = OspfLog {};
        let safe_p = build_safeplugin!(plugin);
        // register for layer 3, ethertype Ipv4
        let id = registry.add_plugin(safe_p);
        registry.register_layer(3, NetworkLayerType::Ipv4 as u16, id)?;
        registry.register_layer(3, NetworkLayerType::Ipv6 as u16, id)?;
        Ok(())
    }
}
