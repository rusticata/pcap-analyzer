use log::warn;

use libpcap_tools::{Error, ParseContext};
use pnet_packet::ethernet::{EtherTypes, EthernetPacket};
use pnet_packet::vlan::VlanPacket;
use pnet_packet::Packet;
use pnet_packet::PrimitiveValues;

// TODO: find simpler solution for function parameter with genericity
pub fn extract_callback_ethernet<D, F1, F2>(
    ctx: &ParseContext,
    get_key_from_ipv4_l3_data: F1,
    get_key_from_ipv6_l3_data: F2,
    packet_data: &[u8],
) -> Result<Option<D>, Error>
where
    F1: Fn(&ParseContext, &[u8]) -> Result<D, Error>,
    F2: Fn(&ParseContext, &[u8]) -> Result<D, Error>,
{
    let ethernet_packet = EthernetPacket::new(packet_data)
        .ok_or(Error::Pnet("Expected Ethernet packet but could not parse"))?;
    match ethernet_packet.get_ethertype() {
        EtherTypes::Arp => Ok(None),
        EtherTypes::Ipv4 => Ok(Some((get_key_from_ipv4_l3_data)(
            ctx,
            ethernet_packet.payload(),
        )?)),
        EtherTypes::Ipv6 => Ok(Some((get_key_from_ipv6_l3_data)(
            ctx,
            ethernet_packet.payload(),
        )?)),
        EtherTypes::Ipx => Ok(None),
        EtherTypes::Lldp => Ok(None),
        EtherTypes::Vlan => {
            // 802.11q
            let vlan_packet = VlanPacket::new(ethernet_packet.payload())
                .ok_or(Error::Pnet("Expected VLAN packet but could not parse"))?;
            match vlan_packet.get_ethertype() {
                EtherTypes::Arp => Ok(None),
                EtherTypes::Ipv4 => Ok(Some((get_key_from_ipv4_l3_data)(
                    ctx,
                    ethernet_packet.payload(),
                )?)),
                EtherTypes::Ipv6 => Ok(Some((get_key_from_ipv6_l3_data)(
                    ctx,
                    ethernet_packet.payload(),
                )?)),
                EtherTypes::Ipx => Ok(None),
                EtherTypes::Lldp => Ok(None),
                _ => {
                    warn!(
                        "Unimplemented Ethertype in 33024/802.11q: {:?}/{:x}",
                        vlan_packet.get_ethertype(),
                        vlan_packet.get_ethertype().to_primitive_values().0
                    );
                    Err(Error::Unimplemented(
                        "Unimplemented Ethertype in 33024/802.11q",
                    ))
                }
            }
        }
        _ => {
            warn!(
                "Unimplemented Ethertype: {:?}/{:x}",
                ethernet_packet.get_ethertype(),
                ethernet_packet.get_ethertype().to_primitive_values().0
            );
            Err(Error::Unimplemented("Unimplemented Ethertype"))
        }
    }
}
