use pnet_packet::ethernet::{EtherTypes, EthernetPacket};
use pnet_packet::vlan::VlanPacket;
use pnet_packet::Packet;
use pnet_packet::PrimitiveValues;

pub fn extract_callback_ethernet<D>(
    get_key_from_ipv4_l3_data: &dyn Fn(&[u8]) -> Result<D, String>,
    get_key_from_ipv6_l3_data: &dyn Fn(&[u8]) -> Result<D, String>,
    packet_data: &[u8],
) -> Result<D, String> {
    let ethernet_packet =
        EthernetPacket::new(packet_data).ok_or("Expected Ethernet packet but not found")?;
    match ethernet_packet.get_ethertype() {
        EtherTypes::Ipv4 => (get_key_from_ipv4_l3_data)(ethernet_packet.payload()),
        EtherTypes::Ipv6 => (get_key_from_ipv6_l3_data)(ethernet_packet.payload()),
        EtherTypes::Vlan => {
            // 802.11q
            let vlan_packet = VlanPacket::new(ethernet_packet.payload())
                .ok_or("Expected VLAN packet but not found")?;
            match vlan_packet.get_ethertype() {
                EtherTypes::Ipv4 => (get_key_from_ipv4_l3_data)(ethernet_packet.payload()),
                EtherTypes::Ipv6 => (get_key_from_ipv6_l3_data)(ethernet_packet.payload()),
                _ => Err(format!(
                    "Unimplemented Ethertype in 33024/802.11q: {:?}/{:x}",
                    vlan_packet.get_ethertype(),
                    vlan_packet.get_ethertype().to_primitive_values().0
                )),
            }
        }
        _ => Err(format!(
            "Unimplemented Ethertype: {:?}/{:x}",
            ethernet_packet.get_ethertype(),
            ethernet_packet.get_ethertype().to_primitive_values().0
        )),
    }
}
