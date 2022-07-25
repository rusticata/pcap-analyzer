use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::ipv6::Ipv6Packet;

use crate::filters::ipv6_utils;

pub fn is_ipv4_first_fragment(payload: &[u8]) -> Result<bool, String> {
    let ipv4_packet = Ipv4Packet::new(payload).ok_or("Expected Ipv4 packet but not found")?;
    let flags = ipv4_packet.get_flags();
    let fragment_offset = ipv4_packet.get_fragment_offset();

    let mf_flag = flags & 1;

    Ok(mf_flag == 1 && fragment_offset == 0)
}

pub fn is_ipv6_first_fragment(payload: &[u8]) -> Result<bool, String> {
    let ipv6_packet = Ipv6Packet::new(payload).ok_or("Expected Ipv6 packet but not found")?;
    let (fragment_packet_option, _l4_proto, _payload) =
        ipv6_utils::get_fragment_packet_option_l4_protol4_payload(payload, &ipv6_packet)?;
    match fragment_packet_option {
        Some(fragment_packet) => Ok(fragment_packet.get_fragment_offset() == 0),
        None => Ok(false),
    }
}
