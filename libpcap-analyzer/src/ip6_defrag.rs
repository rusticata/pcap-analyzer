use pnet_macros_support::types::{u13be, u16be, u32be};
use pnet_packet::ip::IpNextHeaderProtocol;

#[derive(PartialEq)]
/// A structure enabling manipulation of on the wire packets
pub struct IPv6FragmentPacket<'p> {
    packet: ::pnet_macros_support::packet::PacketData<'p>,
}

impl<'a> IPv6FragmentPacket<'a> {
    /// Constructs a new Ipv6Packet. If the provided buffer is less than the minimum required
    /// packet size, this will return None.
    #[inline]
    pub fn new(packet: &[u8]) -> Option<IPv6FragmentPacket> {
        if packet.len() >= IPv6FragmentPacket::minimum_packet_size() {
            use ::pnet_macros_support::packet::PacketData;
            Some(IPv6FragmentPacket {
                packet: PacketData::Borrowed(packet),
            })
        } else {
            None
        }
    }
    /// The minimum size (in bytes) a packet of this type can be. It's based on the total size
    /// of the fixed-size fields.
    #[inline]
    pub fn minimum_packet_size() -> usize {
        8
    }
    #[inline]
    #[allow(trivial_numeric_casts)]
    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
    pub fn get_next_header(&self) -> IpNextHeaderProtocol {
        #[inline(always)]
        #[allow(trivial_numeric_casts)]
        #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
        fn get_arg0(_self: &IPv6FragmentPacket) -> u8 {
            let co = 0;
            (_self.packet[co] as u8)
        }
        IpNextHeaderProtocol::new(get_arg0(&self))
    }
    /// Get the identification field. This field is always stored big-endian
    /// within the struct, but this accessor returns host order.
    #[inline]
    #[allow(trivial_numeric_casts)]
    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
    pub fn get_identification(&self) -> u32be {
        let _self = self;
        let co = 4;
        let b0 = ((_self.packet[co] as u32be) << 24) as u32be;
        let b1 = ((_self.packet[co + 1] as u32be) << 16) as u32be;
        let b2 = ((_self.packet[co + 2] as u32be) << 8) as u32be;
        let b3 = (_self.packet[co + 3] as u32be) as u32be;
        b0 | b1 | b2 | b3
    }
    /// Get the fragment_offset field. This field is always stored big-endian
    /// within the struct, but this accessor returns host order.
    #[inline]
    #[allow(trivial_numeric_casts)]
    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
    pub fn get_fragment_offset(&self) -> u13be {
        let _self = self;
        let co = 2;
        let b0 = ((_self.packet[co] as u16be) << 8) as u16be;
        let b1 = _self.packet[co + 1] as u16be;
        ((b0 | b1) >> 3) as u13be
    }
    #[inline]
    #[allow(trivial_numeric_casts)]
    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
    pub fn more_fragments(&self) -> bool {
        let _self = self;
        let co = 3;
        let b0 = _self.packet[co] & 0x1;
        b0 != 0
    }
}
impl<'a> ::pnet_macros_support::packet::Packet for IPv6FragmentPacket<'a> {
    #[inline]
    fn packet(&self) -> &[u8] {
        &self.packet[..]
    }
    #[inline]
    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
    fn payload(&self) -> &[u8] {
        let _self = self;
        let start = 8;
        let end = _self.packet.len();
        if _self.packet.len() <= start {
            return &[];
        }
        &_self.packet[start..end]
    }
}

#[cfg(test)]
mod tests {
    use super::IPv6FragmentPacket;
    use pnet_packet::ip::IpNextHeaderProtocols;
    const DATA: &[u8] = b"\x11\x00\x00\x01\xf8\x8e\xb4\x66";
    #[test]
    fn ipv6fragment_test() {
        let packet = IPv6FragmentPacket::new(DATA).expect("IPv6FragmentPacket");
        assert_eq!(packet.get_next_header(), IpNextHeaderProtocols::Udp);
        assert_eq!(packet.more_fragments(), true);
        assert_eq!(packet.get_identification(), 0xf88e_b466);
    }
}
