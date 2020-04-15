use pnet_macros_support::types::{u1, u10be, u12be, u3, u4};

#[derive(PartialEq)]
/// A structure enabling manipulation of on the wire packets
pub struct ErspanPacket<'p> {
    packet: ::pnet_macros_support::packet::PacketData<'p>,
}

impl<'a> ErspanPacket<'a> {
    /// Constructs a new ErspanPacket. If the provided buffer is less than the minimum required
    /// packet size, this will return None.
    #[inline]
    pub fn new(packet: &[u8]) -> Option<ErspanPacket> {
        if packet.len() >= ErspanPacket::minimum_packet_size() {
            use ::pnet_macros_support::packet::PacketData;
            Some(ErspanPacket {
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
    /// Get the version field.
    #[inline]
    #[allow(trivial_numeric_casts)]
    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
    pub fn get_version(&self) -> u4 {
        let _self = self;
        let co = 0;
        (_self.packet[co] as u4) >> 4
    }
    /// Get the vlan field.
    #[inline]
    #[allow(trivial_numeric_casts)]
    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
    pub fn get_vlan(&self) -> u12be {
        let _self = self;
        let b0 = (((_self.packet[0] & 0b0000_1111) as u12be) << 8) as u12be;
        let b1 = (_self.packet[1] as u12be) as u12be;
        b0 | b1
    }
    /// Get the COS field.
    #[inline]
    #[allow(trivial_numeric_casts)]
    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
    pub fn get_cos(&self) -> u3 {
        let _self = self;
        let co = 2;
        (_self.packet[co] as u3) >> 5
    }
    /// Get the encap field.
    #[inline]
    #[allow(trivial_numeric_casts)]
    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
    pub fn get_encap(&self) -> u3 {
        let _self = self;
        let co = 2;
        ((_self.packet[co] as u3) >> 3) & 0b11
    }
    /// Get the truncated field.
    #[inline]
    #[allow(trivial_numeric_casts)]
    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
    pub fn get_truncated(&self) -> u1 {
        let _self = self;
        let co = 2;
        ((_self.packet[co] as u1) >> 2) & 0b1
    }
    /// Get the span ID field.
    #[inline]
    #[allow(trivial_numeric_casts, clippy::identity_op)]
    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
    pub fn get_span_id(&self) -> u10be {
        let _self = self;
        let co = 2;
        let b0 = (((_self.packet[co + 0] & 0b0000_0011) as u10be) << 8) as u10be;
        let b1 = (_self.packet[co + 1] as u10be) as u10be;
        b0 | b1
    }
}
impl<'a> ::pnet_macros_support::packet::Packet for ErspanPacket<'a> {
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
    use super::ErspanPacket;
    use pnet_macros_support::packet::Packet;
    const DATA: &[u8] = b"\x10\x17\x08\x64\x00\x00\x00\x00\x12\x34";
    #[test]
    fn erspan_test() {
        let packet = ErspanPacket::new(DATA).expect("ErspanPacket");
        assert_eq!(packet.get_version(), 1);
        assert_eq!(packet.get_vlan(), 23);
        assert_eq!(packet.get_cos(), 0);
        assert_eq!(packet.get_encap(), 1);
        assert_eq!(packet.get_truncated(), 0);
        assert_eq!(packet.get_span_id(), 100);
        assert_eq!(packet.payload(), &[0x12, 0x34]);
    }
}
