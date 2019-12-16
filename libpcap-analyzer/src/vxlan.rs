use pnet_macros_support::types::{u16be, u24be};

#[derive(PartialEq)]
/// A structure enabling manipulation of on the wire packets
pub struct VxlanPacket<'p> {
    packet: ::pnet_macros_support::packet::PacketData<'p>,
}

/// Represents Vxlan flag.
#[derive(Hash, Ord, PartialOrd, Eq, PartialEq, Debug, Copy, Clone)]
pub struct VxlanFlag(pub u16);

impl VxlanFlag {
    /// Create a new `VxlanFlag` instance.
    pub fn new(value: u16) -> VxlanFlag { VxlanFlag(value) }
}

/// Vxlan flags as defined in RFC7348
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod VxlanFlags {
    use super::VxlanFlag;

    /// VXLAN Network ID (VNI)
    pub const VNI: VxlanFlag = VxlanFlag(0x0800);
}


impl <'a> VxlanPacket<'a> {
    /// Constructs a new VxlanPacket. If the provided buffer is less than the minimum required
    /// packet size, this will return None.
    #[inline]
    pub fn new(packet: &[u8]) -> Option<VxlanPacket> {
        if packet.len() >= VxlanPacket::minimum_packet_size() {
            use ::pnet_macros_support::packet::PacketData;
            Some(VxlanPacket{packet: PacketData::Borrowed(packet),})
        } else { None }
    }
    /// The minimum size (in bytes) a packet of this type can be. It's based on the total size
    /// of the fixed-size fields.
    #[inline]
    pub const fn minimum_packet_size() -> usize { 8 }
    /// Get the flags field. This field is always stored big-endian
    /// within the struct, but this accessor returns host order.
    #[inline]
    #[allow(trivial_numeric_casts)]
    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
    pub fn get_flags(&self) -> u16be {
        let _self = self;
        let b0 = ((_self.packet[0] as u16be) << 8) as u16be;
        let b1 = _self.packet[1] as u16be;
        b0 | b1
    }
    /// Get the vxlan_identifier field. This field is always stored big-endian
    /// within the struct, but this accessor returns host order.
    #[inline]
    #[allow(trivial_numeric_casts)]
    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
    pub fn get_vlan_identifier(&self) -> u24be {
        let _self = self;
        let co = 4;
        let b0 = ((_self.packet[co] as u24be) << 16) as u24be;
        let b1 = ((_self.packet[co + 1] as u24be) << 8) as u24be;
        let b2 = _self.packet[co + 2] as u24be;
        b0 | b1 | b2
    }
}
impl<'a> ::pnet_macros_support::packet::Packet for VxlanPacket<'a> {
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
    use super::*;
    const DATA: &[u8] = b"\x08\x00\x00\x00\x00\x00\x7b\x00";
    #[test]
    fn vxlan_test() {
        let packet = VxlanPacket::new(DATA).expect("VxlanPacket");
        assert_eq!(packet.get_vlan_identifier(), 123);
        assert_eq!(packet.get_flags(), VxlanFlags::VNI.0);
    }
}