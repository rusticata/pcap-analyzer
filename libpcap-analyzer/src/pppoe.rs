use pnet_macros_support::types::{u16be, u4};

#[derive(PartialEq)]
/// A structure enabling manipulation of on the wire packets
pub struct PppoeSessionPacket<'p> {
    packet: ::pnet_macros_support::packet::PacketData<'p>,
}

impl<'a> PppoeSessionPacket<'a> {
    /// Constructs a new PppoeSession. If the provided buffer is less than the minimum required
    /// packet size, this will return None.
    #[inline]
    pub fn new(packet: &[u8]) -> Option<PppoeSessionPacket> {
        if packet.len() >= PppoeSessionPacket::minimum_packet_size() {
            use ::pnet_macros_support::packet::PacketData;
            Some(PppoeSessionPacket {
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
        6
    }
    /// Get the version field.
    #[inline]
    pub fn get_version(&self) -> u4 {
        (self.packet[0] >> 4) as u4
    }
    /// Get the type field.
    #[inline]
    pub fn get_type(&self) -> u4 {
        (self.packet[0] & 0b1111) as u4
    }
    /// Get the code field.
    #[inline]
    pub fn get_code(&self) -> u8 {
        self.packet[1]
    }
    /// Get the session id field.
    #[inline]
    #[allow(trivial_numeric_casts)]
    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
    pub fn get_session_id(&self) -> u16be {
        let _self = self;
        let b0 = ((_self.packet[2] as u16be) << 8) as u16be;
        let b1 = (_self.packet[3] as u16be) as u16be;
        b0 | b1
    }
    /// Get the length field.
    #[inline]
    #[allow(trivial_numeric_casts)]
    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
    pub fn get_length(&self) -> u16be {
        let _self = self;
        let b0 = ((_self.packet[4] as u16be) << 8) as u16be;
        let b1 = (_self.packet[5] as u16be) as u16be;
        b0 | b1
    }
}

impl<'a> ::pnet_macros_support::packet::Packet for PppoeSessionPacket<'a> {
    #[inline]
    fn packet(&self) -> &[u8] {
        &self.packet[..]
    }
    #[inline]
    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
    fn payload(&self) -> &[u8] {
        let _self = self;
        let start = 6;
        let end = _self.packet.len();
        if _self.packet.len() <= start {
            return &[];
        }
        &_self.packet[start..end]
    }
}