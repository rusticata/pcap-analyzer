#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PppProtocolType(pub u16);

/// PPP DLL Protocol Number
///
/// See https://www.iana.org/assignments/ppp-numbers/ppp-numbers.xhtml#ppp-numbers-2
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod PppProtocolTypes {
    use crate::ppp::PppProtocolType;
    /// Internet Protocol version 4 (IPv4) [RFC1332].
    pub const Ipv4: PppProtocolType = PppProtocolType(0x0021);
    /// Internet Protocol version 6 (IPv6) [RFC5072].
    pub const Ipv6: PppProtocolType = PppProtocolType(0x0057);
}

#[derive(PartialEq)]
/// A structure enabling manipulation of on the wire packets
pub struct PppPacket<'p> {
    packet: ::pnet_macros_support::packet::PacketData<'p>,
}

impl<'a> PppPacket<'a> {
    /// Constructs a new PPP packet. If the provided buffer is less than the minimum required
    /// packet size, this will return None.
    #[inline]
    pub fn new(packet: &[u8]) -> Option<PppPacket> {
        if packet.len() >= PppPacket::minimum_packet_size() {
            if packet[0] == 0xff && packet[1] == 0x03 && packet.len() < 4 {
                return None;
            }
            use ::pnet_macros_support::packet::PacketData;
            Some(PppPacket {
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
        2
    }
    /// Return true if address and control fields are present.
    ///
    /// These fields are always equal to 0xff03 and can be removed if
    /// Address and Control Field Compression (ACFC) is used
    #[inline]
    pub fn has_address_and_control(&self) -> bool {
        let _self = self;
        let b0 = _self.packet[0];
        let b1 = _self.packet[1];
        b0 == 0xff && b1 == 0x03
    }
    /// Get the protocol field.
    #[inline]
    pub fn get_protocol(&self) -> PppProtocolType {
        let _self = self;
        let _start_idx = if self.has_address_and_control() { 2 } else { 0 };
        let b0 = _self.packet[_start_idx];
        if b0 & 0b1 != 0 {
            PppProtocolType(b0 as u16)
        } else {
            let b1 = _self.packet[_start_idx + 1];
            PppProtocolType(((b0 as u16) << 8) | (b1 as u16))
        }
    }
}

impl<'a> ::pnet_macros_support::packet::Packet for PppPacket<'a> {
    #[inline]
    fn packet(&self) -> &[u8] {
        &self.packet[..]
    }
    #[inline]
    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
    fn payload(&self) -> &[u8] {
        let _self = self;
        let mut start = if self.has_address_and_control() { 2 } else { 0 };
        let b0 = _self.packet[start];
        start += if b0 & 0b1 != 0 { 1 } else { 2 };
        let end = _self.packet.len();
        if _self.packet.len() <= start {
            return &[];
        }
        &_self.packet[start..end]
    }
}
