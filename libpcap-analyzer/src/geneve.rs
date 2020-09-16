//! Generic Network Virtualization Encapsulation (GENEVE)

use pnet_macros_support::types::{u1, u16be, u2, u24be, u5, u6};

#[derive(PartialEq)]
/// A structure enabling manipulation of on the wire packets
pub struct GenevePacket<'p> {
    packet: ::pnet_macros_support::packet::PacketData<'p>,
}

impl<'a> GenevePacket<'a> {
    /// Constructs a new GENEVE packet. If the provided buffer is less than the minimum required
    /// packet size, this will return None.
    #[inline]
    pub fn new(packet: &[u8]) -> Option<GenevePacket> {
        if packet.len() >= GenevePacket::minimum_packet_size() {
            use ::pnet_macros_support::packet::PacketData;
            Some(GenevePacket {
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
    /// The version the GENEVE tunnel header.
    #[inline]
    pub fn get_stack_size(&self) -> u2 {
        (self.packet[0] >> 6) as u2
    }
    /// The length of option fields
    #[inline]
    pub fn get_option_length(&self) -> u6 {
        (self.packet[0] & 0b0011_1111) as u6
    }
    /// Get control packet flag
    ///
    /// True if packet contains a control message.
    #[inline]
    pub fn get_control(&self) -> u1 {
        (self.packet[1] >> 7) as u1
    }
    /// Get critical flag
    #[inline]
    pub fn get_critical(&self) -> u1 {
        ((self.packet[1] >> 6) & 0b01) as u1
    }
    /// Get reserved bits
    #[inline]
    pub fn get_reserved(&self) -> u6 {
        (self.packet[1] & 0b0011_1111) as u1
    }
    /// Get protocol type
    #[inline]
    pub fn get_protocol_type(&self) -> u16be {
        ((self.packet[2] as u16be) << 8) | (self.packet[3] as u16be)
    }
    /// Get Virtual Network Identifier (VNI)
    #[inline]
    pub fn get_virtual_network_identifier(&self) -> u24be {
        ((self.packet[4] as u24be) << 16)
            | ((self.packet[5] as u24be) << 8)
            | (self.packet[6] as u24be)
    }
    /// Get second reserved bits
    #[inline]
    pub fn get_reserved2(&self) -> u8 {
        self.packet[7]
    }
    /// Get the raw &[u8] value of the options field, without copying
    #[inline]
    #[allow(trivial_numeric_casts)]
    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
    pub fn get_options_raw(&self) -> &[u8] {
        use std::cmp::min;
        let _self = self;
        let current_offset = 8;
        let options_len = (self.get_option_length() as usize) * 4;
        let end = min(current_offset + options_len, _self.packet.len());
        &_self.packet[current_offset..end]
    }
    /// Get the value of the options field (copies contents)
    #[inline]
    #[allow(trivial_numeric_casts)]
    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
    pub fn get_options(&self) -> Vec<GeneveOption> {
        use pnet_packet::FromPacket;
        let buf = self.get_options_raw();
        GeneveOptionIterable { buf }
            .map(|packet| packet.from_packet())
            .collect::<Vec<_>>()
    }
    /// Get the value of the options field as iterator
    #[inline]
    #[allow(trivial_numeric_casts)]
    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
    pub fn get_options_iter(&self) -> GeneveOptionIterable {
        let buf = self.get_options_raw();
        GeneveOptionIterable { buf }
    }
}

impl<'a> ::pnet_macros_support::packet::Packet for GenevePacket<'a> {
    #[inline]
    fn packet(&self) -> &[u8] {
        &self.packet[..]
    }
    #[inline]
    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
    fn payload(&self) -> &[u8] {
        let _self = self;
        let options_len = (self.get_option_length() as usize) * 4;
        let start = ::std::cmp::min(8 + options_len, self.packet.len());
        &_self.packet[start..]
    }
}

/// Represents the Geneve Option field.
#[derive(Clone, Debug)]
#[allow(unused_attributes)]
pub struct GeneveOption {
    option_class: u16be,
    option_type: u8,
    length: u5,
    data: Vec<u8>,
}

impl GeneveOption {
    #[inline]
    pub fn option_class(&self) -> u16be {
        self.option_class
    }
    #[inline]
    pub fn option_type(&self) -> u8 {
        self.option_type
    }
    #[inline]
    pub fn option_length(&self) -> u5 {
        self.length
    }
    #[inline]
    pub fn option_data(&self) -> &[u8] {
        &self.data
    }
}

#[derive(PartialEq)]
/// A structure enabling manipulation of on the wire packets
pub struct GeneveOptionPacket<'p> {
    packet: ::pnet_macros_support::packet::PacketData<'p>,
}

impl<'a> GeneveOptionPacket<'a> {
    /// Constructs a new GeneveOptionPacket. If the provided buffer is less than the minimum required
    /// packet size, this will return None.
    #[inline]
    pub fn new(packet: &'_ [u8]) -> Option<GeneveOptionPacket<'_>> {
        if packet.len() >= GeneveOptionPacket::minimum_packet_size() {
            use ::pnet_macros_support::packet::PacketData;
            Some(GeneveOptionPacket {
                packet: PacketData::Borrowed(packet),
            })
        } else {
            None
        }
    }
    /// The minimum size (in bytes) a packet of this type can be. It's based on the total size
    /// of the fixed-size fields.
    #[inline]
    pub const fn minimum_packet_size() -> usize {
        4
    }
    /// Get Option Class
    #[inline]
    pub fn get_option_class(&self) -> u16be {
        ((self.packet[0] as u16be) << 8) | (self.packet[1] as u16be)
    }
    /// Get Option Type
    #[inline]
    pub fn get_option_type(&self) -> u8 {
        self.packet[2]
    }
    /// Get the Option Length field
    #[inline]
    pub fn get_option_length(&self) -> u5 {
        (self.packet[3] & 0b0001_1111) as u5
    }
}

impl<'a> ::pnet_macros_support::packet::Packet for GeneveOptionPacket<'a> {
    #[inline]
    fn packet(&self) -> &[u8] {
        &self.packet[..]
    }
    #[inline]
    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
    fn payload(&self) -> &[u8] {
        let _self = self;
        let options_len = (self.get_option_length() as usize) * 4;
        let start = ::std::cmp::min(4 + options_len, self.packet.len());
        &_self.packet[start..]
    }
}

impl<'a> ::pnet_macros_support::packet::PacketSize for GeneveOptionPacket<'a> {
    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
    fn packet_size(&self) -> usize {
        4 + 4 * (self.get_option_length() as usize)
    }
}

impl<'p> ::pnet_macros_support::packet::FromPacket for GeneveOptionPacket<'p> {
    type T = GeneveOption;
    #[inline]
    fn from_packet(&self) -> GeneveOption {
        use pnet_macros_support::packet::Packet;
        let _self = self;
        GeneveOption {
            option_class: _self.get_option_class(),
            option_type: _self.get_option_type(),
            length: _self.get_option_length(),
            data: {
                let payload = self.payload();
                let mut vec = Vec::with_capacity(payload.len());
                vec.extend_from_slice(payload);
                vec
            },
        }
    }
}

pub struct GeneveOptionIterable<'a> {
    buf: &'a [u8],
}

impl<'a> Iterator for GeneveOptionIterable<'a> {
    type Item = GeneveOptionPacket<'a>;
    fn next(&mut self) -> Option<GeneveOptionPacket<'a>> {
        use pnet_macros_support::packet::PacketSize;
        use std::cmp::min;
        if !self.buf.is_empty() {
            if let Some(ret) = GeneveOptionPacket::new(self.buf) {
                let start = min(ret.packet_size(), self.buf.len());
                self.buf = &self.buf[start..];
                return Some(ret);
            }
        }
        None
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, None)
    }
}
