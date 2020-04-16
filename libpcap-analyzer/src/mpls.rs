use pnet_macros_support::types::{u1, u19be, u3};

#[derive(Debug)]
#[repr(transparent)]
pub struct MplsLabel(u32);

impl MplsLabel {
    /// Get the label value
    #[inline]
    pub fn get_label(&self) -> u19be {
        self.0 >> 12
    }
    /// Get the Traffic Class (QoS and ECN)
    #[inline]
    pub fn get_tc(&self) -> u3 {
        ((self.0 >> 9) & 0b111) as u3
    }
    /// Get the Bottom of Stack indicator
    #[inline]
    pub fn get_bos(&self) -> u1 {
        ((self.0 >> 8) & 0b1) as u1
    }
    /// Get the Time To Live (TTL) value
    #[inline]
    pub fn get_ttl(&self) -> u8 {
        (self.0 >> 24) as u8
    }
    /// Get the raw value
    #[inline]
    pub fn get_raw_value(&self) -> u32 {
        self.0
    }
}

#[derive(PartialEq)]
/// A structure enabling manipulation of on the wire packets
pub struct MplsPacket<'p> {
    packet: ::pnet_macros_support::packet::PacketData<'p>,
    stack_size: usize,
}

impl<'a> MplsPacket<'a> {
    /// Constructs a new PPP packet. If the provided buffer is less than the minimum required
    /// packet size, this will return None.
    #[inline]
    pub fn new(packet: &[u8]) -> Option<MplsPacket> {
        if packet.len() >= MplsPacket::minimum_packet_size() {
            let mut stack_size = 0;
            let mut ptr = packet;
            while ptr.len() >= 4 {
                if ptr[2] & 0b1 == 0 {
                    ptr = &ptr[4..];
                    stack_size += 4;
                } else {
                    stack_size += 4;
                    break;
                }
            }
            if ptr.len() < 4 || packet.len() < stack_size || stack_size < 4 {
                return None;
            }
            use ::pnet_macros_support::packet::PacketData;
            Some(MplsPacket {
                packet: PacketData::Borrowed(packet),
                stack_size,
            })
        } else {
            None
        }
    }
    /// The minimum size (in bytes) a packet of this type can be. It's based on the total size
    /// of the fixed-size fields.
    #[inline]
    pub fn minimum_packet_size() -> usize {
        4
    }
    /// The size (in bytes) of the label stack.
    #[inline]
    pub fn get_stack_size(&self) -> usize {
        self.stack_size
    }
    /// The number of labels in the label stack.
    #[inline]
    pub fn get_num_labels(&self) -> usize {
        self.stack_size / 4
    }
    /// The size (in bytes) of the label stack.
    #[inline]
    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
    pub fn get_top_label(&self) -> MplsLabel {
        let _self = self;
        let label = (_self.packet[0] as u32) << 24
            | (_self.packet[1] as u32) << 16
            | (_self.packet[2] as u32) << 8
            | _self.packet[3] as u32;
        MplsLabel(label)
    }
    /// The label stack (top element is first).
    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
    pub fn get_label_stack(&self) -> Vec<MplsLabel> {
        assert!(self.stack_size % 4 == 0);
        let _self = self;
        let mut data = _self.packet.as_slice();
        let n = _self.stack_size / 4;
        let mut v = Vec::new();
        for _ in 0..n {
            let label = (data[0] as u32) << 24
                | (data[1] as u32) << 16
                | (data[2] as u32) << 8
                | data[3] as u32;
            data = &data[4..];
            v.push(MplsLabel(label));
        }
        v
    }
}

impl<'a> ::pnet_macros_support::packet::Packet for MplsPacket<'a> {
    #[inline]
    fn packet(&self) -> &[u8] {
        &self.packet[..]
    }
    #[inline]
    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
    fn payload(&self) -> &[u8] {
        let _self = self;
        let start = self.stack_size;
        &_self.packet[start..]
    }
}
