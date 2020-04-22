use crate::duration::Duration;
use pcap_parser::*;
use std::convert::TryFrom;

/// Block parsing context
#[derive(Clone, Default)]
pub struct ParseBlockContext {
    /// Index of current block in the pcap file
    pub block_index: usize,
}

/// pcap parsing context
#[derive(Clone, Default)]
pub struct ParseContext {
    /// Timestamp of first packet seen
    pub first_packet_ts: Duration,
    /// Relative timestamp of current packet
    pub rel_ts: Duration,
    /// Index of current packet in pcap file
    pub pcap_index: usize,
}

/// Information related to a network interface used for capture
#[derive(Clone)]
pub struct InterfaceInfo {
    /// The `Linktype` used for data format
    pub link_type: Linktype,
    /// Time resolution
    pub if_tsresol: u8,
    /// Time offset
    pub if_tsoffset: u64,
    /// Maximum number of octets captured from each packet.
    pub snaplen: u32,
}

impl Default for InterfaceInfo {
    fn default() -> Self {
        InterfaceInfo {
            link_type: Linktype(0),
            if_tsresol: 0,
            if_tsoffset: 0,
            snaplen: 0,
        }
    }
}
pub fn pcapng_build_interface<'a>(idb: &'a InterfaceDescriptionBlock<'a>) -> InterfaceInfo {
    let link_type = idb.linktype;
    // extract if_tsoffset and if_tsresol
    let mut if_tsresol: u8 = 6;
    let mut if_tsoffset: u64 = 0;
    for opt in idb.options.iter() {
        match opt.code {
            OptionCode::IfTsresol => {
                if !opt.value.is_empty() {
                    if_tsresol = opt.value[0];
                }
            }
            OptionCode::IfTsoffset => {
                if opt.value.len() >= 8 {
                    let int_bytes = <[u8; 8]>::try_from(opt.value).expect("Convert bytes to u64");
                    if_tsoffset = u64::from_le_bytes(int_bytes) /* LittleEndian::read_u64(opt.value) */;
                }
            }
            _ => (),
        }
    }
    InterfaceInfo {
        link_type,
        if_tsresol,
        if_tsoffset,
        snaplen: idb.snaplen,
    }
}

// pub fn pcapng_build_packet<'a>(
//     if_info: &InterfaceInfo,
//     block: Block<'a>,
// ) -> Option<Packet<'a>> {
//     pcapng::packet_of_block(block, if_info.if_tsoffset, if_info.if_tsresol)
// }
