use pcap_parser::*;
use std::convert::TryFrom;

/// Information related to a network interface used for capture
pub struct InterfaceInfo {
    pub if_index: usize,
    /// The `Linktype` used for data format
    pub link_type: Linktype,
    /// Time resolution
    pub if_tsresol: u8,
    /// Time offset
    pub if_tsoffset: u64,
    /// Maximum number of octets captured from each packet.
    pub snaplen: u32,

    /// Misc options, formatted as string
    pub options: Vec<(OptionCode, Vec<u8>)>,
}

impl Default for InterfaceInfo {
    fn default() -> Self {
        InterfaceInfo {
            if_index: 0,
            link_type: Linktype(0),
            if_tsresol: 0,
            if_tsoffset: 0,
            snaplen: 0,
            options: Vec::new(),
        }
    }
}

pub fn pcapng_build_interface<'a>(
    idb: &'a InterfaceDescriptionBlock<'a>,
    if_index: usize,
) -> InterfaceInfo {
    let mut options = Vec::new();
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
        options.push((opt.code, opt.value.to_vec()));
    }
    InterfaceInfo {
        if_index,
        link_type,
        if_tsresol,
        if_tsoffset,
        snaplen: idb.snaplen,
        options,
    }
}
