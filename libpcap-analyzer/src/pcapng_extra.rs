use pcap_parser::*;
use nom::le_u64;

pub struct InterfaceInfo {
    pub link_type: Linktype,
    pub if_tsresol: u8,
    pub if_tsoffset: u64,
}

impl InterfaceInfo {
    pub fn new() -> InterfaceInfo {
        InterfaceInfo{
            link_type: Linktype(0),
            if_tsresol: 0,
            if_tsoffset: 0,
        }
    }
}

pub fn pcapng_build_interface<'a>(idb: &'a InterfaceDescriptionBlock<'a>) -> InterfaceInfo {
    let link_type = Linktype(idb.linktype as i32);
    // extract if_tsoffset and if_tsresol
    let mut if_tsresol : u8 = 6;
    let mut if_tsoffset : u64 = 0;
    for opt in idb.options.iter() {
        match opt.code {
            OptionCode::IfTsresol  => { if !opt.value.is_empty() { if_tsresol =  opt.value[0]; } },
            OptionCode::IfTsoffset => { if opt.value.len() >= 8 { if_tsoffset = le_u64(opt.value).unwrap_or((&[],0)).1 /* LittleEndian::read_u64(opt.value) */; } },
            _ => (),
        }
    }
    InterfaceInfo{
        link_type, if_tsresol, if_tsoffset,
    }
}

pub fn pcapng_build_packet<'a>(if_info:&InterfaceInfo, block:Block<'a>) -> Option<Packet<'a>> {
    match block {
        Block::EnhancedPacket(ref b) => {
            let if_tsoffset = if_info.if_tsoffset;
            let if_tsresol = if_info.if_tsresol;
            let ts_mode = if_tsresol & 0x70;
            let unit =
                if ts_mode == 0 { 10u64.pow(if_tsresol as u32) }
                else { 2u64.pow((if_tsresol & !0x70) as u32) };
            let ts : u64 = ((b.ts_high as u64) << 32) | (b.ts_low as u64);
            let ts_sec = (if_tsoffset + (ts / unit)) as u32;
            let ts_usec = (ts % unit) as u32;
            let header = PacketHeader{
                ts_sec,
                ts_usec,
                caplen: b.caplen,
                len: b.origlen
            };
            let data = b.data;
            Some(Packet{ header, data})
        },
        _ => None
    }
}

