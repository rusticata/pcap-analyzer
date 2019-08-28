use crate::traits::*;
use libpcap_tools::Packet;
use pcap_parser::Linktype;
use pcap_parser::pcapng::*;
use pcap_parser::ToVec;
use std::io::{self, Error, ErrorKind, Write};

/// Writer for the legacy pcap format
pub struct PcapNGWriter<W>
where
    W: Write,
{
    w: W,
}

impl<W: Write> PcapNGWriter<W> {
    pub fn new(w: W) -> Self {
        PcapNGWriter {
            w,
        }
    }
}

impl<W: Write> Writer for PcapNGWriter<W> {
    fn init_file(&mut self, snaplen: usize, linktype: Linktype) -> Result<usize, io::Error> {
        // write SHB and IDB
        let shb = SectionHeaderBlock {
            block_type: SHB_MAGIC,
            block_len1: 28, // no options
            bom: BOM_MAGIC,
            major_version: 1,
            minor_version: 0,
            section_len: -1,
            options: Vec::new(),
            block_len2: 28,
        };
        let v = shb.to_vec_raw().or(Err(Error::new(ErrorKind::Other, "SHB serialization failed")))?;
        let sz1 = self.w.write(&v)?;
        let mut idb = InterfaceDescriptionBlock {
            block_type: IDB_MAGIC,
            block_len1: 20,
            linktype: linktype,
            reserved: 0,
            snaplen: snaplen as u32,
            options: vec![],
            block_len2: 20,
            if_tsresol: 6,
            if_tsoffset: 0,
        };
        // to_vec will add options automatically
        let v = idb.to_vec().or(Err(Error::new(ErrorKind::Other, "IDB serialization failed")))?;
        let sz2 = self.w.write(&v)?;
        Ok(sz1 + sz2)
    }

    fn write_packet(&mut self, packet: &Packet, data: &[u8]) -> Result<usize, io::Error> {
        let unit : u64 = 1_000_000;
        let ts = ((packet.ts.secs as u64) * unit) + (packet.ts.micros as u64);
        let mut epb = EnhancedPacketBlock {
            block_type: EPB_MAGIC,
            block_len1: 32,
            if_id: 0,
            ts_high: (ts >> 32) as u32,
            ts_low: (ts & 0xffff_ffff) as u32,
            caplen: data.len() as u32,
            origlen: data.len() as u32,
            data,
            options: Vec::new(),
            block_len2: 32,
        };
        // to_vec will adjust length
        let v = epb.to_vec().or(Err(Error::new(ErrorKind::Other, "EPB serialization failed")))?;
        self.w.write(&v)
    }
}
