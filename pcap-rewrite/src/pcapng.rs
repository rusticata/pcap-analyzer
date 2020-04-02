use crate::traits::*;
use libpcap_tools::Packet;
use pcap_parser::pcapng::*;
use pcap_parser::ToVec;
use pcap_parser::{Linktype, PcapBlockOwned};
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
        PcapNGWriter { w }
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
        #[allow(clippy::or_fun_call)]
        let v = shb.to_vec_raw().or(Err(Error::new(
            ErrorKind::Other,
            "SHB serialization failed",
        )))?;
        let sz1 = self.w.write(&v)?;
        let mut idb = InterfaceDescriptionBlock {
            block_type: IDB_MAGIC,
            block_len1: 20,
            linktype,
            reserved: 0,
            snaplen: snaplen as u32,
            options: vec![],
            block_len2: 20,
            if_tsresol: 6,
            if_tsoffset: 0,
        };
        // to_vec will add options automatically
        #[allow(clippy::or_fun_call)]
        let v = idb.to_vec().or(Err(Error::new(
            ErrorKind::Other,
            "IDB serialization failed",
        )))?;
        let sz2 = self.w.write(&v)?;
        Ok(sz1 + sz2)
    }

    fn write_block(&mut self, block: &PcapBlockOwned) -> Result<usize, io::Error> {
        match block {
            PcapBlockOwned::NG(b) => {
                match b {
                    // skip SHB and ISB blocks, processed in `handle_packet`
                    Block::SectionHeader(_) | Block::InterfaceDescription(_) |
                    // skip data blocks, processed in `handle_packet`
                    Block::SimplePacket(_) | Block::EnhancedPacket(_) => Ok(0),
                    // other blocks are copied
                    _ => {
                        let v = b.to_vec_raw().or_else(|_| {
                            Err(Error::new(ErrorKind::Other, "Block serialization failed"))
                        })?;
                        self.w.write(&v)
                    }
                }
            }
            _ => Ok(0),
        }
    }

    fn write_packet(&mut self, packet: &Packet, data: &[u8]) -> Result<usize, io::Error> {
        let unit: u64 = 1_000_000;
        let ts = (u64::from(packet.ts.secs) * unit) + u64::from(packet.ts.micros);
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
        #[allow(clippy::or_fun_call)]
        let v = epb.to_vec().or(Err(Error::new(
            ErrorKind::Other,
            "EPB serialization failed",
        )))?;
        self.w.write(&v)
    }
}
