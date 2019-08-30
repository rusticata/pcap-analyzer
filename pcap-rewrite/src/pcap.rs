use crate::traits::Writer;
use libpcap_tools::Packet;
use pcap_parser::{LegacyPcapBlock, Linktype};
use pcap_parser::ToVec;
use std::io::{self, Error, ErrorKind, Write};

/// Writer for the legacy pcap format
pub struct PcapWriter<W>
where
    W: Write,
{
    w: W,
}

impl<W: Write> PcapWriter<W> {
    pub fn new(w: W) -> Self {
        PcapWriter { w }
    }
}

impl<W: Write> Writer for PcapWriter<W> {
    fn init_file(&mut self, snaplen: usize, linktype: Linktype) -> Result<usize, io::Error> {
        let mut hdr = pcap_parser::PcapHeader::new();
        hdr.snaplen = snaplen as u32;
        hdr.network = linktype;
        #[allow(clippy::or_fun_call)]
        let s = hdr.to_vec().or(Err(Error::new(ErrorKind::Other, "Pcap header serialization failed")))?;
        self.w.write(&s)
    }

    fn write_packet(&mut self, packet: &Packet, data: &[u8]) -> Result<usize, io::Error> {
        let record = LegacyPcapBlock {
            ts_sec: packet.ts.secs as u32,
            ts_usec: packet.ts.micros as u32,
            caplen: data.len() as u32,  // packet.header.caplen,
            origlen: data.len() as u32, // packet.header.len,
            data,
        };
        // debug!("rec_hdr: {:?}", rec_hdr);
        // debug!("data (len={}): {}", data.len(), data.to_hex(16));
        #[allow(clippy::or_fun_call)]
        let s = record.to_vec_raw().or(Err(Error::new(ErrorKind::Other, "Pcap block serialization failed")))?;
        self.w.write(&s)
    }
}
