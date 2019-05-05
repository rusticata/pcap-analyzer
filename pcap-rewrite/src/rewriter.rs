use libpcap_tools::{Error, ParseContext, PcapAnalyzer};
use pcap_parser::{Linktype, Packet};
use pcap_parser::data::*;
use std::io;
use std::io::Write;

#[derive(Debug, Default)]
struct Stats {
    num_packets: u32,
    num_bytes: u64,
}

pub struct Rewriter<W: Write> {
    snaplen: usize,
    w: Box<W>,
    stats: Stats,
}

impl<W> Rewriter<W> where W: std::io::Write {
    pub fn new(w: Box<W>) -> Self {
        Rewriter {
            snaplen: 65535, // XXX
            w,
            stats: Stats::default(),
        }
    }
}

impl<W> PcapAnalyzer for Rewriter<W> where W: std::io::Write {
    fn init(&mut self) -> Result<(), Error> {
        pcap_write_header(&mut self.w, self.snaplen)?;
        Ok(())
    }

    fn handle_packet(&mut self, packet: &Packet, ctx: &ParseContext) -> Result<(),Error> {
        let link_type = match ctx.interfaces.get(packet.interface as usize) {
            Some(if_info) => if_info.link_type,
            None => {
                warn!(
                    "Could not get link_type (missing interface info) for packet idx={}",
                    ctx.pcap_index
                );
                return Err(Error::Generic("Missing interface info"));
            }
        };
        let parse_data = get_linktype_parse_fn(link_type).ok_or("unsupported link_type")?;
        let data = {
            let data = parse_data(&packet);
            if data.len() > self.snaplen {
                eprintln!("truncating index {} to {} bytes", ctx.pcap_index, self.snaplen);
                &data[..self.snaplen as usize]
            } else {
                data
            }
        };
        debug!("Writing packet {} with link_type {} ({} bytes)", ctx.pcap_index, link_type, data.len());
        let written = pcap_write_packet(&mut self.w, &packet, data)?;
        self.stats.num_packets += 1;
        self.stats.num_bytes += written as u64;

        Ok(())
    }

    fn teardown(&mut self) {
        info!("Done.");
        info!("Stats: {:?}", self.stats);
    }
}

fn wrap_get_data_nflog<'a>(packet: &'a Packet) -> &'a[u8] {
    get_data_nflog(packet).expect("extract data from nflog packet")
}

fn get_linktype_parse_fn(link_type:Linktype) -> Option<for<'a> fn (&'a Packet) -> &'a[u8]>
{
    // See http://www.tcpdump.org/linktypes.html
    let f : Option<for<'a> fn (&'a Packet) -> &'a[u8]> = match link_type {
        Linktype::NULL => Some(get_data_null),
        Linktype::ETHERNET => Some(get_data_ethernet),
        Linktype::LINUX_SLL => Some(get_data_linux_cooked),
        Linktype::RAW | Linktype(228) => Some(get_data_raw),
        Linktype::NFLOG => Some(wrap_get_data_nflog),
        _ => None
    };
    f
}

fn pcap_write_header<W:Write>(to:&mut W, snaplen:usize) -> Result <usize,io::Error> {
    let mut hdr = pcap_parser::PcapHeader::new();
    hdr.snaplen = snaplen as u32;
    hdr.network = 228; // DATALINK_RAWIPV4
    let s = hdr.to_string();
    to.write(&s)?;
    Ok(s.len())
}

fn pcap_write_packet<W:Write>(to:&mut W, packet:&Packet, data:&[u8]) -> Result<usize,io::Error> {
    let rec_hdr = pcap_parser::PacketHeader{
        ts_sec: packet.header.ts_sec as u32,
        ts_usec: packet.header.ts_usec as u32,
        caplen: data.len() as u32, // packet.header.caplen,
        len: data.len() as u32, // packet.header.len,
    };
    // debug!("rec_hdr: {:?}", rec_hdr);
    // debug!("data (len={}): {}", data.len(), data.to_hex(16));
    let s = rec_hdr.to_string();
    let sz = to.write(&s)? + to.write(&data)?;

    Ok(sz)
}
