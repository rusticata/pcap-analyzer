use libpcap_tools::Packet;
use pcap_parser::Linktype;
use std::io;

pub trait Writer {
    fn init_file(&mut self, snaplen: usize, linktype: Linktype) -> Result<usize, io::Error>;

    fn write_packet(&mut self, packet: &Packet, data: &[u8]) -> Result<usize, io::Error>;
}
