use crate::duration::Duration;
use pcap_parser::data::PacketData;

pub struct Packet<'a> {
    pub interface: u32,
    pub ts: Duration,
    pub data: PacketData<'a>,
    pub caplen: u32,
    pub origlen: u32,
    pub pcap_index: usize,
}
