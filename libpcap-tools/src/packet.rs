use crate::duration::Duration;
use pcap_parser::{data::PacketData, Linktype};

#[derive(Debug, Clone)]
pub struct Packet<'a> {
    pub interface: u32,
    pub ts: Duration,
    pub link_type: Linktype,
    pub data: PacketData<'a>,
    pub caplen: u32,
    pub origlen: u32,
    pub pcap_index: usize,
}
