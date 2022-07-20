use std::io;

mod info;
mod interface;

pub use info::{FileType, Options, PcapInfo, SectionInfo};
pub use interface::InterfaceInfo;

/// Display information about the input file (which must be pcap or pcap-ng)
pub fn pcap_info(name: &str, options: &info::Options) -> Result<(i32, PcapInfo), io::Error> {
    info::process_file(name, options)
}
