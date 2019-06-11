use crate::error::Error;
use pcap_parser::Linktype;

const ETHER_IPV4 : u16 = 0x0800;
const ETHER_IPV6 : u16 = 0x86DD;

pub enum LayerType {
    L2,
    L3(u16),
}

pub fn get_packet_data<'a>(link_type: Linktype, packet: &pcap_parser::Packet<'a>) -> Result<(LayerType, &'a[u8]), Error> {
        match link_type {
            Linktype::NULL => {
                // XXX read first u32 in *host order*: 2 if IPv4, etc.
                Ok((LayerType::L3(ETHER_IPV4), &packet.data[4..])) // XXX overflow
            }
            Linktype::RAW => {
                // XXX may be IPv4 or IPv6, check IP header ...
                Ok((LayerType::L3(ETHER_IPV4), packet.data)) // XXX overflow
            }
            Linktype(228) /* IPV4 */ => Ok((LayerType::L3(ETHER_IPV4), packet.data)),
            Linktype(229) /* IPV6 */ => Ok((LayerType::L3(ETHER_IPV6), packet.data)),
            Linktype::ETHERNET => Ok((LayerType::L2, packet.data)),
            Linktype::FDDI => Ok((LayerType::L3(ETHER_IPV4), &packet.data[21..])),
            Linktype::NFLOG => match pcap_parser::data::parse_nflog(packet.data) {
                Ok((_, nf)) => {
                    let ethertype = match nf.header.af {
                        2 => ETHER_IPV4,
                        10 => ETHER_IPV6,
                        af => {
                            warn!("NFLOG: unsupported address family {}", af);
                            0
                        }
                    };
                    let data = nf
                        .get_payload()
                        .ok_or("Unable to get payload from nflog data")?;
                    // nf is temporary, but data is not (same lifetime as packet)
                    // rebuild a slice to change lifetime
                    let data_unsafe =
                        unsafe { ::std::slice::from_raw_parts(data.as_ptr(), data.len()) };
                    Ok((LayerType::L3(ethertype), data_unsafe))
                }
                _ => Err(Error::from("Could not parse NFLOG data"))
            },
            l => {
                warn!("Unsupported link type {}", l);
                Err(Error::from("Unsupported link type"))
            }
        }
}
