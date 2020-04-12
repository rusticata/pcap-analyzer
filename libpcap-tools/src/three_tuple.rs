use serde::Serialize;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

/// Network 3-tuple: layer 4 protocol (e.g TCP or UDP), source and destination IP addresses
#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[derive(Serialize)]
pub struct ThreeTuple {
    /// Layer 3 protocol (e.g IPv4, IPv6)
    pub proto: u16,
    /// Source IP address
    pub src: IpAddr,
    /// Destination IP address
    pub dst: IpAddr,
}

impl Default for ThreeTuple {
    fn default() -> Self {
        ThreeTuple {
            proto: 0,
            src: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            dst: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        }
    }
}

impl fmt::Display for ThreeTuple {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} -> {} [{}]", self.src, self.dst, self.proto)
    }
}
