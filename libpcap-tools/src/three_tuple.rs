use serde::Serialize;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

/// Network 3-tuple: layer 4 protocol (e.g TCP or UDP), source and destination IP addresses
#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize)]
pub struct ThreeTuple {
    /// Source IP address
    pub src: IpAddr,
    /// Destination IP address
    pub dst: IpAddr,
    /// Layer 4 protocol (e.g TCP, UDP)
    pub l4_proto: u8,
}

impl ThreeTuple {
    pub fn l3_proto(&self) -> u16 {
        match self.src {
            IpAddr::V4(_) => 0x0800,
            IpAddr::V6(_) => 0x86DD,
        }
    }
}

impl Default for ThreeTuple {
    fn default() -> Self {
        ThreeTuple {
            src: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            dst: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            l4_proto: 0,
        }
    }
}

impl fmt::Display for ThreeTuple {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} -> {} [{}]", self.src, self.dst, self.l4_proto)
    }
}
