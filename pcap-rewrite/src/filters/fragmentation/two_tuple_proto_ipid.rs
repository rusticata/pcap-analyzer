use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

/// Network 2-tuple (src/dst IP address) + IP protocol + IP ID
#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct TwoTupleProtoIpid {
    /// Layer 4 protocol (e.g TCP, UDP, ICMP)
    pub proto: u8,
    /// Source IP address
    pub src: IpAddr,
    /// Destination IP address
    pub dst: IpAddr,
    /// PI id.
    pub ip_id: u32,
}

impl fmt::Display for TwoTupleProtoIpid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{} -> {} [{},{}]",
            self.src, self.dst, self.proto, self.ip_id
        )
    }
}

impl TwoTupleProtoIpid {
    /// Creates a `TwoTupleProtoIpid` from scratch
    pub fn new(src: IpAddr, dst: IpAddr, proto: u8, ip_id: u32) -> TwoTupleProtoIpid {
        TwoTupleProtoIpid {
            proto,
            src,
            dst,
            ip_id,
        }
    }

    /// Returns the opposite `TwoTupleProtoIpid` (swaps IP addresses)
    pub fn get_reverse(&self) -> TwoTupleProtoIpid {
        TwoTupleProtoIpid {
            proto: self.proto,
            src: self.dst,
            dst: self.src,
            ip_id: self.ip_id,
        }
    }
}

impl Default for TwoTupleProtoIpid {
    fn default() -> Self {
        TwoTupleProtoIpid {
            proto: 0,
            src: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            dst: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            ip_id: 0,
        }
    }
}
