use crate::three_tuple::ThreeTuple;
use std::net::{IpAddr, Ipv4Addr};

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct FiveTuple {
    pub proto: u8,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
}

pub trait ToFiveTuple {
    fn get_five_tuple(&self) -> FiveTuple;
}

impl FiveTuple {
    pub fn from_three_tuple(t3: &ThreeTuple, src_port: u16, dst_port: u16) -> Self {
        FiveTuple {
            proto: t3.proto,
            src: t3.src,
            dst: t3.dst,
            src_port,
            dst_port,
        }
    }
    pub fn get_reverse(&self) -> FiveTuple {
        FiveTuple {
            proto: self.proto,
            src: self.dst,
            dst: self.src,
            src_port: self.dst_port,
            dst_port: self.src_port,
        }
    }
}

impl Default for FiveTuple {
    fn default() -> Self {
        FiveTuple {
            proto: 0,
            src: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            dst: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            src_port: 0,
            dst_port: 0,
        }
    }
}
