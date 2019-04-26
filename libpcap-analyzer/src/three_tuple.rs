use std::net::{IpAddr, Ipv4Addr};

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ThreeTuple {
    pub proto: u8,
    pub src: IpAddr,
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
