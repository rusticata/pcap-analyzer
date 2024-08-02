use std::net::IpAddr;

pub struct IpAddrPair {
    ipaddr_0: IpAddr,
    ipaddr_1: IpAddr,
}

impl IpAddrPair {
    pub fn new(ipaddr_0: IpAddr, ipaddr_1: IpAddr) -> IpAddrPair {
        IpAddrPair { ipaddr_0, ipaddr_1 }
    }

    pub fn get_ipaddr_0(&self) -> &IpAddr {
        &self.ipaddr_0
    }

    pub fn get_ipaddr_1(&self) -> &IpAddr {
        &self.ipaddr_1
    }
}
