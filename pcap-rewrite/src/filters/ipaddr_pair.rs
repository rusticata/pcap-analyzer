use std::net::IpAddr;

pub struct IpAddrPair(pub IpAddr, pub IpAddr);

impl IpAddrPair {
    pub fn new(ipaddr_0: IpAddr, ipaddr_1: IpAddr) -> IpAddrPair {
        IpAddrPair(ipaddr_0, ipaddr_1)
    }
}
