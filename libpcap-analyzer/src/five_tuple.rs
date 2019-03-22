use std::net::{IpAddr,Ipv4Addr};

use pnet::packet::Packet;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;

use pnet::packet::ip::IpNextHeaderProtocols;

#[derive(Clone,Debug,Eq,PartialEq,Hash)]
pub struct FiveTuple {
    pub proto:     u8,
    pub src:       IpAddr,
    pub dst:       IpAddr,
    pub src_port:  u16,
    pub dst_port:  u16,
}

pub trait ToFiveTuple {
    fn get_five_tuple(&self) -> FiveTuple;
}


impl FiveTuple {
    pub fn get_reverse(&self) -> FiveTuple {
        FiveTuple{
            proto: self.proto,
            src: self.dst,
            dst: self.src,
            src_port: self.dst_port,
            dst_port: self.src_port,
        }
    }
}

impl Default for FiveTuple {
    fn default() -> Self{
        FiveTuple{
            proto:    0,
            src:      IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            dst:      IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            src_port: 0,
            dst_port: 0,
        }
    }
}

impl<'a> ToFiveTuple for Ipv4Packet<'a> {
    fn get_five_tuple(&self) -> FiveTuple {
        let src = self.get_source();
        let dst = self.get_destination();

        let (proto,sport,dport) =
            match self.get_next_level_protocol() {
                IpNextHeaderProtocols::Tcp => {
                    if let Some(ref tcp) = TcpPacket::new(self.payload()) {
                        (6,tcp.get_source(),tcp.get_destination())
                    } else {
                        (6,0,0)
                    }
                },
                IpNextHeaderProtocols::Udp => {
                    if let Some(ref udp) = UdpPacket::new(self.payload()) {
                        (17,udp.get_source(),udp.get_destination())
                    } else {
                        (17,0,0)
                    }
                },
                _ => (0,0,0),
            };

        FiveTuple{
            proto: proto,
            src: IpAddr::V4(src),
            dst: IpAddr::V4(dst),
            src_port: sport,
            dst_port: dport,
        }
    }
}
