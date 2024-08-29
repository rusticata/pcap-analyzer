use std::collections::HashSet;
use std::error::Error;
use std::fs::File;
use std::iter::FromIterator;
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;

use csv::ReaderBuilder;
use pnet_packet::ip::IpNextHeaderProtocol;

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct IpAddrProtoPort {
    ipaddr: IpAddr,
    proto: IpNextHeaderProtocol,
    port: u16,
}

impl IpAddrProtoPort {
    pub fn new(ipaddr: IpAddr, proto: IpNextHeaderProtocol, port: u16) -> IpAddrProtoPort {
        IpAddrProtoPort {
            ipaddr,
            proto,
            port,
        }
    }
}

pub struct IpAddrProtoPortC {
    s: HashSet<IpAddrProtoPort>,
}

impl IpAddrProtoPortC {
    pub fn new(s: HashSet<IpAddrProtoPort>) -> IpAddrProtoPortC {
        IpAddrProtoPortC { s }
    }

    pub fn of_file_path(ip_file_path: &Path) -> Result<IpAddrProtoPortC, Box<dyn Error>> {
        let file = File::open(ip_file_path)?;

        let mut rdr = ReaderBuilder::new().has_headers(false).from_reader(file);
        let ipaddr_proto_port_v = rdr
            .records()
            .map(|l| {
                let record = l?;

                // TODO: improve field parsing error message

                let ipaddr_s: &str = record.get(0).ok_or_else(|| {
                    "Missing IpAddr value in dispatch filter key file".to_string()
                })?;
                let ipaddr = IpAddr::from_str(ipaddr_s).map_err(|e| e.to_string())?;

                let protocol_s: &str = record.get(1).ok_or_else(|| {
                    "Missing protocol value in dispatch filter key file".to_string()
                })?;
                let protocol_u8 = protocol_s.parse()?;
                let protocol = IpNextHeaderProtocol::new(protocol_u8);

                let port_s: &str = record
                    .get(2)
                    .ok_or_else(|| "Missing port value in dispatch filter key file".to_string())?;
                let port = port_s.parse()?;

                Ok(IpAddrProtoPort::new(ipaddr, protocol, port))
            })
            .collect::<Result<Vec<IpAddrProtoPort>, Box<dyn Error>>>()?;

        let hs = HashSet::from_iter(ipaddr_proto_port_v.iter().cloned());

        Ok(IpAddrProtoPortC::new(hs))
    }

    pub fn contains(&self, ipaddr_proto_port: &IpAddrProtoPort) -> bool {
        self.s.contains(ipaddr_proto_port)
    }
}
