use std::collections::HashSet;
use std::error::Error;
use std::fs::File;
use std::iter::FromIterator;
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;

use csv::ReaderBuilder;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IpAddrC {
    s: HashSet<IpAddr>,
}

impl IpAddrC {
    pub fn new(s: HashSet<IpAddr>) -> IpAddrC {
        IpAddrC { s }
    }

    pub fn of_file_path(ip_file_path: &Path) -> Result<IpAddrC, Box<dyn Error>> {
        let file = File::open(ip_file_path)?;

        let mut rdr = ReaderBuilder::new().has_headers(false).from_reader(file);
        let s_v = rdr
            .records()
            .map(|l| {
                let record = l?;
                let s: &str = record
                    .get(0)
                    .ok_or_else(|| "Empty line in dispatch filter key file".to_string())?;
                Ok(s.to_string())
            })
            .collect::<Result<Vec<String>, Box<dyn Error>>>()?;

        let ip_v = s_v
            .iter()
            .map(|s| IpAddr::from_str(s).map_err(|e| e.to_string()))
            .collect::<Result<Vec<IpAddr>, String>>()?;
        let ip_hs = HashSet::from_iter(ip_v.iter().cloned());

        Ok(IpAddrC::new(ip_hs))
    }

    // pub fn is_empty(&self) -> bool {
    //     self.s.is_empty()
    // }

    // pub fn len(&self) -> usize {
    //     self.s.len()
    // }

    pub fn contains(&self, ipaddr: &IpAddr) -> bool {
        self.s.contains(ipaddr)
    }
}
