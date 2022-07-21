use std::collections::HashSet;
use std::error::Error;
use std::fs::File;
use std::iter::FromIterator;
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;

use csv::ReaderBuilder;

use libpcap_tools::FiveTuple;

#[derive(Clone, Debug)]
pub struct FiveTupleC {
    s0: HashSet<FiveTuple>,
    s1: HashSet<FiveTuple>,
}

impl FiveTupleC {
    pub fn new(s0: HashSet<FiveTuple>, s1: HashSet<FiveTuple>) -> FiveTupleC {
        FiveTupleC { s0, s1 }
    }

    pub fn of_file_path(path: &Path) -> Result<FiveTupleC, Box<dyn Error>> {
        let file = File::open(path)?;

        let mut rdr = ReaderBuilder::new().has_headers(false).from_reader(file);
        let five_tuple_v = rdr
            .records()
            .map(|l| {
                let record = l?;

                // TODO: improve field parsing error message

                let src_ipaddr_s: &str = record.get(0).ok_or_else(|| {
                    "Missing src IpAddr value in dispatch filter key file".to_string()
                })?;
                let src_ipaddr = IpAddr::from_str(src_ipaddr_s).map_err(|e| e.to_string())?;

                let dst_ipaddr_s: &str = record.get(1).ok_or_else(|| {
                    "Missing src IpAddr value in dispatch filter key file".to_string()
                })?;
                let dst_ipaddr = IpAddr::from_str(dst_ipaddr_s).map_err(|e| e.to_string())?;

                let protocol_s: &str = record.get(2).ok_or_else(|| {
                    "Missing protocol value in dispatch filter key file".to_string()
                })?;
                let protocol_u8 = protocol_s
                    .parse()
                    .map_err(|e| format!("Error parsing protocol: {}", e))?;

                let src_port_s: &str = record.get(3).ok_or_else(|| {
                    "Missing src port value in dispatch filter key file".to_string()
                })?;
                let src_port = src_port_s.parse()?;

                let dst_port_s: &str = record.get(4).ok_or_else(|| {
                    "Missing dst port value in dispatch filter key file".to_string()
                })?;
                let dst_port = dst_port_s.parse()?;

                Ok(FiveTuple {
                    src: src_ipaddr,
                    dst: dst_ipaddr,
                    proto: protocol_u8,
                    src_port,
                    dst_port,
                })
            })
            .collect::<Result<Vec<FiveTuple>, Box<dyn Error>>>()?;

        let hs0 = HashSet::from_iter(five_tuple_v.iter().cloned());

        let five_tuple_v_reversed = five_tuple_v
            .iter()
            .map(|five_tuple| five_tuple.get_reverse())
            .collect::<Vec<_>>();
        let hs1 = HashSet::from_iter(five_tuple_v_reversed.iter().cloned());

        Ok(FiveTupleC::new(hs0, hs1))
    }

    // pub fn is_empty(&self) -> bool {
    //     self.s0.is_empty() && self.s1.is_empty()
    // }

    // pub fn len(&self) -> usize {
    //     self.s0.len() + self.s1.len()
    // }

    pub fn contains(&self, five_tuple: &FiveTuple) -> bool {
        self.s0.contains(five_tuple) || self.s1.contains(five_tuple)
    }
}
