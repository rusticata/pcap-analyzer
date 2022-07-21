#[derive(Debug)]
pub enum FilteringKey {
    SrcIpaddr,
    DstIpaddr,
    SrcDstIpaddr,
    SrcIpaddrProtoDstPort,
}

impl FilteringKey {
    pub fn of_string(s: &str) -> Result<FilteringKey, String> {
        match s {
            "si" => Ok(FilteringKey::SrcIpaddr),
            "di" => Ok(FilteringKey::DstIpaddr),
            "sdi" => Ok(FilteringKey::SrcDstIpaddr),
            "sipdp" => Ok(FilteringKey::SrcIpaddrProtoDstPort),
            _ => Err(format!(
                "Invalid string as input to build filtering criterion: {} not among si|di|sdi|sipdp",
                s
            )),
        }
    }
}
