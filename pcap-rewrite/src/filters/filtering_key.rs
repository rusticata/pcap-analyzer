#[derive(Debug)]
pub enum FilteringKey {
    SrcIpaddr,
    DstIpaddr,
    SrcDstIpaddr,
}

impl FilteringKey {
    pub fn of_string(s: &str) -> Result<FilteringKey, String> {
        match s {
            "si" => Ok(FilteringKey::SrcIpaddr),
            "di" => Ok(FilteringKey::DstIpaddr),
            "sdi" => Ok(FilteringKey::SrcDstIpaddr),
            _ => Err(format!(
                "Invalid string as input to build filtering criterion: {} not among si|di|sdi",
                s
            )),
        }
    }
}
