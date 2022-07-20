#[derive(Debug)]
pub enum FilteringKey {
    SrcIpaddr,
    DstIpaddr,
}

impl FilteringKey {
    pub fn of_string(s: &str) -> Result<FilteringKey, String> {
        match s {
            "si" => Ok(FilteringKey::SrcIpaddr),
            "di" => Ok(FilteringKey::DstIpaddr),
            _ => Err(format!(
                "Invalid string as input to build filtering criterion: {} not among si|di",
                s
            )),
        }
    }
}
