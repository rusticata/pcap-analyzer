#[derive(Debug, PartialEq, Eq)]
pub enum FilteringAction {
    Keep,
    Drop,
}

impl FilteringAction {
    pub fn of_string(s: &str) -> Result<FilteringAction, String> {
        match s {
            "k" => Ok(FilteringAction::Keep),
            "d" => Ok(FilteringAction::Drop),
            _ => Err(format!(
                "Invalid string as input to build filtering mode: {s} not among k|d"
            )),
        }
    }
}
