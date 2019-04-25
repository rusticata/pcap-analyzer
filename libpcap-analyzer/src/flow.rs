use std::hash::{Hash, Hasher};

use crate::five_tuple::FiveTuple;
use crate::duration::Duration;

pub type FlowID = u64;

#[derive(PartialEq, Eq, Default, Debug)]
pub struct Flow {
    pub flow_id: FlowID,
    pub five_tuple: FiveTuple,
    /// timestamp of first packet
    pub first_seen: Duration,
}

impl Flow {
    pub fn new(five_tuple: &FiveTuple, ts_sec: u32, ts_usec: u32) -> Self {
        Flow {
            flow_id: 0,
            five_tuple: five_tuple.clone(),
            first_seen: Duration::new(ts_sec, ts_usec),
        }
    }
}

impl Hash for Flow {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // skip flow_id
        self.five_tuple.hash(state);
        self.first_seen.hash(state);
    }
}
