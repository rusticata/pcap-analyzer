use crate::Duration;
use std::hash::{Hash, Hasher};

use crate::five_tuple::FiveTuple;

/// Unique `Flow` identifier
#[allow(clippy::upper_case_acronyms)]
pub type FlowID = u64;

/// Network flow information
#[derive(Clone, PartialEq, Eq, Default, Debug)]
pub struct Flow {
    /// The `Flow` identifier
    pub flow_id: FlowID,
    /// The `FiveTuple` identifying the `Flow`
    pub five_tuple: FiveTuple,
    /// timestamp of first packet
    pub first_seen: Duration,
    /// timestamp of last seen packet
    pub last_seen: Duration,
}

impl Flow {
    pub fn new(five_tuple: &FiveTuple, ts_sec: u32, ts_usec: u32) -> Self {
        let d = Duration::new(ts_sec, ts_usec);
        Flow {
            flow_id: 0,
            five_tuple: five_tuple.clone(),
            first_seen: d,
            last_seen: d,
        }
    }
}

#[allow(clippy::derive_hash_xor_eq)]
impl Hash for Flow {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // skip flow_id
        self.five_tuple.hash(state);
        self.first_seen.hash(state);
        // skip last seen
    }
}
