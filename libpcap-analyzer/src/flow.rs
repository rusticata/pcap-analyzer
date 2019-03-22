use std::hash::{Hash, Hasher};
use std::convert::From;

use crate::five_tuple::FiveTuple;

pub type FlowID = u64;

#[derive(PartialEq,Eq,Default,Debug)]
pub struct Flow {
    pub flow_id: FlowID,
    pub five_tuple: FiveTuple,
}



impl From<&FiveTuple> for Flow {
    fn from(five_tuple: &FiveTuple) -> Self {
        Flow{
            flow_id: 0,
            five_tuple: five_tuple.clone()
        }
    }
}


impl Hash for Flow {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // skip flow_id
        self.five_tuple.hash(state);
    }
}
