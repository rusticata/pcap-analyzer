use std::collections::HashSet;

use crate::filters::fragmentation::two_tuple_proto_ipid::TwoTupleProtoIpid;

pub struct TwoTupleProtoIpidC {
    s0: HashSet<TwoTupleProtoIpid>,
    s1: HashSet<TwoTupleProtoIpid>,
}

impl TwoTupleProtoIpidC {
    pub fn new(
        s0: HashSet<TwoTupleProtoIpid>,
        s1: HashSet<TwoTupleProtoIpid>,
    ) -> TwoTupleProtoIpidC {
        TwoTupleProtoIpidC { s0, s1 }
    }

    // pub fn is_empty(&self) -> bool {
    //     self.s0.is_empty() && self.s1.is_empty()
    // }

    // pub fn len(&self) -> usize {
    //     self.s0.len() + self.s1.len()
    // }

    pub fn contains(&self, five_tuple: &TwoTupleProtoIpid) -> bool {
        self.s0.contains(five_tuple) || self.s1.contains(five_tuple)
    }
}
