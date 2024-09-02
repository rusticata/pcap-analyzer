use std::collections::HashSet;

use crate::filters::fragmentation::two_tuple_proto_ipid::TwoTupleProtoIpid;

#[derive(Debug)]
pub struct TwoTupleProtoIpidC {
    s: HashSet<TwoTupleProtoIpid>,
}

impl TwoTupleProtoIpidC {
    pub fn new(s: HashSet<TwoTupleProtoIpid>) -> TwoTupleProtoIpidC {
        TwoTupleProtoIpidC { s }
    }

    pub fn contains(&self, five_tuple: &TwoTupleProtoIpid) -> bool {
        self.s.contains(five_tuple)
    }
}
