use libpcap_tools::FiveTuple;

use crate::filters::fragmentation::two_tuple_proto_ipid::TwoTupleProtoIpid;

/// Contains both FiveTuple or TwoTupleProtoIpid.
/// It is used to store data from the first fragment.
#[derive(Debug, Default, PartialEq, Eq, Hash, Clone)]
pub struct TwoTupleProtoIpidFiveTuple {
    /// Src/dst/proto/IP ID of the first fragment
    two_tuple_proto_ipid_option: Option<TwoTupleProtoIpid>,
    /// Five tuple of the first fragment
    five_tuple_option: Option<FiveTuple>,
}

impl TwoTupleProtoIpidFiveTuple {
    pub fn new(
        two_tuple_proto_ipid_option: Option<TwoTupleProtoIpid>,
        five_tuple_option: Option<FiveTuple>,
    ) -> Self {
        TwoTupleProtoIpidFiveTuple {
            two_tuple_proto_ipid_option,
            five_tuple_option,
        }
    }

    pub fn get_two_tuple_proto_ipid_option(&self) -> Option<&TwoTupleProtoIpid> {
        self.two_tuple_proto_ipid_option.as_ref()
    }

    pub fn get_five_tuple_option(&self) -> Option<&FiveTuple> {
        self.five_tuple_option.as_ref()
    }
}
