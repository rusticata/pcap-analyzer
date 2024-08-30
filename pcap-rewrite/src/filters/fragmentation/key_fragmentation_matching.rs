use libpcap_tools::FiveTuple;

use crate::filters::fragmentation::two_tuple_proto_ipid::TwoTupleProtoIpid;

/// Contains either FiveTuple or TwoTupleProtoIpid.
/// It is used to store data that will be matched against the data of the first fragment.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum KeyFragmentationMatching {
    /// Packet is either not a fragment, or the first one.
    NotFragmentOrFirstFragment(FiveTuple),
    /// Packet is a fragment, but not the first one.
    FragmentAfterFirst(TwoTupleProtoIpid),
}

impl KeyFragmentationMatching {
    pub fn get_two_tuple_proto_ipid_option(&self) -> Option<&TwoTupleProtoIpid> {
        match self {
            KeyFragmentationMatching::FragmentAfterFirst(two_tuple_proto_ipid) => {
                Some(two_tuple_proto_ipid)
            }
            KeyFragmentationMatching::NotFragmentOrFirstFragment(_) => None,
        }
    }

    pub fn get_five_tuple_option(&self) -> Option<&FiveTuple> {
        match self {
            KeyFragmentationMatching::FragmentAfterFirst(_) => None,
            KeyFragmentationMatching::NotFragmentOrFirstFragment(five_tuple) => Some(five_tuple),
        }
    }
}
