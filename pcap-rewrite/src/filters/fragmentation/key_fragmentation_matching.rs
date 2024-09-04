use crate::filters::fragmentation::two_tuple_proto_ipid::TwoTupleProtoIpid;

/// Contains either FiveTuple or TwoTupleProtoIpid or both.
/// It is used to store data that will be matched against the data of the first fragment.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum KeyFragmentationMatching<Key> {
    /// Packet is not a fragment.
    NotFragment(Key),
    /// Packet is a first fragment.
    FirstFragment(TwoTupleProtoIpid, Key),
    /// Packet is a fragment, but not the first one.
    FragmentAfterFirst(TwoTupleProtoIpid),
}
