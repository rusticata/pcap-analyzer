use crate::filters::fragmentation::two_tuple_proto_ipid::TwoTupleProtoIpid;

#[derive(Debug, Default, PartialEq, Eq, Hash, Clone)]
pub struct TwoTupleProtoIpidKey<Key> {
    two_tuple_proto_ipid_option: Option<TwoTupleProtoIpid>,
    key_option: Option<Key>,
}

impl<Key> TwoTupleProtoIpidKey<Key> {
    pub fn new(
        two_tuple_proto_ipid_option: Option<TwoTupleProtoIpid>,
        key_option: Option<Key>,
    ) -> Self {
        TwoTupleProtoIpidKey {
            two_tuple_proto_ipid_option,
            key_option,
        }
    }

    pub fn get_two_tuple_proto_ipid_option(&self) -> Option<&TwoTupleProtoIpid> {
        self.two_tuple_proto_ipid_option.as_ref()
    }

    pub fn get_key_option(&self) -> Option<&Key> {
        self.key_option.as_ref()
    }
}
