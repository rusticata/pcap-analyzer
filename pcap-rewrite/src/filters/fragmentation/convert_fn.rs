use std::collections::HashSet;

use pnet_packet::ip::IpNextHeaderProtocol;

use crate::container::five_tuple_container::FiveTupleC;
use crate::container::ipaddr_container::IpAddrC;
use crate::container::ipaddr_proto_port_container::IpAddrProtoPortC;
use crate::container::two_tuple_proto_ipid_container::TwoTupleProtoIpidC;
use crate::filters::fragmentation::two_tuple_proto_ipid_five_tuple::TwoTupleProtoIpidFiveTuple;

pub fn convert_data_hs_to_src_ipaddrc(data_hs: &HashSet<TwoTupleProtoIpidFiveTuple>) -> IpAddrC {
    let src_ipaddr_hs: HashSet<_> = data_hs
        .iter()
        .filter_map(|three_five_tuple| three_five_tuple.get_five_tuple_option().clone())
        .map(|five_tuple| five_tuple.src)
        .collect();
    IpAddrC::new(src_ipaddr_hs)
}

pub fn convert_data_hs_to_dst_ipaddrc(data_hs: &HashSet<TwoTupleProtoIpidFiveTuple>) -> IpAddrC {
    let dst_ipaddr_hs: HashSet<_> = data_hs
        .iter()
        .filter_map(|three_five_tuple| three_five_tuple.get_five_tuple_option().clone())
        .map(|five_tuple| five_tuple.dst)
        .collect();
    IpAddrC::new(dst_ipaddr_hs)
}

pub fn convert_data_hs_to_src_dst_ipaddrc(
    data_hs: &HashSet<TwoTupleProtoIpidFiveTuple>,
) -> IpAddrC {
    let mut src_dst_ipaddr_v: Vec<_> = data_hs
        .iter()
        .filter_map(|three_five_tuple| three_five_tuple.get_five_tuple_option().clone())
        .map(|five_tuple| five_tuple.src)
        .collect();
    let mut dst_ipaddr_v: Vec<_> = data_hs
        .iter()
        .filter_map(|three_five_tuple| three_five_tuple.get_five_tuple_option().clone())
        .map(|five_tuple| five_tuple.dst)
        .collect();
    let mut v = vec![];
    v.append(&mut src_dst_ipaddr_v);
    v.append(&mut dst_ipaddr_v);
    let hs = v.into_iter().collect();
    IpAddrC::new(hs)
}

pub fn convert_data_hs_to_src_ipaddr_proto_dst_port_container(
    data_hs: &HashSet<TwoTupleProtoIpidFiveTuple>,
) -> IpAddrProtoPortC {
    let mut src_ipaddr_v: Vec<_> = data_hs
        .iter()
        .filter_map(|three_five_tuple| three_five_tuple.get_five_tuple_option().clone())
        .map(|five_tuple| {
            (
                five_tuple.src,
                IpNextHeaderProtocol::new(five_tuple.proto),
                five_tuple.dst_port,
            )
        })
        .collect();
    let mut dst_ipaddr_v: Vec<_> = data_hs
        .iter()
        .filter_map(|three_five_tuple| three_five_tuple.get_five_tuple_option().clone())
        .map(|five_tuple| {
            (
                five_tuple.dst,
                IpNextHeaderProtocol::new(five_tuple.proto),
                five_tuple.src_port,
            )
        })
        .collect();
    let mut v = vec![];
    v.append(&mut src_ipaddr_v);
    v.append(&mut dst_ipaddr_v);
    let hs = v.into_iter().collect();
    IpAddrProtoPortC::new(hs)
}

pub fn convert_data_hs_to_ctuple(
    data_hs: &HashSet<TwoTupleProtoIpidFiveTuple>,
) -> (TwoTupleProtoIpidC, FiveTupleC) {
    let two_tuple_proto_ipid_hs: HashSet<_> = data_hs
        .iter()
        .filter_map(|three_five_tuple| three_five_tuple.get_two_tuple_proto_ipid_option().clone())
        .collect();
    let two_tuple_proto_ipid_hs_reversed = two_tuple_proto_ipid_hs
        .iter()
        .map(|two_tuple_proto_ipid| two_tuple_proto_ipid.get_reverse())
        .collect();
    let two_tuple_proto_ipid_container =
        TwoTupleProtoIpidC::new(two_tuple_proto_ipid_hs, two_tuple_proto_ipid_hs_reversed);

    let five_tuple_hs: HashSet<_> = data_hs
        .iter()
        .filter_map(|three_five_tuple| three_five_tuple.get_five_tuple_option().clone())
        .collect();
    let five_tuple_hs_reversed = five_tuple_hs
        .iter()
        .map(|five_tuple| five_tuple.get_reverse())
        .collect();
    let five_tuple_c = FiveTupleC::new(five_tuple_hs, five_tuple_hs_reversed);

    (two_tuple_proto_ipid_container, five_tuple_c)
}
