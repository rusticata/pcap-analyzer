use std::collections::HashSet;
use std::iter::FromIterator;

use pnet_packet::ip::IpNextHeaderProtocol;

use libpcap_tools::FiveTuple;

use crate::container::five_tuple_container::FiveTupleC;
use crate::container::ipaddr_container::IpAddrC;
use crate::container::ipaddr_proto_port_container::{IpAddrProtoPort, IpAddrProtoPortC};
use crate::container::two_tuple_proto_ipid_container::TwoTupleProtoIpidC;
use crate::filters::fragmentation::two_tuple_proto_ipid_five_tuple::TwoTupleProtoIpidFiveTuple;

pub fn convert_data_hs_to_src_ipaddrc(data_hs: &HashSet<TwoTupleProtoIpidFiveTuple>) -> IpAddrC {
    let src_ipaddr_iter = data_hs
        .iter()
        .filter_map(|t| t.get_five_tuple_option())
        .map(|five_tuple| five_tuple.src);
    let src_ipaddr_hs = HashSet::from_iter(src_ipaddr_iter);
    IpAddrC::new(src_ipaddr_hs)
}

pub fn convert_data_hs_to_dst_ipaddrc(data_hs: &HashSet<TwoTupleProtoIpidFiveTuple>) -> IpAddrC {
    let dst_ipaddr_iter = data_hs
        .iter()
        .filter_map(|t| t.get_five_tuple_option())
        .map(|five_tuple| five_tuple.dst);
    let dst_ipaddr_hs = HashSet::from_iter(dst_ipaddr_iter);
    IpAddrC::new(dst_ipaddr_hs)
}

pub fn convert_data_hs_to_src_dst_ipaddrc(
    data_hs: &HashSet<TwoTupleProtoIpidFiveTuple>,
) -> IpAddrC {
    let src_ipaddr_iter = data_hs
        .iter()
        .filter_map(|t| t.get_five_tuple_option())
        .map(|five_tuple| five_tuple.src);
    let dst_ipaddr_iter = data_hs
        .iter()
        .filter_map(|t| t.get_five_tuple_option())
        .map(|five_tuple| five_tuple.dst);
    let src_dst_ipaddr_hs = HashSet::from_iter(src_ipaddr_iter.chain(dst_ipaddr_iter));
    IpAddrC::new(src_dst_ipaddr_hs)
}

pub fn convert_data_hs_to_src_ipaddr_proto_dst_port_container(
    data_hs: &HashSet<TwoTupleProtoIpidFiveTuple>,
) -> IpAddrProtoPortC {
    let src_ipaddr_proto_dst_port_iter = data_hs
        .iter()
        .filter_map(|t| t.get_five_tuple_option())
        .map(|five_tuple| {
            IpAddrProtoPort::new(
                five_tuple.src,
                IpNextHeaderProtocol::new(five_tuple.proto),
                five_tuple.dst_port,
            )
        });
    let dst_ipaddr_proto_src_port_iter = data_hs
        .iter()
        .filter_map(|t| t.get_five_tuple_option())
        .map(|five_tuple| {
            IpAddrProtoPort::new(
                five_tuple.dst,
                IpNextHeaderProtocol::new(five_tuple.proto),
                five_tuple.src_port,
            )
        });
    let ipaddr_proto_port_hs =
        HashSet::from_iter(src_ipaddr_proto_dst_port_iter.chain(dst_ipaddr_proto_src_port_iter));
    IpAddrProtoPortC::new(ipaddr_proto_port_hs)
}

pub fn convert_data_hs_to_ctuple(
    data_hs: &HashSet<TwoTupleProtoIpidFiveTuple>,
) -> (TwoTupleProtoIpidC, FiveTupleC) {
    let two_tuple_proto_ipid_hs: HashSet<_> = data_hs
        .iter()
        .filter_map(|two_tuple_proto_ipid_five_tuple| {
            two_tuple_proto_ipid_five_tuple.get_two_tuple_proto_ipid_option()
        })
        .cloned()
        .collect();
    let two_tuple_proto_ipid_hs_reversed = two_tuple_proto_ipid_hs
        .iter()
        .map(|two_tuple_proto_ipid| two_tuple_proto_ipid.get_reverse())
        .collect();
    let two_tuple_proto_ipid_container =
        TwoTupleProtoIpidC::new(two_tuple_proto_ipid_hs, two_tuple_proto_ipid_hs_reversed);

    let five_tuple_hs: HashSet<FiveTuple> = data_hs
        .iter()
        .filter_map(|two_tuple_proto_ipid_five_tuple| {
            two_tuple_proto_ipid_five_tuple.get_five_tuple_option()
        })
        .cloned()
        .collect();
    let five_tuple_hs_reversed = five_tuple_hs
        .iter()
        .map(|five_tuple| five_tuple.get_reverse())
        .collect();
    let five_tuple_c = FiveTupleC::new(five_tuple_hs, five_tuple_hs_reversed);

    (two_tuple_proto_ipid_container, five_tuple_c)
}
