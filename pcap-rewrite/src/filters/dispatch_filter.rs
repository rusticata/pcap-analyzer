use pcap_parser::data::PacketData;
use pnet_packet::ethernet::{EtherType, EtherTypes};
use pnet_packet::PrimitiveValues;

use crate::filters::filter::FResult;
use crate::filters::filter::Filter;
use crate::filters::filter_utils;

pub struct DispatchFilter<C, D> {
    key_container: C,
    get_key_from_ipv4_l3_data: Box<dyn Fn(&[u8]) -> Result<D, String>>,
    get_key_from_ipv6_l3_data: Box<dyn Fn(&[u8]) -> Result<D, String>>,
    keep: Box<dyn Fn(&C, &D) -> Result<bool, String>>,
}

impl<C, D> DispatchFilter<C, D> {
    pub fn new(
        key_container: C,
        get_key_from_ipv4_l3_data: Box<dyn Fn(&[u8]) -> Result<D, String>>,
        get_key_from_ipv6_l3_data: Box<dyn Fn(&[u8]) -> Result<D, String>>,
        keep: Box<dyn Fn(&C, &D) -> Result<bool, String>>,
    ) -> Self {
        DispatchFilter {
            key_container,
            get_key_from_ipv4_l3_data,
            get_key_from_ipv6_l3_data,
            keep,
        }
    }

    pub fn keep<'j>(&self, packet_data: PacketData<'j>) -> FResult<PacketData<'j>, String> {
        let keep = match packet_data {
            PacketData::L2(data) => {
                if data.len() < 14 {
                    return FResult::Error("L2 data too small for ethernet".to_owned());
                }

                filter_utils::extract_test_callback_ethernet(
                    &self.key_container,
                    &self.get_key_from_ipv4_l3_data,
                    &self.get_key_from_ipv6_l3_data,
                    &self.keep,
                    data,
                )
            }
            PacketData::L3(l3_layer_value_u8, data) => {
                let ether_type = EtherType::new(l3_layer_value_u8 as u16);
                match ether_type {
                    EtherTypes::Ipv4 => filter_utils::extract_test_callback_ipv4(
                        &self.key_container,
                        &self.get_key_from_ipv4_l3_data,
                        &self.keep,
                        data,
                    ),
                    EtherTypes::Ipv6 => filter_utils::extract_test_callback_ipv6(
                        &self.key_container,
                        &self.get_key_from_ipv6_l3_data,
                        &self.keep,
                        data,
                    ),
                    _ => Err(format!(
                        "Unimplemented Ethertype in L3 {:?}/{:x}",
                        ether_type,
                        ether_type.to_primitive_values().0
                    )),
                }
            }
            PacketData::L4(_, _) => unimplemented!(),
            PacketData::Unsupported(_) => unimplemented!(),
        };
        match keep {
            Ok(b) => {
                if b {
                    FResult::Ok(packet_data)
                } else {
                    FResult::Drop
                }
            }
            Err(s) => FResult::Error(s),
        }
    }
}

impl<C, D> Filter for DispatchFilter<C, D> {
    fn filter<'i>(&self, i: PacketData<'i>) -> FResult<PacketData<'i>, String> {
        self.keep(i)
    }
}
