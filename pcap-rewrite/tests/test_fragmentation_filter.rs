use pcap_parser::{Capture, PcapCapture};
use std::env;
use std::fs;
use std::fs::File;
use std::path::Path;
use std::path::PathBuf;

use assert_cmd::Command;

fn count_packet_in_trace(trace_file_path: &Path) -> u32 {
    if trace_file_path.exists() {
        let file = File::open(trace_file_path).unwrap();
        let file_size = file.metadata().unwrap().len();
        if file_size == 0 {
            0
        } else {
            let data = fs::read(trace_file_path).unwrap();
            let cap = PcapCapture::from_file(&data).unwrap();
            let mut count = 0;
            let mut iter = cap.iter();
            while iter.next().is_some() {
                count += 1;
            }
            count
        }
    } else {
        panic!("{:#?} does not exists!", trace_file_path)
    }
}

fn generic_test(
    trace_input_file_s: &str,
    trace_output_file_s: &str,
    filtering_key_s: &str,
    filtering_action_s: &str,
    expected_packet_number: u32,
) {
    let mut trace_input_file_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    trace_input_file_path.push(trace_input_file_s);

    let mut trace_output_file_path = std::env::temp_dir();
    trace_output_file_path.push(trace_output_file_s);

    let mut cmd = Command::cargo_bin(env!("CARGO_PKG_NAME")).unwrap();
    cmd.arg("-f")
        .arg(format!(
            "Fragmentation:{}%{}",
            filtering_key_s, filtering_action_s
        ))
        .arg(&trace_input_file_path)
        .arg(&trace_output_file_path);

    let _output = cmd.output().unwrap();
    println!("Output: {}", std::str::from_utf8(&_output.stdout).unwrap());

    let output_nb_packet = count_packet_in_trace(&trace_output_file_path);

    fs::remove_file(&trace_output_file_path).expect("Could not destroy the filtered file");

    assert_eq!(output_nb_packet, expected_packet_number);
}

// IPV4 preliminary - two packets/fragments scenario

// First packet/fragment is kept.
#[test]
fn test_ipv4_src_ipaddr_single_packet_0_keep() {
    generic_test(
        "../assets/frag_tcp_80_ipv4_sp_frag0.pcap",
        "output_fragmentation_filter_ipv4_src_ip_addr_sp0_keep",
        "si",
        "k",
        1,
    )
}

// Second packet/fragment is dropped because TCP parsing fails (no TCP header).
#[test]
fn test_ipv4_src_ipaddr_single_packet_1_keep() {
    generic_test(
        "../assets/frag_tcp_80_ipv4_sp_frag1.pcap",
        "output_fragmentation_filter_ipv4_src_ip_addr_sp1_keep",
        "si",
        "k",
        0,
    )
}

// IPV4

#[test]
fn test_ipv4_src_ipaddr_keep() {
    generic_test(
        "../assets/frag_tcp_80_ipv4.pcap",
        "output_fragmentation_filter_ipv4_src_ip_addr_keep",
        "si",
        "k",
        3,
    )
}

#[test]
fn test_ipv4_src_ipaddr_drop() {
    generic_test(
        "../assets/frag_tcp_80_ipv4.pcap",
        "output_fragmentation_filter_ipv4_src_ip_addr_drop",
        "si",
        "d",
        2,
    )
}

#[test]
fn test_ipv4_dst_ipaddr_keep() {
    generic_test(
        "../assets/frag_tcp_80_ipv4.pcap",
        "output_fragmentation_filter_ipv4_dst_ip_addr_keep",
        "di",
        "k",
        3,
    )
}

#[test]
fn test_ipv4_dst_ipaddr_drop() {
    generic_test(
        "../assets/frag_tcp_80_ipv4.pcap",
        "output_fragmentation_filter_ipv4_dst_ip_addr_drop",
        "di",
        "d",
        2,
    )
}

#[test]
fn test_ipv4_src_dst_ipaddr_keep() {
    generic_test(
        "../assets/frag_tcp_80_ipv4.pcap",
        "output_fragmentation_filter_ipv4_src_dst_ip_addr",
        "sdi",
        "k",
        5,
    )
}

#[test]
fn test_ipv4_src_dst_ipaddr_drop() {
    generic_test(
        "../assets/frag_tcp_80_ipv4.pcap",
        "output_fragmentation_filter_ipv4_src_dst_ip_addr_drop",
        "sdi",
        "d",
        0,
    )
}

#[test]
fn test_ipv4_src_ipaddr_proto_dst_port_keep() {
    generic_test(
        "../assets/frag_tcp_80_ipv4.pcap",
        "output_fragmentation_filter_ipv4_src_ipaddr_proto_dst_port_keep",
        "sipdp",
        "k",
        3,
    )
}

#[test]
fn test_ipv4_src_ipaddr_proto_dst_port_drop() {
    generic_test(
        "../assets/frag_tcp_80_ipv4.pcap",
        "output_fragmentation_filter_ipv4_src_ipaddr_proto_dst_port_drop",
        "sipdp",
        "d",
        2,
    )
}

#[test]
fn test_ipv4_five_tuple_keep() {
    generic_test(
        "../assets/frag_tcp_80_ipv4.pcap",
        "output_fragmentation_filter_ipv4_five_tuple_keep",
        "sdipsdp",
        "k",
        3,
    )
}

#[test]
fn test_ipv4_five_tuple_drop() {
    generic_test(
        "../assets/frag_tcp_80_ipv4.pcap",
        "output_fragmentation_filter_ipv4_five_tuple_drop",
        "sdipsdp",
        "d",
        2,
    )
}
