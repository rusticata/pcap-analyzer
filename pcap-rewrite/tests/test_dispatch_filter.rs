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
    key_file_s: &str,
    key_s: &str,
    expected_packet_number: u32,
) {
    let mut trace_input_file_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    trace_input_file_path.push(trace_input_file_s);

    let mut trace_output_file_path = std::env::temp_dir();
    trace_output_file_path.push(trace_output_file_s);

    let mut key_file_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    key_file_path.push(key_file_s);

    let mut cmd = Command::cargo_bin(env!("CARGO_PKG_NAME")).unwrap();
    cmd.arg("-f")
        .arg(format!("Dispatch:{}%k%{}", key_s, key_file_path.display()))
        .arg(&trace_input_file_path)
        .arg(&trace_output_file_path);

    let _output = cmd.output().unwrap();
    // println!("Output: {:?}", _output);

    let output_nb_packet = count_packet_in_trace(&trace_output_file_path);

    fs::remove_file(&trace_output_file_path).expect("Could not destroy the filtered file");

    assert_eq!(output_nb_packet, expected_packet_number);
}

// IPV4

#[test]
fn test_filter_ipv4_src_ipaddr() {
    generic_test(
        "../assets/nmap_tcp_22_ipv4.pcap",
        "output_src_ip_addr_ipv4",
        "../assets/pcap-filter/ipv4_ipaddr",
        "si",
        2,
    )
}

#[test]
fn test_filter_ipv4_dst_ipaddr() {
    generic_test(
        "../assets/nmap_tcp_22_ipv4.pcap",
        "output_dst_ip_addr_ipv4",
        "../assets/pcap-filter/ipv4_ipaddr",
        "di",
        2,
    )
}

#[test]
fn test_filter_ipv4_src_dst_ipaddr() {
    generic_test(
        "../assets/nmap_tcp_22_ipv4.pcap",
        "output_src_dst_ip_addr_ipv4",
        "../assets/pcap-filter/ipv4_ipaddr",
        "sdi",
        4,
    )
}

#[test]
fn test_filter_ipv4_src_ipaddr_proto_dst_port() {
    generic_test(
        "../assets/nmap_tcp_22_ipv4.pcap",
        "output_src_ipaddr_proto_dst_port_ipv4",
        "../assets/pcap-filter/ipv4_ipaddr_proto_port",
        "sipdp",
        1,
    )
}

#[test]
fn test_filter_ipv4_five_tuple() {
    generic_test(
        "../assets/nmap_tcp_22_ipv4.pcap",
        "output_five_tuple_ipv4",
        "../assets/pcap-filter/ipv4_five_tuple",
        "sdipsdp",
        2,
    )
}

// IPV6

#[test]
fn test_filter_ipv6_src_ipaddr() {
    generic_test(
        "../assets/nmap_tcp_22_ipv6.pcap",
        "output_src_ipaddr_ipv6.cap",
        "../assets/pcap-filter/ipv6_ipaddr",
        "si",
        2,
    )
}

#[test]
fn test_filter_ipv6_dst_ipaddr() {
    generic_test(
        "../assets/nmap_tcp_22_ipv6.pcap",
        "output_dst_ipaddr_ipv6.cap",
        "../assets/pcap-filter/ipv6_ipaddr",
        "di",
        2,
    )
}

#[test]
fn test_filter_ipv6_src_dst_ipaddr() {
    generic_test(
        "../assets/nmap_tcp_22_ipv6.pcap",
        "output_src_dst_ipaddr_ipv6.cap",
        "../assets/pcap-filter/ipv6_ipaddr",
        "sdi",
        4,
    )
}

#[test]
fn test_filter_ipv6_src_ipaddr_proto_dst_port() {
    generic_test(
        "../assets/nmap_tcp_22_ipv6.pcap",
        "output_src_ipaddr_proto_dst_port_ipv6",
        "../assets/pcap-filter/ipv6_ipaddr_proto_port",
        "sipdp",
        1,
    )
}


#[test]
fn test_filter_ipv6_five_tuple() {
    generic_test(
        "../assets/nmap_tcp_22_ipv6.pcap",
        "output_five_tuple_ipv6",
        "../assets/pcap-filter/ipv6_five_tuple",
        "sdipsdp",
        2,
    )
}
