#![warn(clippy::all)]

use pcap_info::*;

use clap::Parser;
use pcap_parser::OptionCode;
use time::UtcOffset;

use std::convert::TryInto;
use std::fs;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::process;
use std::str;

/// Pcap information tool
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Do not check file structure
    #[arg(short, long)]
    no_check: bool,

    /// Input file
    input: String,
}

fn main() -> Result<(), io::Error> {
    let args = Args::parse();

    let input_filename = &args.input;
    let options = Options {
        check_file: !args.no_check,
    };

    let (rc, info) = pcap_info(input_filename, &options)?;
    display_pcap_info(input_filename, &info);

    process::exit(rc);
}

fn display_pcap_info(name: &str, info: &PcapInfo) {
    println!("File name: {}", name);

    if name != "-" {
        let metadata = fs::metadata(name).unwrap();
        println!("  size: {}", metadata.len());
    }
    let file_type_s = match info.file_type() {
        FileType::Pcap => "Legacy Pcap",
        FileType::PcapNG => "Pcap-NG",
    };
    println!("Type: {}", file_type_s);
    println!("Version: {}.{}", info.version_major, info.version_minor);

    println!("{:<20}: {:x}", "SHA256", info.sha256());
    println!("{:<20}: {:x}", "BLAKE2S256", info.blakes256());
    println!("{:<20}: {:x}", "SHA1", info.sha1());

    let local_offset = UtcOffset::current_local_offset().expect("time: could not get local offset");
    let first_ts = info.first_packet().unwrap();
    let last_ts = info.last_packet().unwrap();
    let cap_duration = info.capture_duration();
    println!(
        "{:<20}: {}.{:.6} seconds",
        "Capture duration",
        cap_duration.as_seconds_f32(),
        cap_duration.subsec_microseconds()
    );
    // println!("{:<20}: {}", "Capture duration", cap_duration);
    println!(
        "{:<20}: {}",
        "First packet time",
        first_ts.to_offset(local_offset)
    );
    println!(
        "{:<20}: {}",
        "Last packet time",
        last_ts.to_offset(local_offset)
    );
    println!("{:<20}: {}", "Strict time order", info.strict_time_order);
    println!("{:<20}: {}", "Number of blocks", info.block_index);
    println!("{:<20}: {}", "Number of packets", info.packet_index);
    println!("{:<20}: {} bytes", "File size", info.file_bytes);
    println!("{:<20}: {} bytes", "Data size", info.data_bytes);
    let bit_rate = info.data_bytes as f64 / cap_duration.as_seconds_f64();
    println!("{:<20}: {:.0} bytes/s", "Data byte rate", bit_rate);
    println!("{:<20}: {:.0} kbps/s", "Data bit rate", bit_rate * 0.008);
    println!(
        "{:<20}: {:.2} bytes",
        "Average packet size",
        info.data_bytes as f64 / info.packet_index as f64
    );
    println!(
        "{:<20}: {:.0} packets/s",
        "Average packet rate",
        info.packet_index as f64 / cap_duration.as_seconds_f64()
    );

    for (idx, section_info) in info.sections.iter().enumerate() {
        println!("Section #{}", idx);
        display_section_info(section_info);
    }
}

fn display_section_info(info: &SectionInfo) {
    let native_s = if info.native_endian {
        "Native"
    } else {
        "Reverse"
    };
    println!("  Byte Ordering: {}", native_s);

    for (opt_code, opt_value) in &info.options {
        print!("    ");
        pretty_print_shb_option(*opt_code, opt_value);
    }

    if info.num_ipv4_resolved > 0 {
        println!(
            "  {:<20}: {}",
            "Number of IPv4 resolved", info.num_ipv4_resolved
        );
    }
    if info.num_ipv6_resolved > 0 {
        println!(
            "  {:<20}: {}",
            "Number of IPv6 resolved", info.num_ipv6_resolved
        );
    }
    if info.num_secrets_blocks > 0 {
        println!(
            "  {:<20}: {}",
            "Number of decryption secrets blocks", info.num_secrets_blocks
        );
    }
    if info.num_custom_blocks > 0 {
        println!(
            "  {:<20}: {}",
            "Number of custom blocks", info.num_custom_blocks
        );
    }

    println!(
        "{:<20}: {}",
        "  Number of interfaces",
        info.interfaces.len()
    );
    for interface in &info.interfaces {
        pretty_print_interface(interface);
    }
}

fn pretty_print_interface(if_info: &InterfaceInfo) {
    println!("Interface #{} description:", if_info.if_index);
    println!("    Index: {}", if_info.if_index);
    println!(
        "    Encapsulation: {} ({})",
        if_info.link_type, if_info.link_type.0
    );
    println!("    Capture length: {}", if_info.snaplen);
    println!("    Number of packets: {}", if_info.num_packets);
    println!("    Number of stat entries: {}", if_info.num_stats);
    for (opt_code, opt_value) in &if_info.options {
        print!("    ");
        pretty_print_idb_option(*opt_code, opt_value);
    }
}

fn pretty_print_shb_option(code: OptionCode, value: &[u8]) {
    match code {
        OptionCode::Comment => {
            let s = str::from_utf8(value).unwrap_or("<Invalid UTF-8>");
            println!("Hardware: {}", s);
        }
        OptionCode::EndOfOpt => println!("End of Options"),
        OptionCode::ShbHardware => {
            let s = str::from_utf8(value).unwrap_or("<Invalid UTF-8>");
            println!("Hardware Description: {}", s);
        }
        OptionCode::ShbOs => {
            let s = str::from_utf8(value).unwrap_or("<Invalid UTF-8>");
            println!("OS Description: {}", s);
        }
        OptionCode::ShbUserAppl => {
            let s = str::from_utf8(value).unwrap_or("<Invalid UTF-8>");
            println!("User Application: {}", s);
        }
        OptionCode(_) => {
            let s = str::from_utf8(value).unwrap_or("<Invalid UTF-8>");
            println!("Option {}: {}", code, s);
        }
    }
}

fn pretty_print_idb_option(code: OptionCode, value: &[u8]) {
    match code {
        OptionCode::Comment => {
            let s = str::from_utf8(value).unwrap_or("<Invalid UTF-8>");
            println!("Hardware: {}", s);
        }
        OptionCode::EndOfOpt => println!("End of Options"),
        OptionCode(2) => {
            let s = str::from_utf8(value).unwrap_or("<Invalid UTF-8>");
            println!("Name: {}", s);
        }
        OptionCode(3) => {
            let s = str::from_utf8(value).unwrap_or("<Invalid UTF-8>");
            println!("if_description: {}", s);
        }
        OptionCode(4) => {
            if value.len() == 8 {
                let ipv4_bytes: [u8; 4] = (&value[0..4]).try_into().unwrap();
                let mask_bytes: [u8; 4] = (&value[4..8]).try_into().unwrap();
                let ipv4 = Ipv4Addr::from(ipv4_bytes);
                let mask = Ipv4Addr::from(mask_bytes);
                println!("if_IPv4addr: {} / {}", ipv4, mask);
            } else {
                eprintln!("INVALID if_IPv4addr: {:x?}", value);
            }
        }
        OptionCode(5) => {
            if value.len() == 17 {
                let (start, rest) = value.split_at(16);
                let ipv6_bytes: [u8; 16] = start.try_into().unwrap();
                let ipv6 = Ipv6Addr::from(ipv6_bytes);
                println!("if_IPv6addr: {} / {}", ipv6, rest[0]);
            } else {
                eprintln!("INVALID if_IPv4addr: {:x?}", value);
            }
        }
        OptionCode(8) => {
            if value.len() == 8 {
                let int_bytes: [u8; 8] = value.try_into().unwrap();
                println!("if_speed: {}", u64::from_le_bytes(int_bytes));
            } else {
                eprintln!("INVALID if_speed: {:x?}", value);
            }
        }
        OptionCode::IfTsresol => {
            println!("Time resolution: 0x{:x}", value[0]);
            if value.len() != 1 {
                eprintln!("INVALID if_tsresol: len={} val={:x?}", value.len(), value);
                eprintln!("if_tsresol len should be 1");
            }
        }
        OptionCode(11) => {
            let s = str::from_utf8(value).unwrap_or("<Invalid UTF-8>");
            println!("Filter string: {}", s);
        }
        OptionCode(12) => {
            let s = str::from_utf8(value).unwrap_or("<Invalid UTF-8>");
            println!("Operating System: {}", s);
        }
        OptionCode(_) => {
            let s = str::from_utf8(value).unwrap_or("<Invalid UTF-8>");
            println!("Option {}: {}", code, s);
        }
    }
}
