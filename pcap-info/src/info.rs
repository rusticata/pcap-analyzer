use crate::interface::{pcapng_build_interface, InterfaceInfo};
use chrono::{TimeZone, Utc};
use std::cmp::min;
use std::convert::TryInto;
use std::fs::{self, File};
use std::io::{self, Error, ErrorKind};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::str;
use std::time::Duration;

use flate2::read::GzDecoder;
use xz2::read::XzDecoder;

use digest::Digest;
use ripemd160::Ripemd160;
use sha1::Sha1;
use sha2::Sha256;

use pcap_parser::pcapng::*;
use pcap_parser::{create_reader, Block, PcapBlockOwned, PcapError};

const MICROS_PER_SEC: u64 = 1_000_000;
const NANOS_PER_SEC: u64 = 1_000_000_000;

pub struct Options {
    pub check_file: bool,
}

#[derive(Default)]
struct Context {
    file_bytes: usize,
    data_bytes: usize,
    block_index: usize,
    packet_index: usize,
    first_packet_ts: Duration,
    last_packet_ts: Duration,
    previous_packet_ts: Duration,
    strict_time_order: bool,
    num_ipv4_resolved: usize,
    num_ipv6_resolved: usize,
    num_custom_blocks: usize,
    // section-related variables
    interfaces: Vec<InterfaceInfo>,
    section_num_packets: usize,
    // hashes
    hasher_ripemd160: Ripemd160,
    hasher_sha1: Sha1,
    hasher_sha256: Sha256,
}

fn open_file(name: &str) -> Result<Box<dyn io::Read>, io::Error> {
    let input_reader: Box<dyn io::Read> = if name == "-" {
        Box::new(io::stdin())
    } else {
        let path = Path::new(&name);
        let file = File::open(path)?;
        if name.ends_with(".gz") {
            Box::new(GzDecoder::new(file))
        } else if name.ends_with(".xz") {
            Box::new(XzDecoder::new(file))
        } else {
            Box::new(file)
        }
    };
    Ok(input_reader)
}

pub(crate) fn process_file(name: &str, options: &Options) -> Result<i32, io::Error> {
    println!("File name: {}", name);

    if name != "-" {
        let metadata = fs::metadata(name)?;
        println!("  size: {}", metadata.len());
    }

    let file = open_file(name)?;
    let mut reader = create_reader(128 * 1024, file).expect("reader");

    let mut ctx = Context::default();
    ctx.strict_time_order = true;

    let first_block = reader.next();
    match first_block {
        Ok((sz, PcapBlockOwned::LegacyHeader(hdr))) => {
            println!("Type: Legacy Pcap");
            println!("Version: {}.{}", hdr.version_major, hdr.version_minor);
            println!(
                "Byte Ordering: {}",
                if hdr.magic_number == 0xa1b2_c3d4 {
                    "Native"
                } else {
                    "Reverse"
                }
            );
            println!("Captured length: {}", hdr.snaplen);
            println!("Linktype: {}", hdr.network);
            let if_info = InterfaceInfo {
                if_index: 0,
                link_type: hdr.network,
                if_tsoffset: 0,
                if_tsresol: 6,
                snaplen: hdr.snaplen,
                ..InterfaceInfo::default()
            };
            ctx.interfaces.push(if_info);
            ctx.section_num_packets = 0;
            ctx.file_bytes += sz;
            reader.consume(sz);
        }
        Ok((sz, PcapBlockOwned::NG(Block::SectionHeader(ref shb)))) => {
            println!("Type: Pcap-NG");
            pretty_print_shb(shb);
            let data = reader.data();
            ctx.hasher_ripemd160.input(&data[..sz]);
            ctx.hasher_sha1.input(&data[..sz]);
            ctx.hasher_sha256.input(&data[..sz]);
            ctx.file_bytes += sz;
            reader.consume(sz);
        }
        _ => {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Neither a pcap nor pcap-ng header found",
            ))
        }
    }
    ctx.block_index += 1;

    if !options.check_file {
        return Ok(0);
    }

    let mut last_incomplete_index = 0;
    let mut rc = 0;
    loop {
        match reader.next() {
            Ok((sz, block)) => {
                ctx.block_index += 1;
                ctx.file_bytes += sz;
                handle_pcapblockowned(&block, &mut ctx);
                let data = reader.data();
                ctx.hasher_ripemd160.input(&data[..sz]);
                ctx.hasher_sha1.input(&data[..sz]);
                ctx.hasher_sha256.input(&data[..sz]);
                reader.consume(sz);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete) => {
                if last_incomplete_index == ctx.block_index {
                    eprintln!("Could not read complete data block.");
                    eprintln!("Hint: the reader buffer size may be too small, or the input file may be truncated.");
                    rc = 1;
                    break;
                }
                last_incomplete_index = ctx.block_index;
                reader.refill().expect("Refill failed");
                continue;
            }
            Err(e) => panic!("Error while reading: {:?}", e),
        }
    }

    println!("{:<20}: {:x}", "SHA256", ctx.hasher_sha256.result_reset());
    println!(
        "{:<20}: {:x}",
        "RIPEMD160",
        ctx.hasher_ripemd160.result_reset()
    );
    println!("{:<20}: {:x}", "SHA1", ctx.hasher_sha1.result_reset());

    let cap_duration = ctx.last_packet_ts - ctx.first_packet_ts;
    println!(
        "{:<20}: {}.{:.6} seconds",
        "Capture duration",
        cap_duration.as_secs(),
        cap_duration.subsec_micros()
    );
    let dt = Utc.timestamp(
        ctx.first_packet_ts.as_secs() as i64,
        ctx.first_packet_ts.subsec_nanos(),
    );
    println!("{:<20}: {}", "First packet time", dt);
    let dt = Utc.timestamp(
        ctx.last_packet_ts.as_secs() as i64,
        ctx.last_packet_ts.subsec_nanos(),
    );
    println!("{:<20}: {}", "Last packet time", dt);
    println!("{:<20}: {}", "Strict time order", ctx.strict_time_order);
    println!("{:<20}: {}", "Number of blocks", ctx.block_index);
    println!("{:<20}: {}", "Number of packets", ctx.packet_index);
    println!("{:<20}: {} bytes", "File size", ctx.file_bytes);
    println!("{:<20}: {} bytes", "Data size", ctx.data_bytes);
    let bit_rate = ctx.data_bytes as f64 / cap_duration.as_secs_f64();
    println!("{:<20}: {:.0} bytes/s", "Data byte rate", bit_rate);
    println!("{:<20}: {:.0} kbps/s", "Data bit rate", bit_rate * 0.008);
    println!(
        "{:<20}: {:.2} bytes",
        "Average packet size",
        ctx.data_bytes as f64 / ctx.packet_index as f64
    );
    println!(
        "{:<20}: {:.0} packets/s",
        "Average packet rate",
        ctx.packet_index as f64 / cap_duration.as_secs_f64()
    );
    if ctx.num_ipv4_resolved > 0 {
        println!(
            "{:<20}: {}",
            "Number of IPv4 resolved", ctx.num_ipv4_resolved
        );
    }
    if ctx.num_ipv6_resolved > 0 {
        println!(
            "{:<20}: {}",
            "Number of IPv6 resolved", ctx.num_ipv6_resolved
        );
    }
    if ctx.num_custom_blocks > 0 {
        println!(
            "{:<20}: {}",
            "Number of custom blocks", ctx.num_custom_blocks
        );
    }
    println!("{:<20}: {}", "Number of interfaces", ctx.interfaces.len());

    end_of_section(&mut ctx);

    Ok(rc)
}

fn update_time(ts: Duration, ctx: &mut Context) {
    if ctx.first_packet_ts == Duration::default() {
        ctx.first_packet_ts = ts;
    }
    if ts < ctx.previous_packet_ts {
        println!("** unordered file");
        ctx.strict_time_order = false;
    }
    if ts < ctx.first_packet_ts {
        println!("** unordered file (before first packet)");
        ctx.strict_time_order = false;
        ctx.first_packet_ts = ts;
    }
    if ts > ctx.last_packet_ts {
        ctx.last_packet_ts = ts;
    }
    ctx.previous_packet_ts = ts;
}

fn end_of_section(ctx: &mut Context) {
    // print information for all interfaces in section
    for interface in &ctx.interfaces {
        pretty_print_interface(interface);
    }
    // reset section-related variables in context
    ctx.interfaces = Vec::new();
    ctx.section_num_packets = 0;
}

fn handle_pcapblockowned(b: &PcapBlockOwned, ctx: &mut Context) {
    match b {
        PcapBlockOwned::NG(Block::SectionHeader(ref shb)) => {
            end_of_section(ctx);
            pretty_print_shb(shb);
        }
        PcapBlockOwned::NG(Block::InterfaceDescription(ref idb)) => {
            let num_interfaces = ctx.interfaces.len();
            let if_info = pcapng_build_interface(idb, num_interfaces);
            ctx.interfaces.push(if_info);
        }
        PcapBlockOwned::LegacyHeader(ref hdr) => {
            eprintln!("Unexpected legacy header block");
            end_of_section(ctx);
            let if_info = InterfaceInfo {
                if_index: 0,
                link_type: hdr.network,
                if_tsoffset: 0,
                if_tsresol: 6,
                snaplen: hdr.snaplen,
                ..InterfaceInfo::default()
            };
            ctx.interfaces.push(if_info);
        }
        PcapBlockOwned::Legacy(ref b) => {
            let if_info = &mut ctx.interfaces[0];
            if_info.num_packets += 1;
            assert!(b.ts_usec < 1_000_000);
            let ts = Duration::new(b.ts_sec as u64, b.ts_usec * 1000);
            update_time(ts, ctx);
            ctx.packet_index += 1;
            // TODO update data len
        }
        PcapBlockOwned::NG(Block::EnhancedPacket(epb)) => {
            assert!((epb.if_id as usize) < ctx.interfaces.len());
            let if_info = &mut ctx.interfaces[epb.if_id as usize];
            if_info.num_packets += 1;
            if if_info.snaplen > 0 && epb.data.len() + 4 > if_info.snaplen as usize {
                println!(
                    "*** EPB block data len greater than snaplen in block {} ***",
                    ctx.block_index
                );
            }
            let (ts_sec, ts_frac, unit) = pcap_parser::build_ts(
                epb.ts_high,
                epb.ts_low,
                if_info.if_tsoffset,
                if_info.if_tsresol,
            );
            let ts_frac = ts_frac as u64;
            if ts_frac > unit {
                println!(
                    "Time: fractionnal part is greater than unit in block {}",
                    ctx.block_index
                );
            }
            let ts_nanosec = match unit {
                MICROS_PER_SEC => ts_frac * 1000,
                NANOS_PER_SEC => ts_frac,
                _ => (ts_frac * NANOS_PER_SEC) / unit,
            };
            assert!(ts_nanosec < NANOS_PER_SEC);
            let ts = Duration::new(ts_sec as u64, ts_nanosec as u32);
            update_time(ts, ctx);
            ctx.packet_index += 1;
            let data_len = epb.caplen as usize;
            assert!(data_len <= epb.data.len());
            ctx.data_bytes += data_len;
        }
        PcapBlockOwned::NG(Block::SimplePacket(spb)) => {
            assert!(!ctx.interfaces.is_empty());
            let if_info = ctx.interfaces.first_mut().unwrap();
            if_info.num_packets += 1;
            let data_len = min(if_info.snaplen as usize, spb.data.len());
            ctx.data_bytes += data_len;
            ctx.packet_index += 1;
        }
        PcapBlockOwned::NG(Block::NameResolution(nrb)) => {
            for nr in &nrb.nr {
                match nr.record_type {
                    0 => (),
                    1 => ctx.num_ipv4_resolved += 1,
                    2 => ctx.num_ipv6_resolved += 1,
                    n => println!(
                        "*** invalid NameRecordType {} in NRB (block {})",
                        n, ctx.block_index
                    ),
                }
            }
        }
        PcapBlockOwned::NG(Block::InterfaceStatistics(isb)) => {
            // println!("*** block type ISB ***");
            assert!((isb.if_id as usize) < ctx.interfaces.len());
            let if_info = &mut ctx.interfaces[isb.if_id as usize];
            if_info.num_stats += 1;
        }
        PcapBlockOwned::NG(Block::Custom(_)) => {
            ctx.num_custom_blocks += 1;
        }
        _ => {
            println!("*** Unsupported block type ***");
        }
    }
}

fn pretty_print_shb(shb: &SectionHeaderBlock) {
    println!("Section header:");
    println!("    Version: {}.{}", shb.major_version, shb.minor_version);
    println!("    Section length: {}", shb.section_len);
    println!(
        "    Byte Ordering: {}",
        if shb.bom == BOM_MAGIC {
            "Native"
        } else {
            "Reverse"
        }
    );
    for opt in &shb.options {
        print!("    ");
        pretty_print_shb_option(opt);
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
        pretty_print_idb_option(*opt_code, &opt_value);
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
fn pretty_print_shb_option(o: &PcapNGOption) {
    match o.code {
        OptionCode::Comment => {
            let s = str::from_utf8(o.value).unwrap_or("<Invalid UTF-8>");
            println!("Hardware: {}", s);
        }
        OptionCode::EndOfOpt => println!("End of Options"),
        OptionCode::ShbHardware => {
            let s = str::from_utf8(o.value).unwrap_or("<Invalid UTF-8>");
            println!("Hardware: {}", s);
        }
        OptionCode::ShbOs => {
            let s = str::from_utf8(o.value).unwrap_or("<Invalid UTF-8>");
            println!("Operating system: {}", s);
        }
        OptionCode::ShbUserAppl => {
            let s = str::from_utf8(o.value).unwrap_or("<Invalid UTF-8>");
            println!("Capture application: {}", s);
        }
        OptionCode(_) => {
            let s = str::from_utf8(o.value).unwrap_or("<Invalid UTF-8>");
            println!("Option {}: {}", o.code.0, s);
        }
    }
}
