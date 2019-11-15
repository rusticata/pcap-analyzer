use std::convert::TryInto;
use std::fs::{self, File};
use std::io::{self, Error, ErrorKind};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::str;

use flate2::read::GzDecoder;
use xz2::read::XzDecoder;

use pcap_parser::pcapng::*;
use pcap_parser::{create_reader, Block, PcapBlockOwned, PcapError};

pub struct Options {
    pub check_file: bool,
}

#[derive(Default)]
struct Context {
    num_interfaces: usize,
    block_index: usize,
    packet_index: usize,
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
            reader.consume(sz);
        }
        Ok((sz, PcapBlockOwned::NG(Block::SectionHeader(ref shb)))) => {
            println!("Type: Pcap-NG");
            pretty_print_shb(shb);

            reader.consume(sz);
        }
        _ => return Err(Error::new(ErrorKind::InvalidData, "Neither a pcap nor pcap-ng header found")),
    }
    ctx.block_index += 1;

    if !options.check_file {
        return Ok(0);
    }

    let mut last_incomplete_index = 0;
    let mut rc = 0;
    loop {
        match reader.next() {
            Ok((offset, block)) => {
                ctx.block_index += 1;
                pretty_print_pcapblockowned(&block, &mut ctx);
                reader.consume(offset);
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

    println!("#blocks: {}", ctx.block_index);
    println!("#packets: {}", ctx.packet_index);

    Ok(rc)
}

fn pretty_print_pcapblockowned(b: &PcapBlockOwned, ctx: &mut Context) {
    match b {
        PcapBlockOwned::LegacyHeader(_) => {
            eprintln!("Unexpected legacy header block");
        }
        PcapBlockOwned::NG(Block::SectionHeader(ref shb)) => {
            ctx.num_interfaces = 0;
            pretty_print_shb(shb);
        }
        PcapBlockOwned::NG(Block::InterfaceDescription(ref idb)) => {
            let if_index = ctx.num_interfaces;
            ctx.num_interfaces += 1;
            pretty_print_idb(idb, if_index);
        }
        PcapBlockOwned::Legacy(_) |
        PcapBlockOwned::NG(Block::EnhancedPacket(_)) |
        PcapBlockOwned::NG(Block::SimplePacket(_)) => {
            ctx.packet_index += 1;
        }
        _ => (),
    }
}

fn pretty_print_shb(shb: &SectionHeaderBlock) {
    println!("Section header:");
    println!("  Version: {}.{}", shb.major_version, shb.minor_version);
    println!("  Section length: {}", shb.section_len);
    println!(
        "  Byte Ordering: {}",
        if shb.bom == BOM_MAGIC {
            "Native"
        } else {
            "Reverse"
        }
    );
    for opt in &shb.options {
        print!("  ");
        pretty_print_shb_option(opt);
    }
}

fn pretty_print_idb(idb: &InterfaceDescriptionBlock, if_index: usize) {
    println!("Interface description:");
    println!("  Index: {}", if_index);
    println!("  Linktype: {}", idb.linktype);
    for opt in &idb.options {
        print!("  ");
        pretty_print_idb_option(opt);
    }
}

fn pretty_print_idb_option(o: &PcapNGOption) {
    match o.code {
        OptionCode::Comment => {
            let s = str::from_utf8(o.value).unwrap_or("<Invalid UTF-8>");
            println!("Hardware: {}", s);
        }
        OptionCode::EndOfOpt => println!("End of Options"),
        OptionCode(2) => {
            let s = str::from_utf8(o.value).unwrap_or("<Invalid UTF-8>");
            println!("if_name: {}", s);
        }
        OptionCode(3) => {
            let s = str::from_utf8(o.value).unwrap_or("<Invalid UTF-8>");
            println!("if_description: {}", s);
        }
        OptionCode(4) => {
            if o.len == 8 {
                let ipv4_bytes: [u8; 4] = (&o.value[0..4]).try_into().unwrap();
                let mask_bytes: [u8; 4] = (&o.value[4..8]).try_into().unwrap();
                let ipv4 = Ipv4Addr::from(ipv4_bytes);
                let mask = Ipv4Addr::from(mask_bytes);
                println!("if_IPv4addr: {} / {}", ipv4, mask);
            } else {
                eprintln!("INVALID if_IPv4addr: {:x?}", o.value);
            }
        }
        OptionCode(5) => {
            if o.len == 17 {
                let (start, rest) = o.value.split_at(16);
                let ipv6_bytes: [u8; 16] = start.try_into().unwrap();
                let ipv6 = Ipv6Addr::from(ipv6_bytes);
                println!("if_IPv6addr: {} / {}", ipv6, rest[0]);
            } else {
                eprintln!("INVALID if_IPv4addr: {:x?}", o.value);
            }
        }
        OptionCode(8) => {
            if o.len == 8 {
                let int_bytes: [u8; 8] = o.value.try_into().unwrap();
                println!("if_speed: {}", u64::from_le_bytes(int_bytes));
            } else {
                eprintln!("INVALID if_speed: {:x?}", o.value);
            }
        }
        OptionCode(9) => {
            if o.len == 1 {
                println!("if_tsresol: 0x{:x}", o.value[0]);
            } else {
                eprintln!("INVALID if_tsresol: {:x?}", o.value);
            }
        }
        OptionCode(11) => {
            let s = str::from_utf8(o.value).unwrap_or("<Invalid UTF-8>");
            println!("if_filter: {}", s);
        }
        OptionCode(12) => {
            let s = str::from_utf8(o.value).unwrap_or("<Invalid UTF-8>");
            println!("if_os: {}", s);
        }
        OptionCode(_) => {
            let s = str::from_utf8(o.value).unwrap_or("<Invalid UTF-8>");
            println!("Option {}: {}", o.code.0, s);
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
            println!("OS: {}", s);
        }
        OptionCode::ShbUserAppl => {
            let s = str::from_utf8(o.value).unwrap_or("<Invalid UTF-8>");
            println!("(SHB) User application: {}", s);
        }
        OptionCode(_) => {
            let s = str::from_utf8(o.value).unwrap_or("<Invalid UTF-8>");
            println!("Option {}: {}", o.code.0, s);
        }
    }
}
