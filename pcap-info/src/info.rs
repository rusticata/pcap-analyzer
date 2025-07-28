use crate::interface::{pcapng_build_interface, InterfaceInfo};
use digest::generic_array::GenericArray;
use smart_default::SmartDefault;
use std::cmp::min;
use std::fs::File;
use std::io::{self, Error, ErrorKind};
use std::path::Path;
use std::str;
use time::{Duration, OffsetDateTime};
use tracing::{info, span, warn, Level};

use flate2::read::GzDecoder;
use xz2::read::XzDecoder;

use blake2::Blake2s256;
use digest::Digest;
use sha1::Sha1;
use sha2::Sha256;

use pcap_parser::pcapng::*;
use pcap_parser::{create_reader, Block, PcapBlockOwned, PcapError};

const MICROS_PER_SEC: u64 = 1_000_000;
const NANOS_PER_SEC: u64 = 1_000_000_000;

pub struct Options {
    pub check_file: bool,
}

#[derive(Debug, PartialEq)]
pub enum FileType {
    Pcap,
    PcapNG,
}

#[derive(SmartDefault)]
pub struct PcapInfo {
    is_pcapng: bool,
    pub version_major: u16,
    pub version_minor: u16,

    pub file_bytes: usize,
    pub data_bytes: usize,
    pub block_index: usize,
    pub packet_index: usize,

    pub strict_time_order: bool,

    pub sections: Vec<SectionInfo>,

    // hashes
    hasher_blake2: Blake2s256,
    hasher_sha1: Sha1,
    hasher_sha256: Sha256,
}

impl PcapInfo {
    #[inline]
    pub const fn file_type(&self) -> FileType {
        if self.is_pcapng {
            FileType::PcapNG
        } else {
            FileType::Pcap
        }
    }

    pub fn first_packet(&self) -> Option<OffsetDateTime> {
        self.sections
            .iter()
            .filter_map(|section| section.first_packet())
            .min()
    }

    pub fn last_packet(&self) -> Option<OffsetDateTime> {
        self.sections
            .iter()
            .filter_map(|section| section.last_packet())
            .min()
    }

    pub fn capture_duration(&self) -> Duration {
        let first_ts = self.first_packet().unwrap();
        let last_ts = self.last_packet().unwrap();
        last_ts - first_ts
    }

    pub fn sha1(&self) -> GenericArray<u8, digest::typenum::U20> {
        let mut hash = self.hasher_sha1.clone();
        hash.finalize_reset()
    }

    pub fn sha256(&self) -> GenericArray<u8, digest::typenum::U32> {
        let mut hash = self.hasher_sha256.clone();
        hash.finalize_reset()
    }

    pub fn blakes256(&self) -> GenericArray<u8, digest::typenum::U32> {
        let mut hash = self.hasher_blake2.clone();
        hash.finalize_reset()
    }
}

#[derive(SmartDefault)]
pub struct SectionInfo {
    pub native_endian: bool,

    pub options: Vec<(OptionCode, Vec<u8>)>,

    pub interfaces: Vec<InterfaceInfo>,

    pub num_packets: usize,

    pub num_secrets_blocks: usize,
    pub num_custom_blocks: usize,
    pub num_ipv4_resolved: usize,
    pub num_ipv6_resolved: usize,

    first_packet_ts: (i64, i64),
    last_packet_ts: (i64, i64),
    previous_packet_ts: (i64, i64),
}

impl SectionInfo {
    fn add_shb_options(&mut self, shb: &SectionHeaderBlock) {
        for opt in &shb.options {
            self.options.push((opt.code, opt.value.to_vec()));
        }
    }

    pub fn first_packet(&self) -> Option<OffsetDateTime> {
        OffsetDateTime::from_unix_timestamp(self.first_packet_ts.0)
            .ok()
            .map(|t| t + Duration::nanoseconds(self.first_packet_ts.1))
    }

    pub fn last_packet(&self) -> Option<OffsetDateTime> {
        OffsetDateTime::from_unix_timestamp(self.last_packet_ts.0)
            .ok()
            .map(|t| t + Duration::nanoseconds(self.last_packet_ts.1))
    }

    pub fn duration(&self) -> Duration {
        let first_ts = OffsetDateTime::from_unix_timestamp(self.first_packet_ts.0).unwrap()
            + Duration::nanoseconds(self.first_packet_ts.1);
        let last_ts = OffsetDateTime::from_unix_timestamp(self.last_packet_ts.0).unwrap()
            + Duration::nanoseconds(self.last_packet_ts.1);
        last_ts - first_ts
    }
}

fn open_file(name: &str) -> Result<Box<dyn io::Read + Send>, io::Error> {
    let input_reader: Box<dyn io::Read + Send> = if name == "-" {
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

#[allow(clippy::field_reassign_with_default)]
pub(crate) fn process_file(name: &str, options: &Options) -> Result<(i32, PcapInfo), io::Error> {
    let file = open_file(name)?;
    let mut reader = create_reader(128 * 1024, file).expect("reader");

    let mut ctx = PcapInfo::default();
    ctx.strict_time_order = true;

    let mut current_section = SectionInfo::default();

    let first_block = reader.next();
    match first_block {
        Ok((sz, PcapBlockOwned::LegacyHeader(hdr))) => {
            ctx.version_major = hdr.version_major;
            ctx.version_minor = hdr.version_minor;
            current_section.native_endian = hdr.magic_number >> 16 == 0xa1b2;
            let precision = if hdr.is_nanosecond_precision() { 9 } else { 6 };
            let if_info = InterfaceInfo {
                if_index: 0,
                link_type: hdr.network,
                if_tsoffset: 0,
                if_tsresol: precision,
                snaplen: hdr.snaplen,
                ..InterfaceInfo::default()
            };
            current_section.interfaces.push(if_info);
            current_section.num_packets = 0;
            let data = reader.data();
            ctx.hasher_blake2.update(&data[..sz]);
            ctx.hasher_sha1.update(&data[..sz]);
            ctx.hasher_sha256.update(&data[..sz]);
            ctx.file_bytes += sz;
            reader.consume(sz);
        }
        Ok((sz, PcapBlockOwned::NG(Block::SectionHeader(ref shb)))) => {
            ctx.is_pcapng = true;
            ctx.version_major = shb.major_version;
            ctx.version_minor = shb.minor_version;
            current_section.native_endian = shb.bom == BOM_MAGIC;
            current_section.add_shb_options(shb);
            let data = reader.data();
            ctx.hasher_blake2.update(&data[..sz]);
            ctx.hasher_sha1.update(&data[..sz]);
            ctx.hasher_sha256.update(&data[..sz]);
            ctx.file_bytes += sz;
            reader.consume(sz);
        }
        _ => {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Neither a pcap nor pcap-ng header was found",
            ))
        }
    }
    ctx.block_index += 1;

    if !options.check_file {
        return Ok((0, ctx));
    }

    let mut last_incomplete_index = 0;
    let mut rc = 0;
    loop {
        match reader.next() {
            Ok((sz, block)) => {
                ctx.block_index += 1;
                ctx.file_bytes += sz;
                handle_pcapblockowned(&block, &mut ctx, &mut current_section);
                let data = reader.data();
                ctx.hasher_blake2.update(&data[..sz]);
                ctx.hasher_sha1.update(&data[..sz]);
                ctx.hasher_sha256.update(&data[..sz]);
                reader.consume(sz);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                if last_incomplete_index == ctx.block_index && reader.reader_exhausted() {
                    warn!("Could not read complete data block.");
                    warn!("Hint: the reader buffer size may be too small, or the input file may be truncated.");
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

    end_of_section(&mut ctx, &mut current_section);

    Ok((rc, ctx))
}

fn update_time(
    ts_sec: i64,
    ts_nanosec: i64,
    ctx: &mut PcapInfo,
    current_section: &mut SectionInfo,
) {
    let dt = (ts_sec, ts_nanosec);
    if current_section.first_packet_ts == (0, 0) {
        current_section.first_packet_ts = (ts_sec, ts_nanosec);
    }
    if dt < current_section.previous_packet_ts {
        info!("** unordered file");
        ctx.strict_time_order = false;
    }
    if dt < current_section.first_packet_ts {
        info!("** unordered file (before first packet)");
        ctx.strict_time_order = false;
        current_section.first_packet_ts = (ts_sec, ts_nanosec);
    }
    if dt > current_section.last_packet_ts {
        current_section.last_packet_ts = (ts_sec, ts_nanosec);
    }
    current_section.previous_packet_ts = (ts_sec, ts_nanosec);
}

fn handle_pcapblockowned(
    b: &PcapBlockOwned,
    ctx: &mut PcapInfo,
    current_section: &mut SectionInfo,
) {
    let span = span!(Level::INFO, "handle_block", block_index = ctx.block_index);
    let _enter = span.enter();
    match b {
        PcapBlockOwned::NG(Block::SectionHeader(ref shb)) => {
            end_of_section(ctx, current_section);
            current_section.add_shb_options(shb);
        }
        PcapBlockOwned::NG(Block::InterfaceDescription(ref idb)) => {
            let num_interfaces = current_section.interfaces.len();
            let if_info = pcapng_build_interface(idb, num_interfaces);
            current_section.interfaces.push(if_info);
        }
        PcapBlockOwned::LegacyHeader(ref _hdr) => {
            warn!("Unexpected legacy header block");
            end_of_section(ctx, current_section);
            // let precision = if hdr.is_nanosecond_precision() { 9 } else { 6 };
            // let if_info = InterfaceInfo {
            //     if_index: 0,
            //     link_type: hdr.network,
            //     if_tsoffset: 0,
            //     if_tsresol: precision,
            //     snaplen: hdr.snaplen,
            //     ..InterfaceInfo::default()
            // };
            // ctx.interfaces.push(if_info);
        }
        PcapBlockOwned::Legacy(ref b) => {
            let if_info = &mut current_section.interfaces[0];
            if_info.num_packets += 1;
            let dt = if if_info.if_tsresol == 6 {
                assert!(b.ts_usec < 1_000_000);
                (b.ts_sec as i64, (b.ts_usec as i64) * 1000)
            } else {
                assert!(b.ts_usec < 1_000_000_000);
                (b.ts_sec as i64, b.ts_usec as i64)
            };
            // add time offset if present
            let tz = if_info.if_tsoffset as i64;
            update_time(dt.0 + tz, dt.1, ctx, current_section);
            ctx.packet_index += 1;
            let data_len = b.caplen as usize;
            assert!(data_len <= b.data.len());
            ctx.data_bytes += data_len;
        }
        PcapBlockOwned::NG(Block::EnhancedPacket(epb)) => {
            assert!((epb.if_id as usize) < current_section.interfaces.len());
            let if_info = &mut current_section.interfaces[epb.if_id as usize];
            if_info.num_packets += 1;
            if if_info.snaplen > 0 && epb.data.len() + 4 > if_info.snaplen as usize {
                warn!(
                    "*** EPB block data len greater than snaplen in block {} ***",
                    ctx.block_index
                );
            }
            let unit = if_info.ts_unit;
            let (ts_sec, ts_frac) =
                pcap_parser::build_ts(epb.ts_high, epb.ts_low, if_info.if_tsoffset, unit);
            let ts_frac = ts_frac as u64;
            if ts_frac > unit {
                info!(
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
            let dt = (ts_sec as i64, ts_nanosec as i64);
            // add time offset if present
            let tz = if_info.if_tsoffset as i64;
            update_time(dt.0 + tz, dt.1, ctx, current_section);
            ctx.packet_index += 1;
            let data_len = epb.caplen as usize;
            assert!(data_len <= epb.data.len());
            ctx.data_bytes += data_len;
        }
        PcapBlockOwned::NG(Block::SimplePacket(spb)) => {
            assert!(!current_section.interfaces.is_empty());
            let if_info = current_section.interfaces.first_mut().unwrap();
            if_info.num_packets += 1;
            let data_len = min(if_info.snaplen as usize, spb.data.len());
            ctx.data_bytes += data_len;
            ctx.packet_index += 1;
        }
        PcapBlockOwned::NG(Block::NameResolution(nrb)) => {
            for nr in &nrb.nr {
                match nr.record_type {
                    NameRecordType::End => (),
                    NameRecordType::Ipv4 => current_section.num_ipv4_resolved += 1,
                    NameRecordType::Ipv6 => current_section.num_ipv6_resolved += 1,
                    NameRecordType(n) => warn!(
                        "*** invalid NameRecordType {} in NRB (block {})",
                        n, ctx.block_index
                    ),
                }
            }
        }
        PcapBlockOwned::NG(Block::InterfaceStatistics(isb)) => {
            // println!("*** block type ISB ***");
            assert!((isb.if_id as usize) < current_section.interfaces.len());
            let if_info = &mut current_section.interfaces[isb.if_id as usize];
            if_info.num_stats += 1;
        }
        PcapBlockOwned::NG(Block::DecryptionSecrets(_dsb)) => {
            // println!("*** DSB ***");
            // println!("secrets type {:?}", _dsb.secrets_type);
            // println!("secrets (as str): {:?}", std::str::from_utf8(_dsb.data));
            current_section.num_secrets_blocks += 1;
        }
        PcapBlockOwned::NG(Block::Custom(_)) => {
            current_section.num_custom_blocks += 1;
        }
        PcapBlockOwned::NG(b) => {
            info!("*** Unsupported block type (magic={:08x}) ***", b.magic());
        }
    }
}

fn end_of_section(ctx: &mut PcapInfo, current_section: &mut SectionInfo) {
    let section = std::mem::take(current_section);
    ctx.sections.push(section);
}
