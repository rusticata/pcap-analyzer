extern crate infer;
extern crate lz4;

use std::fs::File;
use std::io::{self, Error, Read, Seek};
use std::path::Path;

use flate2::read::GzDecoder;
use libpcap_tools::{Config, PcapDataEngine, PcapEngine};
use log::warn;
use log::{error, info};
use std::io::SeekFrom;
use xz2::read::XzDecoder;

mod container;
pub mod filters;
mod pcap;
mod pcapng;
pub mod rewriter;
mod traits;

use rewriter::{FileFormat, Rewriter};

pub struct RewriteOptions {
    pub output_format: FileFormat,
    pub config: Config,
}

/// Rewrite input file applying filters
///
/// - `input_filename` must be a Pcap or Pcap-NG file. If using the special value "-", standard input will be used (see notes below)
/// - `output_filename` will be created, or truncated if the file exists
/// - `filters` is an ordered list of [`Filter`](filters::filter::Filter) to apply. It may be empty
/// - `options` are used to specify output format and other options
///
/// # Notes
///
/// `pcap-rewrite` tries to rewrite the file in a single pass. However, some plugins require a pre-analysis pass.
/// Note that these
pub fn pcap_rewrite_file<S1: AsRef<str>, S2: AsRef<str>>(
    input_filename: S1,
    output_filename: S2,
    filters: Vec<Box<dyn filters::filter::Filter>>,
    options: &RewriteOptions,
) -> Result<(), io::Error> {
    let input_filename = input_filename.as_ref();
    let output_filename = output_filename.as_ref();
    let mut input_reader = get_reader(input_filename)?;
    let path = Path::new(output_filename);
    let outfile = File::create(path)?;

    // let block_analyzer = BlockRewriter::new(outfile);
    // let mut engine = BlockEngine::new(block_analyzer, &config);

    let rewriter = Rewriter::new(Box::new(outfile), options.output_format, filters);
    let mut engine = PcapDataEngine::new(rewriter, &options.config);

    if engine.data_analyzer().require_pre_analysis() {
        // check that we are not using stdin
        if input_filename == "-" {
            const MSG: &str = "Plugins with pre-analysis pass cannot be run on stdin";
            error!("{}", MSG);
            return Err(io::Error::new(io::ErrorKind::Other, MSG));
        }
        info!("Running pre-analysis pass");
        engine.data_analyzer_mut().set_run_pre_analysis(true);
        engine
            .run(&mut input_reader)
            .expect("pre-analysis pass failed");
        // reset reader
        input_reader = get_reader(input_filename)?;
    }

    info!(
        "Rewriting file (output format: {:?})",
        options.output_format
    );
    engine.run(&mut input_reader).expect("run analyzer");

    Ok(())
}

fn get_reader(input_filename: &str) -> io::Result<Box<dyn Read + Send>> {
    let input_reader = if input_filename == "-" {
        Box::new(io::stdin())
    } else {
        let path = Path::new(&input_filename);
        let mut file = File::open(path).map_err(|e| {
            error!("Could not open input file '{}'", input_filename);
            e
        })?;

        // https://en.wikipedia.org/wiki/LZ4_(compression_algorithm)
        fn lz4_matcher(buf: &[u8]) -> bool {
            buf.len() >= 4 && buf[0] == 0x04 && buf[1] == 0x22 && buf[2] == 0x4d && buf[3] == 0x18
        }
        // https://www.tcpdump.org/manpages/pcap-savefile.5.html
        fn pcap_same_endianess_matcher_microsecond(buf: &[u8]) -> bool {
            buf.len() >= 4 && buf[0] == 0xa1 && buf[1] == 0xb2 && buf[2] == 0xc3 && buf[3] == 0xd4
        }
        fn pcap_reverse_endianess_matcher_microsecond(buf: &[u8]) -> bool {
            buf.len() >= 4 && buf[0] == 0xd4 && buf[1] == 0xc3 && buf[2] == 0xb2 && buf[3] == 0xa1
        }
        fn pcap_same_endianess_matcher_nanosecond(buf: &[u8]) -> bool {
            buf.len() >= 4 && buf[0] == 0xa1 && buf[1] == 0xb2 && buf[2] == 0x3c && buf[3] == 0x4d
        }
        fn pcap_reverse_endianess_matcher_nanosecond(buf: &[u8]) -> bool {
            buf.len() >= 4 && buf[0] == 0x4d && buf[1] == 0x3c && buf[2] == 0xb2 && buf[3] == 0xa1
        }
        fn pcap_matcher(buf: &[u8]) -> bool {
            pcap_same_endianess_matcher_microsecond(buf)
                || pcap_reverse_endianess_matcher_microsecond(buf)
                || pcap_same_endianess_matcher_nanosecond(buf)
                || pcap_reverse_endianess_matcher_nanosecond(buf)
        }

        fn pcapng_shb_magic_matcher(buf: &[u8]) -> bool {
            buf.len() >= 4 && buf[0] == 0x0a && buf[1] == 0x0d && buf[2] == 0x0d && buf[3] == 0x0a
        }
        fn pcapng_bom_magic_same_endianess_matcher(buf: &[u8]) -> bool {
            buf.len() >= 12
                && buf[8] == 0x1a
                && buf[9] == 0x2b
                && buf[10] == 0x3c
                && buf[11] == 0x4d
        }
        fn pcapng_bom_magic_reverse_endianess_matcher(buf: &[u8]) -> bool {
            buf.len() >= 12
                && buf[8] == 0x4d
                && buf[9] == 0x3c
                && buf[10] == 0x2b
                && buf[11] == 0x1a
        }
        fn pcapng_matcher(buf: &[u8]) -> bool {
            pcapng_shb_magic_matcher(buf)
                && (pcapng_bom_magic_same_endianess_matcher(buf)
                    || pcapng_bom_magic_reverse_endianess_matcher(buf))
        }

        let mut info = infer::Infer::new();
        info.add("custom/lz4", "lz4", lz4_matcher);
        info.add("custom/pcap", "pcap", pcap_matcher);
        info.add("custom/pcap", "pcap", pcapng_matcher);

        let mut buf = vec![0; 12];
        file.read_exact(&mut buf)?;

        let kind = info.get(&buf).unwrap();

        file.seek(SeekFrom::Start(0))?;
        let b: Result<Box<dyn Read + Send>, Error> = match kind.mime_type() {
            "application/gz" => {
                if !input_filename.ends_with(".gz") {
                    warn!("Inferred file type is gz but file extension is not gz")
                }
                Ok(Box::new(GzDecoder::new(file)))
            }
            "application/xz" => {
                if !input_filename.ends_with(".xz") {
                    warn!("Inferred file type is xz but file extension is not xz")
                };
                Ok(Box::new(XzDecoder::new(file)))
            }
            "custom/lz4" => {
                if !input_filename.ends_with(".lz4") {
                    warn!("Inferred file type is lz4 but file extension is not lz4")
                };
                Ok(Box::new(lz4::Decoder::new(file)?))
            }
            "custom/pcap" => Ok(Box::new(file)),
            _ => {
                warn!("Could not infer file type '{}'", input_filename);
                if input_filename.ends_with(".gz") {
                    Ok(Box::new(GzDecoder::new(file)))
                } else if input_filename.ends_with(".xz") {
                    Ok(Box::new(XzDecoder::new(file)))
                } else if input_filename.ends_with(".lz4") {
                    Ok(Box::new(lz4::Decoder::new(file)?))
                } else {
                    Ok(Box::new(file))
                }
            }
        };

        b?
    };
    Ok(input_reader)
}
