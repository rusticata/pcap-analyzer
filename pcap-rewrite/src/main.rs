#![warn(clippy::all)]

#[macro_use]
extern crate log;

extern crate clap;
use clap::{crate_version, App, Arg};

// extern crate env_logger;
extern crate flate2;
extern crate pcap_parser;
extern crate xz2;

use std::fs::File;
use std::io;
use std::path::Path;

use flate2::read::GzDecoder;
use xz2::read::XzDecoder;

use libpcap_tools::{Config, PcapEngine, SingleThreadedEngine};

mod common_filters;
mod filter;
mod pcap;
mod pcapng;
mod rewriter;
mod traits;
use crate::rewriter::*;

fn load_config(config: &mut Config, filename: &str) -> Result<(), io::Error> {
    debug!("Loading configuration {}", filename);
    let path = Path::new(&filename);
    let file = File::open(path)?;
    config.load_config(file)
}

fn main() -> io::Result<()> {
    let matches = App::new("Pcap rewrite tool")
        .version(crate_version!())
        .author("Pierre Chifflier")
        .about("Tool for rewriting pcap files")
        .arg(
            Arg::with_name("plugins")
                .help("Plugins to load (default: none)")
                .short("p")
                .long("plugins")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("config")
                .help("Configuration file")
                .short("c")
                .long("config")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("output-format")
                .help("Output format (default: pcap)")
                .short("of")
                .long("output-format")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("INPUT")
                .help("Input file name")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::with_name("OUTPUT")
                .help("Output file name")
                .required(true)
                .index(2),
        )
        .get_matches();

    let _ =
        simplelog::SimpleLogger::init(simplelog::LevelFilter::Debug, simplelog::Config::default());
    debug!("Pcap rewrite tool {}", crate_version!());

    let mut config = Config::default();
    if let Some(filename) = matches.value_of("config") {
        load_config(&mut config, filename)?;
    }

    let input_filename = matches.value_of("INPUT").unwrap();
    let output_filename = matches.value_of("OUTPUT").unwrap();
    let output_format = match matches.value_of("output-format") {
        Some("pcap") => FileFormat::Pcap,
        Some("pcapng") => FileFormat::PcapNG,
        Some(_) => {
            error!("Invalid output file format");
            ::std::process::exit(1);
        }
        None => FileFormat::Pcap,
    };

    let mut input_reader = if input_filename == "-" {
        Box::new(io::stdin())
    } else {
        let path = Path::new(&input_filename);
        let file = File::open(path)?;
        if input_filename.ends_with(".gz") {
            Box::new(GzDecoder::new(file))
        } else if input_filename.ends_with(".xz") {
            Box::new(XzDecoder::new(file))
        } else {
            Box::new(file) as Box<dyn io::Read>
        }
    };
    let path = Path::new(&output_filename);
    let outfile = File::create(path)?;

    let rewriter = Rewriter::new(Box::new(outfile), output_format);
    let mut engine = SingleThreadedEngine::new(Box::new(rewriter), &config);

    info!("Rewriting file (output format: {:?})", output_format);

    engine.run(&mut input_reader).expect("run analyzer");

    Ok(())
}
