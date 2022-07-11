#![warn(clippy::all)]
#![allow(clippy::upper_case_acronyms)]

#[macro_use]
extern crate log;

extern crate clap;
use clap::{crate_version, App, Arg};

// extern crate env_logger;
extern crate flate2;
extern crate pcap_parser;
extern crate xz2;

use std::io;
use std::path::Path;
use std::{fs::File, io::Read};

use flate2::read::GzDecoder;
use xz2::read::XzDecoder;

use libpcap_tools::{Config, PcapDataEngine, PcapEngine};

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
            Arg::with_name("filters")
                .help(
                    "Filters to load (default: none)
Arguments can be specified using : after the filter name.
Example: -f Source:192.168.1.1",
                )
                .short("f")
                .long("filters")
                .multiple(true)
                .number_of_values(1)
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

    let mut filters: Vec<Box<dyn filter::Filter>> = Vec::new();
    let filter_names: Vec<&str> = matches.values_of("filters").unwrap_or_default().collect();
    for name in &filter_names {
        eprintln!("adding filter: {}", name);
        let args: Vec<_> = name.splitn(2, ':').collect();
        match args[0] {
            "IP" => {
                eprintln!("adding IP filter");
                let f = common_filters::IPFilter::new(&args[1..]);
                filters.push(Box::new(f));
            }
            "Source" => {
                eprintln!("adding source filter");
                let f = common_filters::SourceFilter::new(&args[1..]);
                filters.push(Box::new(f));
            }
            _ => (),
        }
    }

    let mut input_reader = get_reader(input_filename)?;
    let path = Path::new(&output_filename);
    let outfile = File::create(path)?;

    // let block_analyzer = BlockRewriter::new(outfile);
    // let mut engine = BlockEngine::new(block_analyzer, &config);

    let rewriter = Rewriter::new(Box::new(outfile), output_format, filters);
    let mut engine = PcapDataEngine::new(rewriter, &config);

    if engine.data_analyzer().require_pre_analysis() {
        // check that we are not using stdin
        if input_filename == "-" {
            error!("Plugins with pre-analysis pass cannot be run on stdin");
            ::std::process::exit(1);
        }
        info!("Running pre-analysis pass");
        engine.data_analyzer_mut().set_run_pre_analysis(true);
        engine.run(&mut input_reader).expect("run analyzer");
        // reset reader
        input_reader = get_reader(input_filename)?;
    }

    info!("Rewriting file (output format: {:?})", output_format);
    engine.run(&mut input_reader).expect("run analyzer");

    Ok(())
}

fn get_reader(input_filename: &str) -> io::Result<Box<dyn Read>> {
    let input_reader = if input_filename == "-" {
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
    Ok(input_reader)
}
