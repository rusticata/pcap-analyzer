#![warn(clippy::all)]
#![allow(clippy::upper_case_acronyms)]

use clap::{crate_version, App, Arg};
use libpcap_tools::Config;
use log::{debug, error};
use std::fs::File;
use std::io;
use std::path::Path;

use pcap_rewrite::filters::dispatch_filter::DispatchFilterBuilder;
use pcap_rewrite::filters::filtering_action::FilteringAction;
use pcap_rewrite::filters::filtering_key::FilteringKey;
use pcap_rewrite::filters::fragmentation::fragmentation_filter::FragmentationFilterBuilder;
use pcap_rewrite::rewriter::*;
use pcap_rewrite::{filters, RewriteOptions};

fn load_config(config: &mut Config, filename: &str) -> Result<(), io::Error> {
    debug!("Loading configuration {}", filename);
    let path = Path::new(&filename);
    let file = File::open(path).map_err(|e| {
        error!("Could not open config file '{}'", filename);
        e
    })?;
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
Examples:
-f Source:192.168.1.1
-f Dispatch:fk%fa%path
-f Dispatch:fk%fa

fk: filtering key=si|di|sdi|sipdp|sdipsdp
with si: src IP
     di: dst IP
     sdi: srd/dst IP
     sipdp: src IP, proto, dst port
     sdipsdp: src/dst IP, proto, src/dst port

fa: filtering action=k|d
with k: keep
     d: drop

path: path to a csv formatted file without header that contains filtering keys
",
                )
                .short('f')
                .long("filters")
                .multiple(true)
                .number_of_values(1)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("config")
                .help("Configuration file")
                .short('c')
                .long("config")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("output-format")
                .help("Output format (default: pcap)")
                .short('o')
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

    let mut filters: Vec<Box<dyn filters::filter::Filter>> = Vec::new();
    let filter_names: Vec<&str> = matches.values_of("filters").unwrap_or_default().collect();
    for name in &filter_names {
        eprintln!("adding filter: {}", name);
        let args: Vec<_> = name.splitn(2, ':').collect();
        match args[0] {
            "IP" => {
                eprintln!("adding IP filter");
                let f = filters::common_filters::IPFilter::new(&args[1..]);
                filters.push(Box::new(f));
            }
            "Source" => {
                eprintln!("adding source filter");
                let f = filters::common_filters::SourceFilter::new(&args[1..]);
                filters.push(Box::new(f));
            }
            "Dispatch" => {
                eprintln!("adding dispatch filter");
                let dispatch_data = args[1];
                let args: Vec<_> = dispatch_data.split('%').collect();
                assert_eq!(args.len(), 3);
                let filtering_key = FilteringKey::of_string(args[0])
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                let filtering_action = FilteringAction::of_string(args[1])
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                let key_file_path = args[2];

                let f = DispatchFilterBuilder::from_args(
                    filtering_key,
                    filtering_action,
                    key_file_path,
                )?;
                filters.push(f);
            }
            "Fragmentation" => {
                eprintln!("adding fragmentation filter");
                let dispatch_data = args[1];
                let args: Vec<_> = dispatch_data.split('%').collect();
                if args.len() != 2 {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "More than two arguments provided to fragmentation filter.".to_string(),
                    ));
                };
                let filtering_key = FilteringKey::of_string(args[0])
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                let filtering_action = FilteringAction::of_string(args[1])
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

                let f = FragmentationFilterBuilder::from_args(filtering_key, filtering_action)?;
                filters.push(f);
            }
            _ => {
                error!("Unexpected filter name");
                ::std::process::exit(1);
            }
        }
    }

    let options = RewriteOptions {
        output_format,
        config,
    };

    pcap_rewrite::pcap_rewrite_file(input_filename, output_filename, filters, &options)
}
