#![warn(clippy::all)]
#![allow(clippy::upper_case_acronyms)]

use clap::{crate_version, Parser};
use libpcap_tools::Config;
use log::{debug, error};
use std::fs::File;
use std::io;
use std::path::Path;
use tracing::Level;
use tracing_subscriber::EnvFilter;

use pcap_rewrite::filters::dispatch_filter::DispatchFilterBuilder;
use pcap_rewrite::filters::filtering_action::FilteringAction;
use pcap_rewrite::filters::filtering_key::FilteringKey;
use pcap_rewrite::filters::fragmentation::fragmentation_filter::FragmentationFilterBuilder;
use pcap_rewrite::rewriter::*;
use pcap_rewrite::{filters, RewriteOptions};

/// Tool for rewriting pcap files
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Configuration file
    #[arg(short, long, value_name = "CONFIG")]
    config: Option<String>,

    /// Filters to load (default: none)
    ///
    /// Arguments can be specified using : after the filter name.
    /// Examples:
    /// -f Source:192.168.1.1
    /// -f Dispatch:fk%fa%path
    /// -f Dispatch:fk%fa
    ///
    /// fk: filtering key=si|di|sdi|sipdp|sdipsdp
    /// with si: src IP
    ///      di: dst IP
    ///      sdi: srd/dst IP
    ///      sipdp: src IP, proto, dst port
    ///      sdipsdp: src/dst IP, proto, src/dst port
    ///
    /// fa: filtering action=k|d
    /// with k: keep
    ///      d: drop
    ///
    /// path: path to a csv formatted file without header that contains filtering keys
    #[clap(verbatim_doc_comment)]
    #[arg(short, long)]
    filters: Vec<String>,

    /// Output format (default: pcap)
    #[arg(short, long)]
    output_format: Option<String>,

    /// Input file name
    input: String,

    /// Output file name
    output: String,
}

fn load_config(config: &mut Config, filename: &str) -> Result<(), io::Error> {
    debug!("Loading configuration {filename}");
    let path = Path::new(&filename);
    let file = File::open(path).map_err(|e| {
        error!("Could not open config file '{filename}'");
        e
    })?;
    config.load_config(file)
}

fn main() -> io::Result<()> {
    let args = Args::parse();

    let mut config = Config::default();
    if let Some(filename) = args.config.as_ref() {
        load_config(&mut config, filename)?;
    }

    let env_filter = EnvFilter::try_from_env("PCAP_REWRITE_LOG")
        .unwrap_or_else(|_| EnvFilter::from_default_env().add_directive(Level::INFO.into()));
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        //.json()
        //.with_span_events(FmtSpan::ENTER)
        //.with_thread_ids(true)
        //.with_max_level(tracing::Level::TRACE)
        .compact()
        .init();

    debug!("Pcap rewrite tool {}", crate_version!());

    let input_filename = args.input.as_str();
    let output_filename = args.output.as_str();
    let output_format = match args.output_format.as_deref() {
        Some("pcap") => FileFormat::Pcap,
        Some("pcapng") => FileFormat::PcapNG,
        Some(_) => {
            error!("Invalid output file format");
            ::std::process::exit(1);
        }
        None => FileFormat::Pcap,
    };

    let mut filters: Vec<Box<dyn filters::filter::Filter>> = Vec::new();
    let filter_names = &args.filters;
    for name in filter_names {
        eprintln!("adding filter: {name}");
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
                let filtering_key = FilteringKey::of_string(args[0]).map_err(io::Error::other)?;
                let filtering_action =
                    FilteringAction::of_string(args[1]).map_err(io::Error::other)?;
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
                    return Err(io::Error::other(
                        "More than two arguments provided to fragmentation filter.".to_string(),
                    ));
                };
                let filtering_key = FilteringKey::of_string(args[0]).map_err(io::Error::other)?;
                let filtering_action =
                    FilteringAction::of_string(args[1]).map_err(io::Error::other)?;

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
