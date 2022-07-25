#![warn(clippy::all)]
#![allow(clippy::upper_case_acronyms)]

#[macro_use]
extern crate log;

extern crate clap;
use clap::{crate_version, App, Arg};
use pnet_packet::ip::IpNextHeaderProtocol;

// extern crate env_logger;
extern crate flate2;
extern crate pcap_parser;
extern crate xz2;

use std::io;
use std::net::IpAddr;
use std::path::Path;
use std::{fs::File, io::Read};

use flate2::read::GzDecoder;
use xz2::read::XzDecoder;

use libpcap_tools::{Config, FiveTuple, PcapDataEngine, PcapEngine};

mod container;
mod filters;
mod pcap;
mod pcapng;
mod rewriter;
mod traits;

use crate::rewriter::*;
use container::five_tuple_container::FiveTupleC;
use container::ipaddr_container::IpAddrC;
use container::ipaddr_proto_port_container::IpAddrProtoPortC;
use filters::dispatch_filter;
use filters::filtering_action::FilteringAction;
use filters::filtering_key::FilteringKey;
use filters::key_parser_ipv4;
use filters::key_parser_ipv6;

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
Example: -f Source:192.168.1.1",
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

                match filtering_key {
                    FilteringKey::SrcIpaddr => {
                        let ipaddr_container = IpAddrC::of_file_path(Path::new(key_file_path))
                            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

                        let keep: &dyn Fn(&IpAddrC, &IpAddr) -> Result<bool, String> =
                            match filtering_action {
                                FilteringAction::Keep => {
                                    &|c: &IpAddrC, ipaddr| Ok(c.contains(ipaddr))
                                }
                                FilteringAction::Drop => {
                                    &|c: &IpAddrC, ipaddr| Ok(!c.contains(ipaddr))
                                }
                            };

                        let f = dispatch_filter::DispatchFilter::new(
                            ipaddr_container,
                            Box::new(key_parser_ipv4::parse_src_ipaddr),
                            Box::new(key_parser_ipv6::parse_src_ipaddr),
                            Box::new(keep),
                        );
                        filters.push(Box::new(f));
                    }
                    FilteringKey::DstIpaddr => {
                        let ipaddr_container = IpAddrC::of_file_path(Path::new(key_file_path))
                            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

                        let keep: &dyn Fn(&IpAddrC, &IpAddr) -> Result<bool, String> =
                            match filtering_action {
                                FilteringAction::Keep => {
                                    &|c: &IpAddrC, ipaddr| Ok(c.contains(ipaddr))
                                }
                                FilteringAction::Drop => {
                                    &|c: &IpAddrC, ipaddr| Ok(!c.contains(ipaddr))
                                }
                            };

                        let f = dispatch_filter::DispatchFilter::new(
                            ipaddr_container,
                            Box::new(key_parser_ipv4::parse_dst_ipaddr),
                            Box::new(key_parser_ipv6::parse_dst_ipaddr),
                            Box::new(keep),
                        );
                        filters.push(Box::new(f));
                    }
                    FilteringKey::SrcDstIpaddr => {
                        let ipaddr_container = IpAddrC::of_file_path(Path::new(key_file_path))
                            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

                        let keep: &dyn Fn(&IpAddrC, &(IpAddr, IpAddr)) -> Result<bool, String> =
                            match filtering_action {
                                FilteringAction::Keep => &|c, ipaddr_tuple| {
                                    Ok(c.contains(&ipaddr_tuple.0) || c.contains(&ipaddr_tuple.1))
                                },
                                FilteringAction::Drop => &|c, ipaddr_tuple| {
                                    Ok(!c.contains(&ipaddr_tuple.0) && !c.contains(&ipaddr_tuple.1))
                                },
                            };

                        let f = dispatch_filter::DispatchFilter::new(
                            ipaddr_container,
                            Box::new(key_parser_ipv4::parse_src_dst_ipaddr),
                            Box::new(key_parser_ipv6::parse_src_dst_ipaddr),
                            Box::new(keep),
                        );
                        filters.push(Box::new(f));
                    }
                    FilteringKey::SrcIpaddrProtoDstPort => {
                        let ipaddr_proto_port_container =
                            IpAddrProtoPortC::of_file_path(Path::new(key_file_path))
                                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

                        let keep: &dyn Fn(
                            &IpAddrProtoPortC,
                            &(IpAddr, IpNextHeaderProtocol, u16),
                        ) -> Result<bool, String> = match filtering_action {
                            FilteringAction::Keep => {
                                &|c, tuple| Ok(c.contains(&tuple.0, &tuple.1, tuple.2))
                            }
                            FilteringAction::Drop => {
                                &|c, tuple| Ok(!c.contains(&tuple.0, &tuple.1, tuple.2))
                            }
                        };

                        let f = dispatch_filter::DispatchFilter::new(
                            ipaddr_proto_port_container,
                            Box::new(key_parser_ipv4::parse_src_ipaddr_proto_dst_port),
                            Box::new(key_parser_ipv6::parse_src_ipaddr_proto_dst_port),
                            Box::new(keep),
                        );
                        filters.push(Box::new(f));
                    }
                    FilteringKey::SrcDstIpaddrProtoSrcDstPort => {
                        let five_tuple_container =
                            FiveTupleC::of_file_path(Path::new(key_file_path))
                                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

                        let keep: &dyn Fn(&FiveTupleC, &FiveTuple) -> Result<bool, String> =
                            match filtering_action {
                                FilteringAction::Keep => {
                                    &|c, five_tuple| Ok(c.contains(five_tuple))
                                }
                                FilteringAction::Drop => {
                                    &|c, five_tuple| Ok(!c.contains(five_tuple))
                                }
                            };

                        let f = dispatch_filter::DispatchFilter::new(
                            five_tuple_container,
                            Box::new(key_parser_ipv4::parse_five_tuple),
                            Box::new(key_parser_ipv6::parse_five_tuple),
                            Box::new(keep),
                        );
                        filters.push(Box::new(f));
                    }
                }
            }
            _ => {
                error!("Unexpected filter name");
                ::std::process::exit(1);
            }
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
        let file = File::open(path).map_err(|e| {
            error!("Could not open input file '{}'", input_filename);
            e
        })?;
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
