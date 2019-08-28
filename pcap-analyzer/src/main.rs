#[macro_use]
extern crate log;

extern crate clap;
use clap::{crate_version, App, Arg};

extern crate env_logger;
extern crate flate2;
extern crate lz4;
extern crate xz2;

use std::fs::File;
use std::io;
use std::io::{Error, ErrorKind};
use std::path::Path;

use flate2::read::GzDecoder;
use xz2::read::XzDecoder;

use libpcap_analyzer::*;
use libpcap_tools::{Config, PcapAnalyzer, PcapEngine, SingleThreadedEngine};

fn load_config(config: &mut Config, filename: &str) -> Result<(), io::Error> {
    debug!("Loading configuration {}", filename);
    let path = Path::new(&filename);
    let file = File::open(path)?;
    config.load_config(file)
}

fn main() -> io::Result<()> {
    let matches = App::new("Pcap analyzer")
        .version(crate_version!())
        .author("Pierre Chifflier")
        .about("Tool for Pcap file analyzis")
        .arg(
            Arg::with_name("verbose")
                .help("Be verbose")
                .short("v")
                .long("verbose"),
        )
        .arg(
            Arg::with_name("jobs")
                .help("Number of concurrent jobs to run (default: number of cpus)")
                .short("j")
                .long("jobs")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("list-builders")
                .help("List plugin builders and exit")
                .long("list-builders")
        )
        .arg(
            Arg::with_name("list-plugins")
                .help("List instanciated plugins and exit")
                .short("l")
                .long("list-plugins")
        )
        .arg(
            Arg::with_name("plugins")
                .help("Plugins to load (default: all)")
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
            Arg::with_name("INPUT")
                .help("Input file name")
                .required(true)
                .index(1),
        )
        .get_matches();

    env_logger::init();

    debug!("Pcap analyser {}", crate_version!());

    // create plugin factory with all available plugins
    let factory = plugins::PluginsFactory::default();
    // check if asked to list plugin builders
    if matches.is_present("list-builders") {
        println!("pcap-analyzer available plugin builders:");
        factory.iter_builders(|name|
                              println!("    {}", name));
        ::std::process::exit(0);
    }
    // load config
    let mut config = Config::default();
    if let Some(filename) = matches.value_of("config") {
        load_config(&mut config, filename)?;
    }
    // override config options from command-line arguments
    if let Some(jobs) = matches.value_of("jobs") {
        let j = jobs.parse::<u32>().or(Err(Error::new(
            ErrorKind::Other,
            "Invalid value for 'jobs' argument",
        )))?;
        config.set("num_threads", j);
    }
    // instanciate all plugins
    let registry = if let Some(plugin_names) = matches.value_of("plugins") {
        debug!("Restricting plugins to: {}", plugin_names);
        let names: Vec<_> = plugin_names.split(",").collect();
        factory.build_filter_plugins(
            |n| {
                debug!("n: {}", n);
                names.iter().any(|&x| n.contains(x))
            },
            &config,
        )
    } else {
        factory.build_plugins(&config)
    };
    // check if asked to list plugins
    if matches.is_present("list-plugins") {
        println!("pcap-analyzer instanciated plugins:");
        registry.run_plugins(
            |_| true,
            |p| {
                println!("  {}", p.name());
                let t = p.plugin_type();
                print!("    layers: ");
                if t & PLUGIN_L2 != 0 { print!("  L2"); }
                if t & PLUGIN_L3 != 0 { print!("  L3"); }
                if t & PLUGIN_L4 != 0 { print!("  L4"); }
                println!("");
                print!("    events: ");
                if t & PLUGIN_FLOW_NEW != 0 { print!("  FLOW_NEW"); }
                if t & PLUGIN_FLOW_DEL != 0 { print!("  FLOW_DEL"); }
                println!("");
            },
            );
        ::std::process::exit(0);
    }
    if registry.num_plugins() == 0 {
        warn!("No plugins loaded");
    }
    debug!("Plugins loaded:");
    registry.run_plugins(
        |_| true,
        |p| {
            debug!("  {}", p.name());
        },
    );
    let input_filename = matches.value_of("INPUT").unwrap();

    let mut input_reader = if input_filename == "-" {
        Box::new(io::stdin())
    } else {
        let path = Path::new(&input_filename);
        let file = File::open(path)?;
        if input_filename.ends_with(".gz") {
            Box::new(GzDecoder::new(file))
        } else if input_filename.ends_with(".xz") {
            Box::new(XzDecoder::new(file))
        } else if input_filename.ends_with(".lz4") {
            Box::new(lz4::Decoder::new(file)?)
        } else {
            Box::new(file) as Box<dyn io::Read>
        }
    };

    let analyzer: Box<dyn PcapAnalyzer> = match config.get_usize("num_threads") {
        Some(1) => Box::new(Analyzer::new(registry, &config)),
        _ => Box::new(ThreadedAnalyzer::new(registry, &config)),
    };
    let mut engine = SingleThreadedEngine::new(analyzer, &config);

    let _ = engine.run(&mut input_reader).expect("run analyzer");

    Ok(())
}
