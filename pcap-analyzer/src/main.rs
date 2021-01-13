#![warn(clippy::all)]

#[macro_use]
extern crate log;

extern crate clap;
use clap::{crate_version, App, Arg};

extern crate flate2;
extern crate lz4;
extern crate xz2;

use std::fs::{File, OpenOptions};
use std::io;
use std::io::{Error, ErrorKind};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use flate2::read::GzDecoder;
use xz2::read::XzDecoder;

use libpcap_analyzer::*;
use libpcap_tools::{Config, PcapDataEngine, PcapEngine};

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
                .help("Number of concurrent jobs to run (default: 1)")
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
            Arg::with_name("outdir")
                .help("Plugins output directory")
                .short("o")
                .long("outdir")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("INPUT")
                .help("Input file name")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::with_name("skip")
                .help("Skip given number of packets")
                .long("skip")
                .takes_value(true),
        )
        .get_matches();

    // create plugin factory with all available plugins
    let factory = plugins::PluginsFactory::default();
    // check if asked to list plugin builders
    if matches.is_present("list-builders") {
        println!("pcap-analyzer available plugin builders:");
        factory.iter_builders(|name| println!("    {}", name));
        ::std::process::exit(0);
    }
    // load config
    let mut config = Config::default();
    if let Some(filename) = matches.value_of("config") {
        load_config(&mut config, filename)?;
    }
    // override config options from command-line arguments
    if let Some(jobs) = matches.value_of("jobs") {
        #[allow(clippy::or_fun_call)]
        let j = jobs.parse::<u32>().or(Err(Error::new(
            ErrorKind::Other,
            "Invalid value for 'jobs' argument",
        )))?;
        config.set("num_threads", j);
    }
    if let Some(dir) = matches.value_of("outdir") {
        config.set("output_dir", dir);
    }

    let skip = matches.value_of("skip").unwrap_or("0");
    let skip = skip.parse::<u32>().map_err(|_| Error::new(
        ErrorKind::Other,
        "Invalid value for 'skip' argument",
    ))?;
    config.set("skip_index", skip);

    // Open log file
    let log_file = config.get("log_file").unwrap_or("pcap-analyzer.log");
    let mut path_log = PathBuf::new();
    if let Some(dir) = config.get("output_dir") {
        path_log.push(dir);
    }
    path_log.push(log_file);
    let f = OpenOptions::new()
        .append(true)
        .create(true)
        .open(&path_log)
        .unwrap();

    // let _ = simplelog::SimpleLogger::init(simplelog::LevelFilter::Info, simplelog::Config::default());
    let _ = simplelog::WriteLogger::init(simplelog::LevelFilter::Info, simplelog::Config::default(), f);

    // Now, really start
    info!("Pcap analyser {}", crate_version!());

    // instantiate all plugins
    let registry = if let Some(plugin_names) = matches.value_of("plugins") {
        debug!("Restricting plugins to: {}", plugin_names);
        let names: Vec<_> = plugin_names.split(',').collect();
        factory.build_filter_plugins(
            |n| {
                debug!("n: {}", n);
                names.iter().any(|&x| n.contains(x))
            },
            &config,
        ).expect("Could not build factory")
    } else {
        factory.build_plugins(&config).expect("Could not build factory")
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
                println!();
                print!("    events: ");
                if t & PLUGIN_FLOW_NEW != 0 { print!("  FLOW_NEW"); }
                if t & PLUGIN_FLOW_DEL != 0 { print!("  FLOW_DEL"); }
                println!();
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

    let num_threads = config.get_usize("num_threads").unwrap_or(1);
    let mut engine = if num_threads == 1 {
        let analyzer = Analyzer::new(Arc::new(registry), &config);
        Box::new(PcapDataEngine::new(analyzer, &config)) as Box<dyn PcapEngine>
    } else {
        let analyzer = ThreadedAnalyzer::new(registry, &config);
        Box::new(PcapDataEngine::new(analyzer, &config)) as Box<dyn PcapEngine>
    };
    engine.run(&mut input_reader).expect("run analyzer");

    Ok(())
}
