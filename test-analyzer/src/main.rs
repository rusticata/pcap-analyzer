#![warn(clippy::all)]

#[macro_use]
extern crate log;

use clap::{crate_version, App, Arg};
use explugin_example::ExEmptyPluginBuilder;
use libpcap_analyzer::*;
use libpcap_analyzer::plugins::PluginsFactory;
use libpcap_tools::{Config, PcapDataEngine, PcapEngine};
use simplelog::{LevelFilter, SimpleLogger};
use std::fs::File;
use std::io;
use std::io::{Error, ErrorKind};
use std::path::Path;
use std::sync::Arc;

use flate2::read::GzDecoder;
use xz2::read::XzDecoder;

fn load_config(config: &mut Config, filename: &str) -> Result<(), io::Error> {
    debug!("Loading configuration {}", filename);
    let path = Path::new(&filename);
    let file = File::open(path)?;
    config.load_config(file)
}

const ENV_LOG : &str = "PCAP_ANALYZER_LOG";
fn env_get_log_level() -> LevelFilter {
    match std::env::var(ENV_LOG) {
        Ok(key) => {
            match key.as_ref() {
                "off" => LevelFilter::Off,
                "error" => LevelFilter::Error,
                "warn" => LevelFilter::Warn,
                "info" => LevelFilter::Info,
                "debug" => LevelFilter::Debug,
                "trace" => LevelFilter::Trace,
                _ => panic!("Invalid log level '{}'", key),
            }
        },
        _ => LevelFilter::Debug
    }
}

fn main() -> Result<(), io::Error> {
    let matches = App::new("Pcap analyzer test tool")
        .version(crate_version!())
        .author("Pierre Chifflier")
        .about("Test tool for pcap-analyzer crate")
        .arg(
            Arg::with_name("config")
                .help("Configuration file")
                .short("c")
                .long("config")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("jobs")
                .help("Number of concurrent jobs to run (default: 1)")
                .short("j")
                .long("jobs")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("plugins")
                .help("Plugins to load (default: all)")
                .short("p")
                .long("plugins")
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

    let log_level = env_get_log_level();
    let _ = SimpleLogger::init(log_level, simplelog::Config::default());
    info!("test-analyzer tool starting");

    // create plugin factory with all available plugins
    let mut factory = PluginsFactory::default();
    // add external plugins
    factory.add_builder(Box::new(ExEmptyPluginBuilder));
    let mut config = Config::default();
    if let Some(filename) = matches.value_of("config") {
        load_config(&mut config, filename)?;
    }
    let input_filename = matches.value_of("INPUT").unwrap();

    let skip = matches.value_of("skip").unwrap_or("0");
    let skip = skip.parse::<u32>().map_err(|_| Error::new(
        ErrorKind::Other,
        "Invalid value for 'skip' argument",
    ))?;
    config.set("skip_index", skip);

    // override config options from command-line arguments
    if let Some(jobs) = matches.value_of("jobs") {
        let j = jobs.parse::<u32>().or_else(|_| Err(io::Error::new(
            io::ErrorKind::Other,
            "Invalid value for 'jobs' argument",
        )))?;
        config.set("num_threads", j);
    }

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
    debug!("test-analyzer instantiated plugins:");
    registry.run_plugins(
        |_| true,
        |p| {
            debug!("  {}", p.name());
            let t = p.plugin_type();
            let mut s = "    layers: ".to_owned();
            if t & PLUGIN_L2 != 0 { s += "  L2"; }
            if t & PLUGIN_L3 != 0 { s += "  L3"; }
            if t & PLUGIN_L4 != 0 { s += "  L4"; }
            debug!("{}", s);
            let mut s = "    events: ".to_owned();
            if t & PLUGIN_FLOW_NEW != 0 { s += "  FLOW_NEW"; }
            if t & PLUGIN_FLOW_DEL != 0 { s += "  FLOW_DEL"; }
            debug!("{}", s);
        },
        );

    // let analyzer: Box<dyn PcapAnalyzer> = match config.get_usize("num_threads") {
    //     Some(1) => Box::new(Analyzer::new(registry, &config)),
    //     _ => Box::new(ThreadedAnalyzer::new(registry, &config)),
    // };

    let mut input_reader: Box<dyn io::Read> = if input_filename == "-" {
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

    info!("test-analyzer: done");
    Ok(())
}