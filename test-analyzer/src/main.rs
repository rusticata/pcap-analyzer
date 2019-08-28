#[macro_use]
extern crate log;

use clap::{crate_version, App, Arg};
use explugin_example::ExEmptyPluginBuilder;
use libpcap_analyzer::{plugins::PluginsFactory, Analyzer, ThreadedAnalyzer};
use libpcap_tools::{Config, PcapAnalyzer, PcapEngine, SingleThreadedEngine};
use std::fs::File;
use std::io;
use std::path::Path;

fn load_config(config: &mut Config, filename: &str) -> Result<(), io::Error> {
    debug!("Loading configuration {}", filename);
    let path = Path::new(&filename);
    let file = File::open(path)?;
    config.load_config(file)
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
                .help("Number of concurrent jobs to run (default: number of cpus)")
                .short("j")
                .long("jobs")
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

    // override config options from command-line arguments
    if let Some(jobs) = matches.value_of("jobs") {
        let j = jobs.parse::<u32>().or(Err(io::Error::new(
            io::ErrorKind::Other,
            "Invalid value for 'jobs' argument",
        )))?;
        config.set("num_threads", j);
    }

    let registry = factory.build_plugins(&config);

    let analyzer: Box<dyn PcapAnalyzer> = match config.get_usize("num_threads") {
        Some(1) => Box::new(Analyzer::new(registry, &config)),
        _ => Box::new(ThreadedAnalyzer::new(registry, &config)),
    };

    let mut input_reader: Box<dyn io::Read> = if input_filename == "-" {
        Box::new(io::stdin())
    } else {
        let path = Path::new(&input_filename);
        let file = File::open(path)?;
        Box::new(file)
    };

    let mut engine = SingleThreadedEngine::new(analyzer, &config);
    let _ = engine.run(&mut input_reader).expect("run analyzer");

    info!("test-analyzer: done");
    Ok(())
}
