#![warn(clippy::all)]

#[macro_use]
extern crate log;

extern crate clap;
use clap::{crate_version, Parser};
use tracing::Level;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::EnvFilter;

extern crate flate2;
extern crate lz4;
extern crate xz2;

use std::fs::File;
use std::io;
use std::path::Path;
use std::sync::Arc;

use flate2::read::GzDecoder;
use xz2::read::XzDecoder;

use libpcap_analyzer::*;
use libpcap_tools::{Config, PcapDataEngine, PcapEngine};

/// Pcap file analysis tool
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Configuration file
    #[arg(short, long, value_name = "CONFIG")]
    config: Option<String>,

    /// Plugins to load (default: all)
    #[arg(short, long)]
    plugins: Option<String>,

    /// List plugin builders and exit
    #[arg(long)]
    list_builders: bool,

    /// List instanciated plugins and exit
    #[arg(long)]
    list_plugins: bool,

    /// Plugins output directory
    #[arg(short, long)]
    outdir: Option<String>,

    /// Number of jobs to run (default: 0 (auto))
    #[arg(short, long, default_value_t = 0)]
    jobs: u8,

    /// Number of packets to skip
    #[arg(short, long, default_value_t = 0)]
    skip: u32,

    /// Be verbose
    #[arg(short, long)]
    verbose: bool,

    /// Input file
    input: Option<String>,
}

fn load_config(config: &mut Config, filename: &str) -> Result<(), io::Error> {
    debug!("Loading configuration {filename}");
    let path = Path::new(&filename);
    let file = File::open(path)?;
    config.load_config(file)
}

fn main() -> io::Result<()> {
    let args = Args::parse();

    // create plugin factory with all available plugins
    let factory = plugins::PluginsFactory::default();
    // check if asked to list plugin builders
    if args.list_builders {
        println!("pcap-analyzer available plugin builders:");
        factory.iter_builders(|name| println!("    {name}"));
        ::std::process::exit(0);
    }
    // load config
    let mut config = Config::default();
    if let Some(filename) = args.config {
        load_config(&mut config, &filename)?;
    }
    // override config options from command-line arguments
    config.set("num_threads", args.jobs);
    if let Some(dir) = args.outdir {
        config.set("output_dir", dir.as_str());
    }
    config.set("skip_index", args.skip);

    // Open log file
    let log_file = config.get("log_file").unwrap_or("pcap-analyzer.log");
    let output_dir = config.get("output_dir").unwrap_or(".");
    let file_appender = RollingFileAppender::new(Rotation::NEVER, output_dir, log_file);
    let env_filter = EnvFilter::try_from_env("PCAP_ANALYZER_LOG")
        .unwrap_or_else(|_| EnvFilter::from_default_env().add_directive(Level::INFO.into()));
    tracing_subscriber::fmt()
        .with_writer(file_appender)
        .with_env_filter(env_filter)
        //.json()
        //.with_span_events(FmtSpan::ENTER)
        //.with_thread_ids(true)
        //.with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .compact()
        .init();

    // Now, really start
    info!("Pcap analyser {}", crate_version!());

    // instantiate all plugins
    let registry = if let Some(plugin_names) = args.plugins.as_ref() {
        debug!("Restricting plugins to: {plugin_names}");
        let names: Vec<_> = plugin_names.split(',').collect();
        factory
            .build_filter_plugins(
                |n| {
                    debug!("n: {n}");
                    names.iter().any(|&x| n.contains(x))
                },
                &config,
            )
            .expect("Could not build factory")
    } else {
        factory
            .build_plugins(&config)
            .expect("Could not build factory")
    };
    // check if asked to list plugins
    if args.list_plugins {
        println!("pcap-analyzer instanciated plugins:");
        registry.run_plugins(
            |_| true,
            |p| {
                println!("  {}", p.name());
                let t = p.plugin_type();
                print!("    layers: ");
                if t & PLUGIN_L2 != 0 {
                    print!("  L2");
                }
                if t & PLUGIN_L3 != 0 {
                    print!("  L3");
                }
                if t & PLUGIN_L4 != 0 {
                    print!("  L4");
                }
                println!();
                print!("    events: ");
                if t & PLUGIN_FLOW_NEW != 0 {
                    print!("  FLOW_NEW");
                }
                if t & PLUGIN_FLOW_DEL != 0 {
                    print!("  FLOW_DEL");
                }
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

    let input_filename = match args.input.as_ref() {
        Some(s) => s.as_str(),
        None => {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Input file name cannot be empty",
            ));
        }
    };

    let mut input_reader = if input_filename == "-" {
        Box::new(io::stdin())
    } else {
        let path = Path::new(input_filename);
        let file = File::open(path)?;
        if input_filename.ends_with(".gz") {
            Box::new(GzDecoder::new(file))
        } else if input_filename.ends_with(".xz") {
            Box::new(XzDecoder::new(file))
        } else if input_filename.ends_with(".lz4") {
            Box::new(lz4::Decoder::new(file)?)
        } else {
            Box::new(file) as Box<dyn io::Read + Send>
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

    // TODO: log results

    info!("pcap-analyzer: done, exiting");
    Ok(())
}
