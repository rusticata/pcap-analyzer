#![warn(clippy::all)]

#[macro_use]
extern crate log;

use clap::Parser;
use explugin_example::ExEmptyPluginBuilder;
use libpcap_analyzer::plugins::PluginsFactory;
use libpcap_analyzer::*;
use libpcap_tools::{Config, PcapDataEngine, PcapEngine};
use std::fs::File;
use std::io;
use std::path::Path;
use std::sync::Arc;
use tracing::Level;
use tracing_subscriber::EnvFilter;

use flate2::read::GzDecoder;
use xz2::read::XzDecoder;

mod display;
use display::*;

#[derive(Debug, clap::Args)]
#[group(required = true, multiple = false)]
pub struct InputGroup {
    /// Input file
    // #[clap(short, long)]
    input: Option<String>,

    #[cfg(feature = "live")]
    /// Live Mode
    #[clap(short, long)]
    interface: Option<String>,
}

/// Pcap analyzer test tool
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Configuration file
    #[arg(short, long, value_name = "CONFIG")]
    config: Option<String>,

    /// Plugins to load (default: all)
    #[arg(short, long)]
    plugins: Option<String>,

    /// Number of jobs to run (default: 1)
    #[arg(short, long, default_value_t = 1)]
    jobs: u8,

    /// Number of packets to skip
    #[arg(short, long, default_value_t = 0)]
    skip: u32,

    #[cfg(feature = "live")]
    /// Filter used to match packets
    #[arg(short, long)]
    filter: Option<String>,

    /// Input
    #[clap(flatten)]
    input_group: InputGroup,
}

fn load_config(config: &mut Config, filename: &str) -> Result<(), io::Error> {
    debug!("Loading configuration {filename}");
    let path = Path::new(&filename);
    let file = File::open(path)?;
    config.load_config(file)
}

fn main() -> Result<(), io::Error> {
    let args = Args::parse();

    let env_filter = EnvFilter::try_from_env("PCAP_ANALYZER_LOG")
        .unwrap_or_else(|_| EnvFilter::from_default_env().add_directive(Level::DEBUG.into()));
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        //.json()
        //.with_span_events(FmtSpan::ENTER)
        .with_thread_ids(true)
        //.with_max_level(tracing::Level::TRACE)
        .compact()
        .init();
    info!("test-analyzer tool starting");

    // create plugin factory with all available plugins
    let mut factory = PluginsFactory::default();
    // add external plugins
    factory.add_builder(Box::new(ExEmptyPluginBuilder));
    let mut config = Config::default();
    if let Some(filename) = args.config {
        load_config(&mut config, &filename)?;
    }

    config.set("skip_index", args.skip);

    // override config options from command-line arguments
    config.set("num_threads", args.jobs);

    let registry = if let Some(plugin_names) = args.plugins {
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
    debug!("test-analyzer instantiated plugins:");
    registry.run_plugins(
        |_| true,
        |p| {
            debug!("  {}", p.name());
            let t = p.plugin_type();
            let mut s = "    layers: ".to_owned();
            if t & PLUGIN_L2 != 0 {
                s += "  L2";
            }
            if t & PLUGIN_L3 != 0 {
                s += "  L3";
            }
            if t & PLUGIN_L4 != 0 {
                s += "  L4";
            }
            debug!("{s}");
            let mut s = "    events: ".to_owned();
            if t & PLUGIN_FLOW_NEW != 0 {
                s += "  FLOW_NEW";
            }
            if t & PLUGIN_FLOW_DEL != 0 {
                s += "  FLOW_DEL";
            }
            debug!("{s}");
        },
    );

    if let Some(input_filename) = args.input_group.input.as_ref() {
        let mut input_reader: Box<dyn io::Read + Send> = if input_filename == "-" {
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
                Box::new(file) as Box<dyn io::Read + Send>
            }
        };

        let num_threads = config.get_usize("num_threads").unwrap_or(1);
        if num_threads == 1 {
            let analyzer = Analyzer::new(Arc::new(registry), &config);
            let mut engine = PcapDataEngine::new(analyzer, &config);
            engine.run(&mut input_reader).expect("run analyzer");
            show_results(engine.data_analyzer());
        } else {
            let analyzer = ThreadedAnalyzer::new(registry, &config);
            let mut engine = PcapDataEngine::new(analyzer, &config);
            engine.run(&mut input_reader).expect("run analyzer");
            let threaded_data_analyzer = engine.data_analyzer();
            show_results(threaded_data_analyzer.inner_analyzer());
        }
    } else {
        #[cfg(feature = "live")]
        if let Some(interface_name) = args.input_group.interface {
            use libpcap_analyzer_live::create_engine_live;
            use std::sync::atomic::{AtomicBool, Ordering};

            let mut engine =
                create_engine_live(&interface_name, &config).map_err(io::Error::other)?;

            if let Some(filter) = args.filter.as_ref() {
                engine.set_filter(filter).map_err(io::Error::other)?;
            }

            let running = Arc::new(AtomicBool::new(true));
            let r = running.clone();
            ctrlc::set_handler(move || {
                debug!("Receiving SIGINT, exiting (this can take a few seconds)");
                r.store(false, Ordering::SeqCst);
            })
            .expect("Error setting Ctrl-C handler");

            engine.run(running).expect("live analyzer failed");
            show_results(engine.data_analyzer());
        }
        #[cfg(not(feature = "live"))]
        {
            // This is not supposed to be possible, if clap checks arguments
            error!("No input was provided");
            std::process::exit(1);
        }
    }

    info!("test-analyzer: done");
    Ok(())
}

fn show_results(analyzer: &Analyzer) {
    analyzer.registry().run_plugins(
        |_| true,
        |p| {
            let res = p.get_results();
            // dbg!(&res);
            if let Some(res) = res {
                match p.name() {
                    "BasicStats" => display_json_basicstats(res),
                    "CommunityID" => display_json_communityid(res),
                    "FlowsInfo" => display_json_flowsinfo(res),
                    "Rusticata" => display_json_rusticata(res),
                    "TlsStats" => display_json_tlsstats(res),
                    _ => display_generic(p, res),
                }
            } else {
                info!("{}: <no value>", p.name());
            }
        },
    )
}
