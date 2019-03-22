extern crate clap;
use clap::{Arg,App,crate_version};

extern crate env_logger;

use std::fs::File;
use std::path::Path;

use libpcap_analyzer::{plugins,Analyzer};

fn main() {
   let matches = App::new("Pcap analyzer")
        .version(crate_version!())
        .author("Pierre Chifflier")
        .about("Tool for Pcap file analyzis")
        .arg(Arg::with_name("verbose")
             .help("Be verbose")
             .short("v")
             .long("verbose"))
        .arg(Arg::with_name("INPUT")
             .help("Input file name")
             .required(true)
             .index(1))
        .get_matches();

   env_logger::init();

   eprintln!("Hello, world!");

   let builder = plugins::plugins_factory();
   let mut all_plugins = plugins::plugins(&builder);
   eprintln!("  Plugins loaded: {}", all_plugins.list.len());
   let mut analyzer = Analyzer::new(&mut all_plugins);

   let input_filename = matches.value_of("INPUT").unwrap();
   // let verbose = matches.is_present("verbose");

   let path = Path::new(&input_filename);
   let display = path.display();
   let mut file = match File::open(path) {
       // The `description` method of `io::Error` returns a string that
       // describes the error
       Err(why) => panic!("couldn't open {}: {}", display,
                          why.to_string()),
       Ok(file) => file,
   };

   let _ = analyzer.run(&mut file);
}
