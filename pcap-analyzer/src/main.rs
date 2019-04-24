extern crate clap;
use clap::{Arg,App,crate_version};

extern crate env_logger;

use std::fs::File;
use std::io;
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
        .arg(Arg::with_name("plugins")
             .help("Plugins to load (default: all)")
             .short("p")
             .long("plugins")
             .takes_value(true))
        .arg(Arg::with_name("INPUT")
             .help("Input file name")
             .required(true)
             .index(1))
        .get_matches();

   env_logger::init();

   eprintln!("Hello, world!");

   let builder = plugins::plugins_factory();
   let mut plugins = plugins::plugins(&builder);

   if let Some(plugin_names) = matches.value_of("plugins") {
       eprintln!("plugins: {}", plugin_names);
       let names : Vec<_> = plugin_names.split(",").collect();
       plugins.list.retain(|k, _| {
           names.iter().any(|&x| x == k.as_str())
       });
   }

   eprintln!("  Plugins loaded: {}", plugins.list.len());
   let mut analyzer = Analyzer::new(&mut plugins);

   let input_filename = matches.value_of("INPUT").unwrap();
   // let verbose = matches.is_present("verbose");

   let mut input_reader =
       if input_filename == "-" {
           Box::new(io::stdin()) as Box<io::Read>
       } else {
           let path = Path::new(&input_filename);
           let display = path.display();
           let file = match File::open(path) {
               // The `description` method of `io::Error` returns a string that
               // describes the error
               Err(why) => panic!("couldn't open {}: {}", display,
                                  why.to_string()),
               Ok(file) => file,
           };
           Box::new(file) as Box<io::Read>
       };

   let _ = analyzer.run(&mut input_reader);
}
