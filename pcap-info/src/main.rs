#![warn(clippy::all)]

use pcap_info::*;

extern crate clap;
use clap::{crate_version, App, Arg};

use std::io;
use std::process;

fn main() -> Result<(), io::Error> {
    let matches = App::new("Pcap information tool")
        .version(crate_version!())
        .author("Pierre Chifflier")
        .about("Display information about pcap files")
        .arg(
            Arg::with_name("no-check")
                .help("Do not check file")
                .short('n')
                .long("no-check"),
        )
        .arg(
            Arg::with_name("INPUT")
                .help("Input file name")
                .required(true)
                .index(1),
        )
        .get_matches();

    let input_filename = matches.value_of("INPUT").unwrap();
    let options = Options {
        check_file: !matches.is_present("no-check"),
    };

    let rc = pcap_info(input_filename, &options)?;

    process::exit(rc);
}
