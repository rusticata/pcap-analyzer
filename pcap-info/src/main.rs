#![warn(clippy::all)]

extern crate clap;
use clap::{crate_version, App, Arg};

use std::io;
use std::process;

mod info;

fn main() -> Result<(), io::Error> {
    let matches = App::new("Pcap information tool")
        .version(crate_version!())
        .author("Pierre Chifflier")
        .about("Display information about pcap files")
        .arg(
            Arg::with_name("check")
                .help("Check file")
                .short("c")
                .long("check"),
        )
        .arg(
            Arg::with_name("INPUT")
                .help("Input file name")
                .required(true)
                .index(1),
        )
        .get_matches();

    let input_filename = matches.value_of("INPUT").unwrap();
    let options = info::Options {
        check_file: matches.is_present("check"),
    };

    let rc = info::process_file(input_filename, &options)?;

    process::exit(rc);
}
