#[macro_use]
extern crate log;

extern crate circular;

extern crate pcap_parser;

extern crate nom;

// #[macro_use] extern crate lazy_static;

extern crate rand;

mod pcapng_extra;

mod duration;
mod five_tuple;
mod flow;
mod packet_data;

mod plugin;
use plugin::*;

pub mod plugins;

mod analyzer;
pub use analyzer::*;


#[derive(Debug,PartialEq)]
pub struct Error;

