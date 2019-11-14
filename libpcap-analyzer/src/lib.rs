#![warn(clippy::all)]

#[macro_use]
extern crate log;

extern crate nom;
extern crate pcap_parser;
extern crate rand;

mod packet_info;

mod plugin;
#[macro_use] mod plugin_registry;
pub use plugin::*;
pub use plugin_registry::*;

pub mod plugins;
pub mod output;

mod analyzer;
mod threaded_analyzer;
pub use analyzer::*;
pub use threaded_analyzer::*;

mod ip6_defrag;
mod ip_defrag;
pub use ip6_defrag::*;

pub mod toeplitz;

#[derive(Debug, PartialEq)]
pub struct Error;
