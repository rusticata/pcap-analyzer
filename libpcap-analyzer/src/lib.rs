#![warn(clippy::all)]
#![allow(clippy::upper_case_acronyms)]

#[macro_use]
extern crate log;

mod flow_map;
mod layers;
mod packet_info;
pub use flow_map::FlowMap;
pub use layers::*;
pub use packet_info::*;

mod plugin;
#[macro_use]
mod plugin_registry;
pub use plugin::*;
pub use plugin_registry::*;

pub mod output;
pub mod plugins;

mod analyzer;
mod threaded_analyzer;
pub use analyzer::*;
pub use threaded_analyzer::*;

mod erspan;
mod geneve;
mod ip_defrag;
mod mpls;
mod ppp;
mod pppoe;
mod tcp_reassembly;
mod vxlan;
pub use erspan::*;
pub use geneve::*;
pub use mpls::*;
pub use ppp::*;
pub use pppoe::*;
pub use vxlan::*;

pub mod toeplitz;

#[derive(Debug, PartialEq)]
pub struct Error;
