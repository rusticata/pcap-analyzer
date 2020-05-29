# PAL (Pcap Analysis Library)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE-MIT)
[![Apache License 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE-APACHE)
[![Build Status](https://travis-ci.org/rusticata/pcap-analyzer.svg?branch=master)](https://travis-ci.org/rusticata/pcap-analyzer)

PAL (Pcap Analysis Library) is a framework and a set of tools for Pcap file analysis, written in
Rust.

The main objectives are:

- provide a robust and efficient framework for analyzing pcap files
- provide tools to manipulate pcap files with a unifier abstraction
- reconstruct network data progressively for network layers (Layer 2, 3, etc.) correctly, dealing
  with common problems safely (fragmentation, missing data, encapsulation, etc.)
- allow developing plugins easily, focusing only on the interesting content
- allow plugins to interact with data at different network level (Layer 2, 3, application, etc.)
- use Rust features like thread safety (to exploit parallelism), memory safety, zero-copy, etc.

## Architecture

PAL is split into several components:

- `libpcap-tools`: a library providing support functions to manipulate pcap files
- `libpcap-analyzer`: the main library, providing network data reconstruction, dispatch, and plugin
  management. It also provides some plugins.
- `pcap-analyzer`: the main executable to run plugins on pcap files
- `pcap-rewrite`: a tool to rewrite a pcap file format and link type to another
- `test-analyzer`: a similar tool to `pcap-analyzer`, with more debug plugins and verbosity (for ex. for debugging
  plugins)
- `explugin-example`: an example of plugin developed in a separate crate

## Building pcap-analyzer

Use `cargo` to build pcap-analyzer:

```
# release mode
cargo build --release
# debug mode
cargo build
```

## Running pcap-analyzer

Just run `pcap-analyzer` with the names of pcap files as arguments:

```
pcap-analyzer file.pcap
pcap-analyzer -c config.toml file.pcap
```

The `-p` option can be used to restrict the list of plugins to load.

Concurrency level is set using the `-j` argument. Default is to 1 (no multithreading).
Threading is useful when having many flows, so if the input file is small, or if it does not contain
many flows, it is best to leave it to 1.
Use the value `0` to set the number of threads to the number of virtual CPUs.

Logging is done using the `log` cargo crate, and will to the log file defined
in configuration (`pcap-analyzer.log` by default).
Note that in release mode, only messages with a severity of `warn` or more are displayed.

To get more debug info, use the `test-analyzer` tool. It provides the exact same features, but will
be more verbose, and will output logs to stderr. The `PCAP_ANALYZER_LOG` environment variable can be
used to set the log level (and set concurrency to 1):

```
PCAP_ANALYZER_LOG=debug test-analyzer cargo run -p test-analyzer -- -j 1 -c conf/pcap-analyzer.conf file.pcap
```

## Plugins

Plugins are modules that are selected during build, and can be activated during execution. They are
embedded into the resulting library.

Not all plugins are built by default, those that are not yet stable or have many dependencies are
conditioned by a build feature. To build all plugins, activate the `all` feature, or select features
individually:

```
cargo build --all --all-features
```

You can also edit `libpcap-analyzer/Cargo.toml` to edit the `default` feature.

Note that due to limitations in the handling of features in workspaces by cargo, there seems to be
no easy way to enable one feature only when building the package.
Also note that, due to the same limitations, `cargo run` will not use the features.

*For the moment, the only "stable" method is to edit `libpcap-analyzer/Cargo.toml`.*

Plugins can declare functions that will be called either when receiving data for a network layer, or
for some events:

- layer 2: raw data (only if the pcap contains L2 data)
- layer 3: raw data + ethernet type
- layer 4: flow + l4 data + l4 payload (if l4 type is known/supported) + l3 data + ethertype + raw packet
- creating of a flow
- destruction of a flow

Flows are created for every L4 communication. Flows use five-tuples (IP source and destination, L4
protocol, source and destination ports). If the protocol does not contain ports, they are set to 0.

Note that functions can be called several times for a single packet. For example, in case of
encapsulated data (like IP in IP), functions will be called in order (first, the outer data, then
the inner data).

## Parallelism

To use parallelism, network packets have to be dispatched to worker threads. To ensure consistency,
all packets from a single connexion have to be sent to the same worker, or this would create
problems like handling packets out-of-order.

The current implementation dispatches packets starting from the layer 3 (layer 2 is handled by the
main thread). The dispatch function is based on a symmetric hash function on IP parameters.
After this dispatch, each worker thread handles its packets (in received order) and will reconstruct
the layer 2 (if present), calling plugins, then layer 3, call plugins, etc.

To ensure consistency, plugins are protected (using locks) before being called. The lock is done at
the plugin level, so only one handling function can be called at a time.

In particular:

- if a plugin registers for several layers, the functions are guaranteed to be called in parsing
  order (from outer data to inner data)
- even if several packets are concurrently handled by several workers, a single plugin will not be
  called concurrently. However, different plugins can execute concurrently.

## Notes

- pcap file parsing is completely reimplemented from scratch. This is the result of most existing
  libraries lacking features, and the will to provide a unified abstraction to manipulate the
  different subformats (pcap and pcapng, both in little and big-endian) and link types
- pcap file read is done in a circular buffer (which size can be controlled using configuration).
  Before each buffer refill, a synchronization is done to wait all workers to finish their current
  jobs
- the plugins are embedded into the main binary. Currently, there is no support for dynamic
  libraries, due to the lack of support/stability by Rust

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
