use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration as StdDuration;

use libpcap_tools::pcap_parser::{self, LegacyPcapBlock, Linktype};
use libpcap_tools::{
    Config, Duration, Error, Packet, ParseBlockContext, ParseContext, PcapAnalyzer, PcapBlockOwned,
};
use pcap::{Active, Capture, Precision};
use tracing::{debug, error, trace};

pub struct PcapLiveDataEngine<A: PcapAnalyzer> {
    analyzer: A,

    cap: Capture<Active>,
    link_type: Linktype,
    precision: Precision,
    sleep_interval: u64,
}

impl<A: PcapAnalyzer> PcapLiveDataEngine<A> {
    pub fn new(interface_name: &str, analyzer: A, config: &Config) -> Result<Self, pcap::Error> {
        let interfaces = match pcap::Device::list() {
            Ok(interfaces) => interfaces,
            Err(e) => {
                error!("Could not list network interfaces: {e:?}\nAre you running with root privileges (CAP_NET_RAW)?");
                std::process::exit(1);
            }
        };

        let immediate = config.get_bool("live.immediate").unwrap_or(true);
        let precision = match config.get("live.precision") {
            None | Some("micro") => Precision::Micro,
            Some("nano") => Precision::Nano,
            _ => return Err(pcap::Error::InvalidInputString),
        };
        let promisc = config.get_bool("live.promisc").unwrap_or(false);
        let sleep_interval = config.get_usize("live.sleep").unwrap_or(500) as u64;

        if let Some(dev) = interfaces
            .into_iter()
            .find(|iface| iface.name == interface_name)
        {
            let cap = Capture::from_device(dev)?
                .immediate_mode(immediate)
                .promisc(promisc)
                .precision(precision)
                // .timeout(10)
                ;

            let cap = cap.open()?.setnonblock()?;

            // convert from `pcap` crate format to `libpcap_tools` format
            let link_type = Linktype(cap.get_datalink().0);

            let engine = PcapLiveDataEngine {
                analyzer,
                cap,
                link_type,
                precision,
                sleep_interval,
            };
            Ok(engine)
        } else {
            Err(pcap::Error::InvalidInputString)
        }
    }

    pub fn data_analyzer(&self) -> &A {
        &self.analyzer
    }

    pub fn data_analyzer_mut(&mut self) -> &mut A {
        &mut self.analyzer
    }

    pub fn run(&mut self, stop: Arc<AtomicBool>) -> Result<(), Error> {
        debug!("Live mode: waiting for packets");
        let cap = &mut self.cap;
        let mut block_ctx = ParseBlockContext::default();
        let mut ctx = ParseContext::default();
        while stop.load(Ordering::SeqCst) {
            match cap.next_packet() {
                Ok(packet) => {
                    debug!("Live: receiving packet, handling block");
                    block_ctx.block_index += 1;
                    let header = &packet.header;
                    let ts_sec = header.ts.tv_sec as u32;
                    let ts_usec = header.ts.tv_usec as u32;
                    let block = LegacyPcapBlock {
                        ts_sec,
                        ts_usec,
                        caplen: header.caplen,
                        origlen: header.len,
                        data: packet.data,
                    };
                    let block_owned = PcapBlockOwned::Legacy(block);
                    self.analyzer.handle_block(&block_owned, &block_ctx)?;

                    // packet handling
                    ctx.pcap_index += 1;
                    let blen = header.caplen as usize;
                    let data = pcap_parser::data::get_packetdata(packet.data, self.link_type, blen)
                        .ok_or(Error::Generic("Parsing PacketData failed (Legacy Packet)"))?;
                    debug!("Live: receiving packet, handling packet {}", ctx.pcap_index);
                    let ts = if self.precision == Precision::Micro {
                        Duration::new(ts_sec, ts_usec)
                    } else {
                        Duration::new(ts_sec, ts_usec / 1000)
                    };
                    let packet = Packet {
                        interface: 0,
                        ts,
                        link_type: self.link_type,
                        data,
                        origlen: header.len,
                        caplen: header.caplen,
                        pcap_index: ctx.pcap_index,
                    };
                    trace!("**************************************************************");
                    // build ts
                    if ctx.pcap_index == 1 {
                        ctx.first_packet_ts = ts;
                    }
                    trace!("    time  : {} / {:06}", packet.ts.secs, packet.ts.micros);
                    ctx.rel_ts = ts - ctx.first_packet_ts; // an underflow is weird but not critical
                    trace!(
                        "    reltime  : {}.{:06}",
                        ctx.rel_ts.secs,
                        ctx.rel_ts.micros
                    );
                    self.analyzer.handle_packet(&packet, &ctx)?;
                }
                Err(pcap::Error::TimeoutExpired) => {
                    thread::sleep(StdDuration::from_micros(self.sleep_interval));
                    continue;
                }
                Err(e) => {
                    debug!("Live mode: getting next packet failed: {e:?}");
                    break;
                }
            }
        }

        Ok(())
    }
}
