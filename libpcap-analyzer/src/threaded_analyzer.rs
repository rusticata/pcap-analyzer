use crate::analyzer::{handle_l3, run_plugins_v2_link, run_plugins_v2_physical, Analyzer};
use crate::layers::LinkLayerType;
use crate::plugin_registry::PluginRegistry;
use crossbeam_channel::{unbounded, Receiver, Sender};
use libpcap_tools::*;
use pcap_parser::data::PacketData;
use pnet_packet::ethernet::{EtherType, EtherTypes, EthernetPacket};
use std::cmp::min;
use std::panic::AssertUnwindSafe;
use std::sync::{Arc, Barrier};
use std::thread;

pub enum Job<'a> {
    Exit,
    PrintDebug,
    New(Packet<'a>, ParseContext, &'a [u8], EtherType),
    Wait,
}

pub struct Worker {
    pub(crate) _id: usize,
    pub(crate) handler: thread::JoinHandle<()>,
}

/// Pcap/Pcap-ng Multi-threaded analyzer
///
pub struct ThreadedAnalyzer<'a> {
    registry: Arc<PluginRegistry>,
    /// create a local analyzer, so L2 packets can be handled without
    /// dispatching them to threads
    analyzer: Analyzer,

    local_jobs: Vec<Sender<Job<'a>>>,
    workers: Vec<Worker>,
    barrier: Arc<Barrier>,
}

impl<'a> ThreadedAnalyzer<'a> {
    pub fn new(registry: PluginRegistry, config: &Config) -> Self {
        let n_workers = config
            .get_usize("num_threads")
            .unwrap_or_else(num_cpus::get);
        let barrier = Arc::new(Barrier::new(n_workers + 1));
        let registry = Arc::new(registry);
        let analyzer = Analyzer::new(registry.clone(), &config);

        let mut workers = Vec::new();
        let mut local_jobs = Vec::new();
        for idx in 0..n_workers {
            let n = format!("worker {}", idx);
            let a = Analyzer::new(registry.clone(), &config);
            let (sender, receiver) = unbounded();
            // NOTE: remove job queue from lifetime management, it must be made 'static
            // to be sent to threads
            let r: Receiver<Job<'static>> = unsafe { ::std::mem::transmute(receiver) };
            let barrier = barrier.clone();
            let builder = thread::Builder::new();
            let handler = builder
                .name(n)
                .spawn(move || {
                    worker(a, idx, r, barrier);
                })
                .unwrap();
            let worker = Worker { _id: idx, handler };
            workers.push(worker);
            local_jobs.push(sender);
        }

        ThreadedAnalyzer {
            registry,
            analyzer,
            local_jobs,
            workers,
            barrier,
        }
    }

    fn wait_for_empty_jobs(&self) {
        trace!("waiting for threads to finish processing");
        for job in self.local_jobs.iter() {
            job.send(Job::Wait).expect("Error while sending job");
        }
        self.barrier.wait();
    }

    fn dispatch(&mut self, packet: Packet<'static>, ctx: &ParseContext) -> Result<(), Error> {
        match packet.data {
            PacketData::L2(data) => self.handle_l2(packet, &ctx, data),
            PacketData::L3(ethertype, data) => {
                extern_dispatch_l3(&self.local_jobs, packet, &ctx, data, EtherType(ethertype))
            }
            PacketData::L4(_, _) => {
                warn!("Unsupported packet data layer 4");
                unimplemented!() // XXX
            }
            PacketData::Unsupported(_) => {
                warn!("Unsupported linktype");
                unimplemented!() // XXX
            }
        }
    }

    fn handle_l2(
        &mut self,
        packet: Packet<'static>,
        ctx: &ParseContext,
        data: &'static [u8],
    ) -> Result<(), Error> {
        trace!("handle_l2 (idx={})", ctx.pcap_index);
        // resize slice to remove padding
        let datalen = min(packet.caplen as usize, data.len());
        let data = &data[..datalen];

        // let start = ::std::time::Instant::now();
        run_plugins_v2_physical(&packet, ctx, data, &mut self.analyzer)?;
        // let elapsed = start.elapsed();
        // debug!("Time to run l2 plugins: {}.{}", elapsed.as_secs(), elapsed.as_millis());

        match EthernetPacket::new(data) {
            Some(eth) => {
                // debug!("    source: {}", eth.get_source());
                // debug!("    dest  : {}", eth.get_destination());
                match &data[..6] {
                    [0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc] => {
                        info!("Cisco CDP/VTP/UDLD - ignoring");
                        // the 'ethertype' field is used for length
                        return Ok(());
                    }
                    [0x01, 0x00, 0x0c, 0xcd, 0xcd, 0xd0] => {
                        info!("Cisco Multicast address - ignoring");
                        return Ok(());
                    }
                    _ => {
                        info!("Ethernet broadcast (unknown type) (idx={})", ctx.pcap_index);
                    }
                }
                let ethertype = eth.get_ethertype();
                let payload = &data[14..];
                trace!("    ethertype: 0x{:x}", ethertype.0);
                run_plugins_v2_link(
                    &packet,
                    ctx,
                    LinkLayerType::Ethernet,
                    payload,
                    &mut self.analyzer,
                )?;
                extern_dispatch_l3(&self.local_jobs, packet, &ctx, payload, ethertype)
            }
            None => {
                // packet too small to be ethernet
                Ok(())
            }
        }
    }
}

impl<'a> PcapAnalyzer for ThreadedAnalyzer<'a> {
    fn init(&mut self) -> Result<(), Error> {
        self.registry.run_plugins(|_| true, |p| p.pre_process());

        Ok(())
    }

    fn handle_packet(&mut self, packet: &Packet, ctx: &ParseContext) -> Result<(), Error> {
        // NOTE: remove packet from lifetime management, it must be made 'static
        // to be sent to threads
        let packet: Packet<'static> = unsafe { ::std::mem::transmute(packet.clone()) };
        self.dispatch(packet, &ctx)?;
        Ok(())
    }

    fn teardown(&mut self) {
        debug!("main: exit");
        self.wait_for_empty_jobs();
        for job in self.local_jobs.iter() {
            // XXX expire flows?
            job.send(Job::PrintDebug).expect("Error while sending job");
            job.send(Job::Exit).expect("Error while sending job");
        }
        while let Some(w) = self.workers.pop() {
            w.handler.join().expect("panic occurred in a thread");
        }
        self.local_jobs.clear();
        debug!("main: all workers ended");

        self.registry.run_plugins(|_| true, |p| p.post_process());
    }

    fn before_refill(&mut self) {
        self.wait_for_empty_jobs();
        trace!("threads synchronized, refill");
    }
}

pub(crate) fn extern_dispatch_l3<'a>(
    jobs: &[Sender<Job<'a>>],
    packet: Packet<'a>,
    ctx: &ParseContext,
    data: &'a [u8],
    ethertype: EtherType,
) -> Result<(), Error> {
    let n_workers = jobs.len();
    let i = fan_out(data, ethertype, n_workers);
    debug_assert!(i < n_workers);
    jobs[i]
        .send(Job::New(packet, ctx.clone(), data, ethertype))
        .or(Err(Error::Generic("Error while sending job")))
}

fn fan_out(data: &[u8], ethertype: EtherType, n_workers: usize) -> usize {
    match ethertype {
        EtherTypes::Ipv4 => {
            if data.len() >= 20 {
                // let src = &data[12..15];
                // let dst = &data[16..19];
                // let proto = data[9];
                // (src[0] ^ dst[0] ^ proto) as usize % n_workers
                let mut buf: [u8; 20] = [0; 20];
                let sz = 4;
                buf[0] = data[12] ^ data[16];
                buf[1] = data[13] ^ data[17];
                buf[2] = data[14] ^ data[18];
                buf[3] = data[15] ^ data[19];
                // we may append source and destination ports
                // XXX breaks fragmentation
                // if data[9] == crate::plugin::TRANSPORT_TCP || data[9] == crate::plugin::TRANSPORT_UDP {
                //     if data.len() >= 24 {
                //         // source port, in network-order
                //         buf[8] = data[20];
                //         buf[9] = data[21];
                //         // destination port, in network-order
                //         buf[10] = data[22];
                //         buf[11] = data[23];
                //         sz = 12;
                //     }
                // }
                // let hash = crate::toeplitz::toeplitz_hash(crate::toeplitz::KEY, &buf[..sz]);
                let hash = fasthash::metro::hash64(&buf[..sz]);
                // debug!("{:?} -- hash --> 0x{:x}", buf, hash);
                // ((hash >> 24) ^ (hash & 0xff)) as usize % n_workers
                hash as usize % n_workers
            } else {
                n_workers - 1
            }
        }
        EtherTypes::Ipv6 => {
            if data.len() >= 40 {
                let mut buf: [u8; 40] = [0; 40];
                // let sz = 32;
                // source IP + destination IP, in network-order
                // buf[0..32].copy_from_slice(&data[8..40]);
                let sz = 16;
                for i in 0..16 {
                    buf[i] = data[8 + i] ^ data[24 + i];
                }
                // we may append source and destination ports
                // XXX breaks fragmentation
                // if data[6] == crate::plugin::TRANSPORT_TCP || data[6] == crate::plugin::TRANSPORT_UDP {
                //     if data.len() >= 44 {
                //         // source port, in network-order
                //         buf[33] = data[40];
                //         buf[34] = data[41];
                //         // destination port, in network-order
                //         buf[35] = data[42];
                //         buf[36] = data[43];
                //         sz += 4;
                //     }
                // }
                // let hash = crate::toeplitz::toeplitz_hash(crate::toeplitz::KEY, &buf[..sz]);
                let hash = fasthash::metro::hash64(&buf[..sz]);
                // debug!("{:?} -- hash --> 0x{:x}", buf, hash);
                // ((hash >> 24) ^ (hash & 0xff)) as usize % n_workers
                hash as usize % n_workers
            } else {
                n_workers - 1
            }
        }
        _ => 0,
    }
}

fn worker(mut a: Analyzer, idx: usize, r: Receiver<Job>, barrier: Arc<Barrier>) {
    debug!("worker thread {} starting", idx);
    let mut pcap_index = 0;
    let res = ::std::panic::catch_unwind(AssertUnwindSafe(|| loop {
        if let Ok(msg) = r.recv() {
            match msg {
                Job::Exit => break,
                Job::PrintDebug => {
                    {
                        debug!("thread {}: hash table size: {}", idx, a.flows.len());
                    };
                }
                Job::New(packet, ctx, data, ethertype) => {
                    pcap_index = ctx.pcap_index;
                    trace!("thread {}: got a job", idx);
                    let h3_res = handle_l3(&packet, &ctx, data, ethertype, &mut a);
                    if h3_res.is_err() {
                        warn!("thread {}: handle_l3 failed", idx);
                    }
                }
                Job::Wait => {
                    trace!("Thread {}: waiting at barrier", idx);
                    barrier.wait();
                }
            }
        }
    }));
    if let Err(panic) = res {
        warn!("thread {} panicked (idx={})\n{:?}", idx, pcap_index, panic);
        // match panic.downcast::<String>() {
        //     Ok(panic_msg) => {
        //         println!("panic happened: {}", panic_msg);
        //     }
        //     Err(_) => {
        //         println!("panic happened: unknown type.");
        //     }
        // }
        // ::std::panic::resume_unwind(err);
        ::std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::Job;
    use libpcap_tools::Flow;
    use libpcap_tools::{Packet, ParseContext};
    use std::mem;
    #[test]
    fn size_of_structs() {
        println!("sizeof ParseContext: {}", mem::size_of::<ParseContext>());
        println!("sizeof Packet: {}", mem::size_of::<Packet>());
        println!("sizeof Flow: {}", mem::size_of::<Flow>());
        println!("sizeof Job: {}", mem::size_of::<Job>());
    }
}
