use crate::analyzer::{handle_l3, TAD};
use crate::plugin_registry::PluginRegistry;
use crossbeam_channel::{unbounded, Receiver, Sender};
use libpcap_tools::*;
use pcap_parser::data::PacketData;
use pnet_base::MacAddr;
use pnet_packet::ethernet::{EtherType, EtherTypes, EthernetPacket};
use std::cmp::min;
use std::sync::{Arc, Barrier};
use std::thread;

pub enum Job<'a> {
    Exit,
    PrintDebug,
    New(&'a Packet<'a>, &'a ParseContext, &'a [u8], EtherType),
    Wait,
}

pub struct Worker {
    pub(crate) _id: usize,
    pub(crate) handler: thread::JoinHandle<()>,
}

pub struct ThreadedAnalyzer<'a> {
    registry: PluginRegistry,
    n_workers: usize,

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
        ThreadedAnalyzer {
            registry,
            n_workers,
            local_jobs: Vec::new(),
            workers: Vec::new(),
            barrier,
        }
    }

    fn wait_for_empty_jobs(&self) {
        trace!("waiting for threads to finish processing");
        for job in self.local_jobs.iter() {
            job.send(Job::Wait);
        }
        self.barrier.wait();
    }

    fn dispatch(&self, packet: &'static Packet, ctx: &'a ParseContext) -> Result<(), Error> {
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
        &self,
        packet: &'static Packet,
        ctx: &'a ParseContext,
        data: &'static [u8],
    ) -> Result<(), Error> {
        trace!("handle_l2 (idx={})", ctx.pcap_index);
        // resize slice to remove padding
        let datalen = min(packet.caplen as usize, data.len());
        let data = &data[..datalen];

        // let start = ::std::time::Instant::now();
        self.registry.run_plugins_l2(&packet, &data);
        // let elapsed = start.elapsed();
        // debug!("Time to run l2 plugins: {}.{}", elapsed.as_secs(), elapsed.as_millis());

        match EthernetPacket::new(data) {
            Some(eth) => {
                // debug!("    source: {}", eth.get_source());
                // debug!("    dest  : {}", eth.get_destination());
                let dest = eth.get_destination();
                if dest.0 == 1 {
                    // Multicast
                    if eth.get_destination() == MacAddr(0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc) {
                        info!("Cisco CDP/VTP/UDLD");
                        return Ok(());
                    } else if eth.get_destination() == MacAddr(0x01, 0x00, 0x0c, 0xcd, 0xcd, 0xd0) {
                        info!("Cisco Multicast address");
                        return Ok(());
                    } else {
                        info!("Ethernet broadcast (unknown type) (idx={})", ctx.pcap_index);
                    }
                }
                trace!("    ethertype: 0x{:x}", eth.get_ethertype().0);
                // self.handle_l3(&packet, &ctx, eth.payload(), eth.get_ethertype())
                let payload = &data[14..];
                extern_dispatch_l3(&self.local_jobs, packet, &ctx, payload, eth.get_ethertype())
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

        self.local_jobs.reserve(self.n_workers);

        let workers: Vec<_> = (0..self.n_workers)
            .map(|i| {
                let (sender, receiver) = unbounded();
                self.local_jobs.push(sender);
                // NOTE: remove job queue from lifetime management, it must be made 'static
                // to be sent to threads
                let r : Receiver<Job<'static>> =
                    unsafe { ::std::mem::transmute(receiver) };
                let arc_registry = self.registry.clone();
                let barrier = self.barrier.clone();
                let n = format!("worker {}", i);
                let builder = thread::Builder::new();
                let handler = builder
                    .name(n)
                    .spawn(move || {
                        debug!("worker thread {} starting", i);
                        loop {
                            if let Ok(msg) = r.recv() {
                                match msg {
                                    Job::Exit => break,
                                    Job::PrintDebug => {
                                        TAD.with(|f| {
                                            debug!(
                                                "thread {}: hash table size: {}",
                                                i,
                                                f.borrow().flows.len()
                                            );
                                        });
                                    }
                                    Job::New(packet, ctx, data, ethertype) => {
                                        trace!("thread {}: got a job", i);
                                        // extern_l2(&s, &registry);
                                        let res = ::std::panic::catch_unwind(|| {
                                            let h3_res = handle_l3(
                                                &packet,
                                                &ctx,
                                                data,
                                                ethertype,
                                                &arc_registry,
                                            );
                                            if h3_res.is_err() {
                                                warn!("thread {}: handle_l3 failed", i);
                                            }
                                        });
                                        if let Err(panic) = res {
                                            warn!(
                                                "thread {} panicked (idx={})\n{:?}",
                                                i, ctx.pcap_index, panic
                                            );
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
                                    Job::Wait => {
                                        trace!("Thread {}: waiting at barrier", i);
                                        barrier.wait();
                                    }
                                }
                            }
                        }
                    })
                    .unwrap();
                Worker { _id: i, handler }
                // (q, exit.clone(), handler)
            })
            .collect();

        self.workers = workers;
        Ok(())
    }

    fn handle_packet(&mut self, packet: &Packet, ctx: &ParseContext) -> Result<(), Error> {
        // NOTE: remove packet from lifetime management, it must be made 'static
        // to be sent to threads
        // "by doing this, I solely declare that I am responsible of the lifetime
        // and safety of packet"
        let packet: &'static Packet = unsafe { ::std::mem::transmute(packet) };
        let ctx: &'static ParseContext = unsafe { ::std::mem::transmute(ctx) };
        self.dispatch(packet, ctx)?;
        Ok(())
    }

    fn teardown(&mut self) {
        debug!("main: exit");
        self.wait_for_empty_jobs();
        for job in self.local_jobs.iter() {
            // XXX expire flows?
            job.send(Job::PrintDebug);
            job.send(Job::Exit);
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
    packet: &'a Packet,
    ctx: &'a ParseContext,
    data: &'a [u8],
    ethertype: EtherType,
) -> Result<(), Error> {
    let n_workers = jobs.len();
    let i = fan_out(data, ethertype, n_workers);
    debug_assert!(i < n_workers);
    jobs[i].send(Job::New(packet, ctx, data, ethertype));
    Ok(())
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
                    buf[i] = data[8+i] ^ data[24+i];
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

#[cfg(test)]
mod tests {
    use super::Job;
    use libpcap_tools::{Packet, ParseContext};
    use std::mem;
    #[test]
    fn size_of_structs() {
        println!("sizeof ParseContext: {}", mem::size_of::<ParseContext>());
        println!("sizeof Packet: {}", mem::size_of::<Packet>());
        println!("sizeof Job: {}", mem::size_of::<Job>());
    }
}
