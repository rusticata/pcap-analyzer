use libpcap_tools::{Duration, Flow, FlowID};
use pnet_macros_support::packet::Packet as PnetPacket;
use pnet_packet::tcp::{TcpFlags, TcpPacket};
use std::cmp::Ordering;
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::net::IpAddr;
use std::num::Wrapping;

#[derive(Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub enum TcpStatus {
    Closed = 0,
    Listen,
    SynSent,
    SynRcv,
    Established,
    Closing,
    CloseWait,
    FinWait1,
    FinWait2,
    LastAck,
    TimeWait,
}

impl Default for TcpStatus {
    fn default() -> Self {
        TcpStatus::Closed
    }
}

#[derive(Debug)]
pub struct TcpSegment {
    pub rel_seq: Wrapping<u32>,
    pub rel_ack: Wrapping<u32>,
    pub flags: u16,
    pub data: Vec<u8>,
    pub pcap_index: usize,
}

impl TcpSegment {
    /// Return the offset of the overlapping area if `self` (as left) overlaps on `right`
    pub fn overlap_offset(&self, right: &TcpSegment) -> Option<usize> {
        let next_seq = self.rel_seq + Wrapping(self.data.len() as u32);
        if next_seq > right.rel_seq {
            let overlap_offset = (right.rel_seq - self.rel_seq).0 as usize;
            Some(overlap_offset)
        } else {
            None
        }
    }

    /// Splits the segment into two at the given offset.
    ///
    /// # Panics
    ///
    /// Panics if `offset > self.data.len()`
    pub fn split_off(&mut self, offset: usize) -> TcpSegment {
        debug_assert!(offset < self.data.len());
        let remaining = self.data.split_off(offset);
        let rel_seq = self.rel_seq + Wrapping(offset as u32);
        TcpSegment {
            data: remaining,
            rel_seq,
            ..*self
        }
    }
}

pub struct TcpPeer {
    /// Initial Seq number (absolute)
    isn: Wrapping<u32>,
    /// Initial Ack number (absolute)
    ian: Wrapping<u32>,
    /// Next Seq number
    next_rel_seq: Wrapping<u32>,
    /// Last acknowledged number
    last_rel_ack: Wrapping<u32>,
    /// Connection state
    status: TcpStatus,
    /// The current list of segments (ordered by rel_seq)
    segments: VecDeque<TcpSegment>,
    /// DEBUG: host address
    addr: IpAddr,
    /// DEBUG: port
    port: u16,
}

impl TcpPeer {
    fn insert_sorted(&mut self, s: TcpSegment) {
        // find index
        let idx = self.segments.iter().enumerate().find_map(|(n, item)| {
            if s.rel_seq < item.rel_seq {
                Some(n)
            } else {
                None
            }
        });
        match idx {
            Some(idx) => self.segments.insert(idx, s),
            None => self.segments.push_back(s),
        }
    }
}

pub struct TcpStream {
    pub client: TcpPeer,
    pub server: TcpPeer,
    pub status: TcpStatus,
    // XXX timestamp of last seen packet
    pub last_seen_ts: Duration,
}

pub struct TcpStreamReassembly {
    pub m: HashMap<FlowID, TcpStream>,

    pub timeout: Duration,
}

impl Default for TcpStreamReassembly {
    fn default() -> Self {
        TcpStreamReassembly {
            m: HashMap::new(),
            timeout: Duration::new(120, 0),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum TcpStreamError {
    Anomaly,
    /// Connection is OK, but sides are inverted
    Inverted,
    /// Packet received but connection has expired
    Expired,
    HandshakeFailed,
}

impl TcpPeer {
    pub fn new(addr: &IpAddr, port: u16) -> Self {
        TcpPeer {
            isn: Wrapping(0),
            ian: Wrapping(0),
            next_rel_seq: Wrapping(0),
            last_rel_ack: Wrapping(0),
            status: TcpStatus::Closed,
            segments: VecDeque::new(),
            addr: *addr,
            port,
        }
    }
}

impl TcpStream {
    pub fn new(flow: &Flow) -> Self {
        TcpStream {
            client: TcpPeer::new(&flow.five_tuple.src, flow.five_tuple.src_port),
            server: TcpPeer::new(&flow.five_tuple.dst, flow.five_tuple.dst_port),
            status: TcpStatus::Closed,
            last_seen_ts: flow.last_seen,
        }
    }

    pub fn handle_new_connection<'a>(
        &mut self,
        tcp: &'a TcpPacket,
        to_server: bool,
        pcap_index: usize,
    ) -> Result<Option<Vec<TcpSegment>>, TcpStreamError> {
        let seq = Wrapping(tcp.get_sequence());
        let ack = Wrapping(tcp.get_acknowledgement());
        let tcp_flags = tcp.get_flags();

        let (mut src, mut dst) = if to_server {
            (&mut self.client, &mut self.server)
        } else {
            (&mut self.server, &mut self.client)
        };

        match src.status {
            // Client -- SYN --> Server
            TcpStatus::Closed => {
                if tcp_flags & TcpFlags::RST != 0 {
                    // TODO check if destination.segments must be removed
                    // client sent a RST, this is expected
                    return Ok(None);
                }
                if tcp_flags & TcpFlags::SYN == 0 {
                    // not a SYN - usually happens at start of pcap if missed SYN
                    warn!("First packet of a TCP stream is not a SYN");
                    // test is ACK + data, and set established if possible
                    if tcp_flags & TcpFlags::ACK != 0 {
                        trace!("Trying to catch connection on the fly");
                        src.isn = seq;
                        src.ian = ack;
                        src.next_rel_seq = Wrapping(0);
                        src.status = TcpStatus::Established;
                        dst.isn = ack;
                        dst.ian = seq;
                        dst.status = TcpStatus::Established;
                        dst.last_rel_ack = Wrapping(0);
                        self.status = TcpStatus::Established;
                        // queue segment (even if FIN, to get correct seq numbers)
                        let segment = TcpSegment {
                            rel_seq: Wrapping(0),
                            rel_ack: Wrapping(0),
                            flags: tcp_flags,
                            data: tcp.payload().to_vec(), // XXX data cloned here
                            pcap_index,
                        };
                        queue_segment(&mut src, segment);

                        return Ok(None);
                    }
                    return Err(TcpStreamError::Anomaly);
                }
                if tcp_flags & TcpFlags::ACK != 0 {
                    warn!("First packet is SYN+ACK - missed SYN?");
                    dst.isn = ack - Wrapping(1);
                    dst.status = TcpStatus::SynSent;
                    dst.next_rel_seq = Wrapping(1);
                    src.isn = seq;
                    src.ian = ack;
                    src.last_rel_ack = Wrapping(1);
                    src.next_rel_seq = Wrapping(1);
                    src.status = TcpStatus::Listen;
                    // swap sides and tell analyzer to do the same for flow
                    std::mem::swap(&mut self.client, &mut self.server);
                    return Err(TcpStreamError::Inverted);
                }
                src.isn = seq;
                src.next_rel_seq = Wrapping(1);
                dst.ian = seq;
                self.status = TcpStatus::SynSent;
                src.status = TcpStatus::SynSent;
                dst.status = TcpStatus::Listen;
                // do we have data ?
                if !tcp.payload().is_empty() {
                    warn!("Data in handshake SYN");
                    // conn.next_rel_seq += Wrapping(tcp.payload().len() as u32);
                    let segment = TcpSegment {
                        rel_seq: seq - src.isn,
                        rel_ack: ack - dst.isn,
                        flags: tcp_flags,
                        data: tcp.payload().to_vec(), // XXX data cloned here
                        pcap_index,
                    };
                    queue_segment(&mut src, segment);
                }
            }
            // Server -- SYN+ACK --> Client
            TcpStatus::Listen => {
                if tcp_flags != (TcpFlags::SYN | TcpFlags::ACK) {
                    // XXX ?
                }
                // if we had data in SYN, add its length
                let next_rel_seq = if dst.segments.is_empty() {
                    Wrapping(1)
                } else {
                    Wrapping(1) + Wrapping(dst.segments[0].data.len() as u32)
                };
                if ack != dst.isn + next_rel_seq {
                    warn!("NEW/SYN-ACK: ack number is wrong");
                    return Err(TcpStreamError::HandshakeFailed);
                }
                src.isn = seq;
                src.next_rel_seq = Wrapping(1);
                dst.ian = seq;
                dst.last_rel_ack = Wrapping(1);

                src.status = TcpStatus::SynRcv;
                self.status = TcpStatus::SynRcv;

                // do not push data if we had some in SYN, it will be done after handshake succeeds
            }
            // Client -- ACK --> Server
            TcpStatus::SynSent => {
                if tcp_flags & TcpFlags::ACK == 0 {
                    if tcp_flags == TcpFlags::SYN {
                        // can be a SYN resend
                        if seq == src.isn && ack.0 == 0 {
                            trace!("SYN resend - ignoring");
                            return Ok(None);
                        }
                        // can be a disordered handshake (receive S after SA)
                        if seq + Wrapping(1) == dst.ian {
                            trace!("Likely received SA before S - ignoring");
                            return Ok(None);
                        }
                    }
                    warn!("Not an ACK");
                }
                // TODO check seq, ack
                if ack != dst.isn + Wrapping(1) {
                    warn!("NEW/ACK: ack number is wrong");
                    return Err(TcpStreamError::HandshakeFailed);
                }
                src.status = TcpStatus::Established;
                dst.status = TcpStatus::Established;
                dst.last_rel_ack = Wrapping(1);
                self.status = TcpStatus::Established;
                // do we have data ?
                if !tcp.payload().is_empty() {
                    // warn!("Data in handshake ACK");
                    let segment = TcpSegment {
                        rel_seq: seq - src.isn,
                        rel_ack: ack - dst.isn,
                        flags: tcp_flags,
                        data: tcp.payload().to_vec(), // XXX data cloned here
                        pcap_index,
                    };
                    queue_segment(&mut src, segment);
                }
            }
            TcpStatus::SynRcv => {
                // we received something while in SYN_RCV state - we should only have sent ACK
                // this could be a SYN+ACK retransmit
                if tcp_flags == TcpFlags::SYN | TcpFlags::ACK {
                    // XXX compare SEQ numbers?
                    // ignore
                    return Ok(None);
                }
                warn!(
                    "Received unexpected data in SYN_RCV state idx={}",
                    pcap_index
                );
            }
            _ => unreachable!(),
        }
        Ok(None)
    }

    pub fn handle_established_connection<'a>(
        &mut self,
        tcp: &'a TcpPacket,
        to_server: bool,
        pcap_index: usize,
    ) -> Result<Option<Vec<TcpSegment>>, TcpStreamError> {
        let (mut origin, destination) = if to_server {
            (&mut self.client, &mut self.server)
        } else {
            (&mut self.server, &mut self.client)
        };

        let rel_seq = Wrapping(tcp.get_sequence()) - origin.isn;
        let rel_ack = Wrapping(tcp.get_acknowledgement()) - destination.isn;
        let tcp_flags = tcp.get_flags();

        trace!("EST: payload len={}", tcp.payload().len());
        trace!(
            "    Tcp rel seq {} ack {} next seq {}",
            rel_seq,
            rel_ack,
            origin.next_rel_seq
        );

        if tcp_flags & TcpFlags::ACK == 0 && tcp.get_acknowledgement() != 0 {
            warn!(
                "EST/ packet without ACK (broken TCP implementation or attack) idx={}",
                pcap_index
            );
            // ignore segment
            return Ok(None);
        }

        let segment = TcpSegment {
            rel_seq,
            rel_ack,
            flags: tcp_flags,
            data: tcp.payload().to_vec(), // XXX data cloned here
            pcap_index,
        };
        queue_segment(&mut origin, segment);

        // trace!("Destination: {:?}", destination); // TODO to remove

        // if there is a ACK, check & send segments on the *other* side
        let ret = if tcp_flags & TcpFlags::ACK != 0 {
            send_peer_segments(destination, rel_ack)
        } else {
            None
        };

        trace!(
            "    PEER EST rel next seq {} last_ack {}",
            destination.next_rel_seq,
            destination.last_rel_ack,
        );

        Ok(ret)
    }

    fn handle_closing_connection(
        &mut self,
        tcp: &TcpPacket,
        to_server: bool,
        pcap_index: usize,
    ) -> Result<Option<Vec<TcpSegment>>, TcpStreamError> {
        let (mut origin, destination) = if to_server {
            (&mut self.client, &mut self.server)
        } else {
            (&mut self.server, &mut self.client)
        };

        let tcp_flags = tcp.get_flags();
        let rel_seq = Wrapping(tcp.get_sequence()) - origin.isn;
        let rel_ack = Wrapping(tcp.get_acknowledgement()) - destination.isn;
        let has_ack = tcp_flags & TcpFlags::ACK != 0;
        let has_fin = tcp_flags & TcpFlags::FIN != 0;

        let ret = if has_ack {
            trace!("ACKing segments up to {}", rel_ack);
            send_peer_segments(destination, rel_ack)
        } else {
            if tcp.get_acknowledgement() != 0 {
                warn!(
                    "EST/ packet without ACK (broken TCP implementation or attack) idx={}",
                    pcap_index
                );
                // ignore segment
                return Ok(None);
            }
            None
        };
        if tcp_flags & TcpFlags::RST != 0 {
            // if we get a RST, check the sequence number and remove matching segments
            // trace!("RST received. rel_seq: {}", rel_seq);
            // trace!(
            //     "{} remaining (undelivered) segments DESTINATION",
            //     destination.segments.len()
            // );
            // for (n, s) in destination.segments.iter().enumerate() {
            //     trace!("  s[{}]: rel_seq={} plen={}", n, s.rel_seq, s.data.len());
            // }
            // remove queued segments up to rel_seq
            destination.segments.retain(|s| s.rel_ack != rel_seq);
            trace!(
                "RST: {} remaining (undelivered) segments DESTINATION after removal",
                destination.segments.len()
            );
            origin.status = TcpStatus::Closed; // XXX except if ACK ?
            return Ok(ret);
        }

        // queue segment (even if FIN, to get correct seq numbers)
        let rel_seq = Wrapping(tcp.get_sequence()) - origin.isn;
        let rel_ack = Wrapping(tcp.get_acknowledgement()) - destination.isn;
        let segment = TcpSegment {
            rel_seq,
            rel_ack,
            flags: tcp_flags,
            data: tcp.payload().to_vec(), // XXX data cloned here
            pcap_index,
        };
        queue_segment(&mut origin, segment);

        // if tcp_flags & TcpFlags::FIN != 0 {
        //     warn!("origin next seq was {}", origin.next_rel_seq.0);
        //     origin.next_rel_seq += Wrapping(1);
        // }

        match origin.status {
            TcpStatus::Established => {
                // we know there is a FIN (tested in TcpStreamReassembly::update)
                origin.status = TcpStatus::FinWait1;
                destination.status = TcpStatus::CloseWait; // we are not sure it was received
            }
            TcpStatus::CloseWait => {
                if !has_fin {
                    // if only an ACK, do nothing and stay in CloseWait status
                    if has_ack {
                        // debug!("destination status: {:?}", destination.status);
                        if destination.status == TcpStatus::FinWait1 {
                            destination.status = TcpStatus::FinWait2;
                        }
                    } else {
                        warn!("Origin should have sent a FIN and/or ACK");
                    }
                } else {
                    origin.status = TcpStatus::LastAck;
                    // debug!("destination status: {:?}", destination.status);
                    if has_ack || destination.status == TcpStatus::FinWait2 {
                        destination.status = TcpStatus::TimeWait;
                    } else {
                        destination.status = TcpStatus::Closing;
                    }
                }
            }
            TcpStatus::TimeWait => {
                // only an ACK should be sent (XXX nothing else, maybe PSH)
                if has_ack {
                    // this is the end!
                    origin.status = TcpStatus::Closed;
                    destination.status = TcpStatus::Closed;
                }
            }
            _ => {
                warn!(
                    "Unhandled closing transition: origin host {} status {:?}",
                    origin.addr, origin.status
                );
                warn!(
                    "    dest host {} status {:?}",
                    destination.addr, destination.status
                );
            }
        }

        trace!(
            "TCP connection closing, {} remaining (undelivered) segments",
            origin.segments.len()
        );
        // DEBUG
        for (n, s) in origin.segments.iter().enumerate() {
            trace!("  s[{}]: plen={}", n, s.data.len());
        }

        // TODO what now?

        if origin.segments.is_empty() {
            return Ok(ret);
        }

        Ok(ret)
    }

    // force expiration (for ex after timeout) of this stream
    fn expire(&mut self) {
        self.client.status = TcpStatus::Closed;
        self.server.status = TcpStatus::Closed;
    }
} // TcpStream

fn queue_segment(peer: &mut TcpPeer, segment: TcpSegment) {
    // only store segments with data, except FIN
    if segment.data.is_empty() && segment.flags & TcpFlags::FIN == 0 {
        return;
    }
    // // DEBUG
    // for (n, s) in peer.segments.iter().enumerate() {
    //     debug!(
    //         "  XXX peer s[{}]: rel_seq={} plen={}",
    //         n,
    //         s.rel_seq,
    //         s.data.len()
    //     );
    // }
    // trivial case: list is empty - just push segment
    if peer.segments.is_empty() {
        trace!("Pushing segment (front)");
        peer.segments.push_front(segment);
        return;
    }
    // find last element before candidate and first element after candidate
    let mut before = None;
    let mut after = None;
    let mut opt_pos = None;
    for (n, s) in peer.segments.iter().enumerate() {
        if s.rel_seq < segment.rel_seq {
            before = Some(s);
        } else {
            after = Some(s);
            opt_pos = Some(n);
            break;
        }
    }
    // trace!("tcp segment insertion index: {:?}", opt_pos);
    // check for left overlap
    if let Some(s) = before {
        let next_seq = s.rel_seq + Wrapping(s.data.len() as u32);
        match segment.rel_seq.cmp(&next_seq) {
            Ordering::Equal => {
                // XXX do nothing, simply queue segment
                // // simple case: merge segment
                // trace!(
                //     "Merging segments (seq {} and {})",
                //     s.rel_seq,
                //     segment.rel_seq
                // );
                // s.data.extend_from_slice(&segment.data);
                // s.rel_ack = segment.rel_ack;
                // // XXX pcap_index should be a list (and append to it)
                // // TODO check next segment in queue to test if a hole was filled
                // return;
            }
            Ordering::Greater => {
                // we have a hole
                warn!("Missing segment on left of incoming segment");
            }
            Ordering::Less => {
                // Left overlap
                warn!("Segment with left overlap");
                // let overlap_size = (next_seq - segment.rel_seq).0 as usize;
                // debug_assert!(overlap_size <= s.data.len());
                // let overlap_start = s.data.len() - overlap_size;
                // let overlap_left = &s.data[overlap_start..];
                // if overlap_left == &segment.data[..overlap_size] {
                //     info!(
                //         "TCP Segment with left overlap: area matches idx={}",
                //         segment.pcap_index
                //     );
                //     trace!("Left overlap: removing {} bytes", overlap_size);
                //     // remove overlapping area and fix offset
                //     let new_data = segment.data.split_off(overlap_size);
                //     segment.data = new_data;
                //     segment.rel_seq += Wrapping(overlap_size as u32);
                // } else {
                //     warn!(
                //         "TCP Segment with left overlap: area differs idx={}",
                //         segment.pcap_index
                //     );
                //     // XXX keep new ?
                // }
            }
        }
    }
    // check for right overlap
    if let Some(s) = after {
        let right_next_seq = segment.rel_seq + Wrapping(segment.data.len() as u32);
        match right_next_seq.cmp(&s.rel_seq) {
            Ordering::Equal => (),
            Ordering::Greater => {
                // Right overlap
                warn!("Segment with right overlap");
                // let overlap_size = (right_next_seq - s.rel_seq).0 as usize;
                // debug_assert!(overlap_size <= s.data.len());
                // let overlap_start = segment.data.len() - overlap_size;
                // let overlap = &segment.data[overlap_start..];
                // let right_overlap = &s.data[..overlap_size];
                // if overlap == right_overlap {
                //     info!(
                //         "TCP Segment with right overlap: area matches idx={}",
                //         segment.pcap_index
                //     );
                //     trace!("Right overlap: removing {} bytes", overlap_size);
                //     segment.data.truncate(overlap_start);
                // } else {
                //     warn!(
                //         "TCP Segment with right overlap: area differs idx={}",
                //         segment.pcap_index
                //     );
                //     // XXX keep new ?
                // }
            }
            Ordering::Less => {
                trace!(
                    "hole remaining on right of incoming segment idx={}",
                    segment.pcap_index
                );
            }
        }
    }
    // if segment.data.is_empty() && segment.flags & TcpFlags::FIN == 0 {
    //     trace!("No data after overlap, NOT queuing segment");
    //     return;
    // }
    trace!("Pushing segment");
    match opt_pos {
        Some(idx) => peer.segments.insert(idx, segment),
        None => peer.segments.push_back(segment),
    }
    // peer.insert_sorted(segment);
}

fn send_peer_segments(peer: &mut TcpPeer, rel_ack: Wrapping<u32>) -> Option<Vec<TcpSegment>> {
    trace!(
        "Trying to send segments for {}:{} up to {} (last ack: {})",
        peer.addr,
        peer.port,
        rel_ack,
        peer.last_rel_ack
    );
    if rel_ack == peer.last_rel_ack {
        trace!("re-acking last data, doing nothing");
        return None;
    }
    if peer.segments.is_empty() {
        return None;
    }

    // is ACK acceptable?
    if rel_ack < peer.last_rel_ack {
        warn!("ACK request for already ACKed data (ack < last_ack)");
        return None;
    }

    trace!("Peer: {:?}", peer); // TODO to remove

    // check consistency of segment ACK numbers + order and/or missing fragments and/or overlap

    let mut acked = Vec::new();

    while !peer.segments.is_empty() {
        let segment = &peer.segments[0];
        trace!(
            "segment: rel_seq={}  len={}",
            segment.rel_seq,
            segment.data.len()
        );
        trace!(
            "  origin.next_rel_seq {} ack {}",
            peer.next_rel_seq,
            rel_ack
        );
        // if origin.next_rel_seq > rel_ack {
        //     warn!("next_seq > ack - partial ACK ?");
        //     unreachable!(); // XXX do we care about that case?
        //                     // break;
        // }
        if rel_ack <= segment.rel_seq {
            // if packet is in the past (strictly less), we don't care
            break;
        }

        // safety: segments is just tested above
        let mut segment = peer.segments.pop_front().unwrap();

        if rel_ack < segment.rel_seq + Wrapping(segment.data.len() as u32) {
            // warn!("ACK lower then seq + segment size - SACK?");
            trace!("ACK for part of buffer");
            // split data and insert new dummy segment
            trace!("rel_ack {} segment.rel_seq {}", rel_ack, segment.rel_seq);
            trace!("segment data len {}", segment.data.len());
            let acked_len = (rel_ack - segment.rel_seq).0 as usize;
            let new_segment = segment.split_off(acked_len);
            trace!(
                "insert new segment from {} len {}",
                new_segment.rel_ack,
                new_segment.data.len()
            );
            peer.insert_sorted(new_segment);
        }

        adjust_seq_numbers(peer, &segment);
        handle_overlap(peer, &mut segment);

        trace!(
            "ACKed: pushing segment: rel_seq={} len={}",
            segment.rel_seq,
            segment.data.len(),
        );
        if !segment.data.is_empty() {
            acked.push(segment);
        }
    }

    if peer.next_rel_seq != rel_ack {
        // missed segments, or maybe received FIN ?
        warn!(
            "TCP ACKed unseen segment next_seq {} != ack {} (Missed segments?)",
            peer.next_rel_seq, rel_ack
        );
        // TODO notify upper layer for missing data
    }

    peer.last_rel_ack = rel_ack;
    Some(acked)
}

// check for overlap
// XXX what if several segments overlap the same area?
// XXX    currently, `segment` will be dropped, so the last segment remains
fn handle_overlap(peer: &mut TcpPeer, segment: &mut TcpSegment) {
    if let Some(next) = peer.segments.front() {
        if let Some(overlap_offset) = segment.overlap_offset(&next) {
            // strategy 1: find intersection and drop it
            let mut remaining = None;
            warn!("segments overlaps next candidate (offset={})", overlap_offset);
            let mut overlapping_area = segment.split_off(overlap_offset);
            // next segment can be smaller than current segment
            if next.data.len() < overlapping_area.data.len() {
                trace!("re-splitting segment");
                let rem = overlapping_area.split_off(next.data.len());
                remaining = Some(rem);
            }
            // compare zones
            if overlapping_area.data[..] != next.data[..] {
                warn!(
                    "Overlapping area differs! idx={} vs idx={}",
                    segment.pcap_index, next.pcap_index
                );
                // unimplemented!();
            }
            trace!(
                "Dropping part of segment: rel_seq={} len={}",
                overlapping_area.rel_seq,
                overlapping_area.data.len(),
            );
            drop(overlapping_area);
            if let Some(rem) = remaining {
                trace!("re-inserting remaining data");
                peer.insert_sorted(rem);
            }
        }
    }
}

fn adjust_seq_numbers(origin: &mut TcpPeer, segment: &TcpSegment) {
    if !segment.data.is_empty() {
        // adding length is wrong in case of overlap
        // origin.next_rel_seq += Wrapping(segment.data.len() as u32);
        origin.next_rel_seq = segment.rel_seq + Wrapping(segment.data.len() as u32);
    }

    if segment.flags & TcpFlags::FIN != 0 {
        // trace!("Segment has FIN");
        origin.next_rel_seq += Wrapping(1);
    }
}

impl TcpStreamReassembly {
    pub(crate) fn update(
        &mut self,
        flow: &Flow,
        tcp: &TcpPacket,
        to_server: bool,
        pcap_index: usize,
    ) -> Result<Option<Vec<TcpSegment>>, TcpStreamError> {
        trace!("5-t: {}", flow.five_tuple);
        trace!("  flow id: {:x}", flow.flow_id);
        trace!(
            "  seq: {:x}  ack {:x}",
            tcp.get_sequence(),
            tcp.get_acknowledgement()
        );

        let mut stream = self
            .m
            .entry(flow.flow_id)
            .or_insert_with(|| TcpStream::new(flow));
        trace!("stream state: {:?}", stream.status);
        trace!("to_server: {}", to_server);

        // check time delay with previous packet before updating
        if stream.last_seen_ts > flow.last_seen {
            info!("packet received in past of stream idx={}", pcap_index);
        } else if flow.last_seen - stream.last_seen_ts > self.timeout {
            warn!("TCP stream received packet after timeout");
            stream.expire();
            return Err(TcpStreamError::Expired);
        }
        stream.last_seen_ts = flow.last_seen;

        let (origin, _destination) = if to_server {
            (&stream.client, &stream.server)
        } else {
            (&stream.server, &stream.client)
        };

        trace!(
            "origin: {}:{} status {:?}",
            origin.addr,
            origin.port,
            origin.status
        );
        debug_print_tcp_flags(tcp.get_flags());

        match origin.status {
            TcpStatus::Closed | TcpStatus::Listen | TcpStatus::SynSent | TcpStatus::SynRcv => {
                stream.handle_new_connection(&tcp, to_server, pcap_index)
            }
            TcpStatus::Established => {
                // check for close request
                if tcp.get_flags() & (TcpFlags::FIN | TcpFlags::RST) != 0 {
                    trace!("Requesting end of connection");
                    stream.handle_closing_connection(tcp, to_server, pcap_index)
                } else {
                    stream.handle_established_connection(tcp, to_server, pcap_index)
                }
            }
            _ => stream.handle_closing_connection(tcp, to_server, pcap_index),
        }
    }
    pub(crate) fn check_expired_connections(&mut self, now: Duration) {
        for (flow_id, stream) in self.m.iter_mut() {
            if now < stream.last_seen_ts {
                warn!(
                    "stream.last_seen_ts is in the future for flow id {:x}",
                    flow_id
                );
                continue;
            }
            if now - stream.last_seen_ts > self.timeout {
                warn!("TCP stream timeout reached for flow {:x}", flow_id);
                stream.expire();
            }
        }
    }
}

pub(crate) fn finalize_tcp_streams(analyzer: &mut crate::analyzer::Analyzer) {
    warn!("expiring all TCP connections");
    for (flow_id, _stream) in analyzer.tcp_defrag.m.iter() {
        // TODO do we have anything to do?
        if let Some(flow) = analyzer.flows.get_flow(*flow_id) {
            debug!("  flow: {:?}", flow);
        }
    }
    analyzer.tcp_defrag.m.clear();
}

fn debug_print_tcp_flags(tcp_flags: u16) {
    if log::Level::Debug <= log::STATIC_MAX_LEVEL {
        let mut s = String::from("tcp_flags: [");
        if tcp_flags & TcpFlags::SYN != 0 {
            s += "S"
        }
        if tcp_flags & TcpFlags::FIN != 0 {
            s += "F"
        }
        if tcp_flags & TcpFlags::RST != 0 {
            s += "R"
        }
        if tcp_flags & TcpFlags::URG != 0 {
            s += "U"
        }
        if tcp_flags & TcpFlags::PSH != 0 {
            s += "P"
        }
        if tcp_flags & TcpFlags::ACK != 0 {
            s += "A"
        }
        s += "]";
        trace!("{}", s);
    }
}

impl fmt::Debug for TcpPeer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Peer: {}:{}", self.addr, self.port)?;
        writeln!(f, "  status: {:?}", self.status)?;
        writeln!(f, "  isn: 0x{:x}  ian: 0x{:x}", self.isn, self.ian)?;
        writeln!(f, "  next_rel_seq: {}", self.next_rel_seq)?;
        writeln!(f, "  last_rel_ack: {}", self.last_rel_ack)?;
        writeln!(f, "  #segments: {}", self.segments.len())?;
        for (n, s) in self.segments.iter().enumerate() {
            writeln!(
                f,
                "    s[{}]: rel_seq={} len={}",
                n,
                s.rel_seq,
                s.data.len()
            )?;
        }
        Ok(())
    }
}
