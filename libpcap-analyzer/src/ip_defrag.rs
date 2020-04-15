use std::cmp::Ordering;
use std::collections::HashMap;

/// Defragmentation engine
pub trait DefragEngine: Send + Sync {
    /// This function updates the engine with a new Fragment
    /// Returns a Fragment describing the defragmentation operation result
    fn update<'a>(
        &mut self,
        id: u32,
        offset: usize,
        more_fragments: bool,
        frag: &'a [u8],
    ) -> Fragment<'a>;
}

pub enum Fragment<'a> {
    /// Data is not fragmented - return original slice
    NoFrag(&'a [u8]),
    /// Data was defragmented - return buffer
    Complete(Vec<u8>),
    /// Fragment is part of a (yet) unfinished buffer
    Incomplete,
    /// Defragmentation error
    Error,
}

struct DefragData {
    buffer: Vec<u8>,
    last_complete_offset: usize,
    next_data: Vec<u8>,
    next_offset: Option<usize>,
    next_is_complete: bool,
}

impl DefragData {
    fn new(data: &[u8], offset: usize, complete: bool) -> DefragData {
        if offset == 0 {
            DefragData {
                buffer: data.to_vec(),
                last_complete_offset: data.len(),
                next_data: Vec::new(),
                next_offset: None,
                next_is_complete: complete,
            }
        } else {
            DefragData {
                buffer: Vec::new(),
                last_complete_offset: 0,
                next_data: data.to_vec(),
                next_offset: Some(offset),
                next_is_complete: complete,
            }
        }
    }
}

pub struct IPDefragEngine {
    // XXX we need to store all fragments, with offsets
    // XXX index this by 3-tuple ?
    ip_fragments: HashMap<u32, DefragData>,
}

impl IPDefragEngine {
    pub fn new() -> IPDefragEngine {
        IPDefragEngine {
            ip_fragments: HashMap::new(),
        }
    }
}

impl DefragEngine for IPDefragEngine {
    fn update<'a>(
        &mut self,
        id: u32,
        frag_offset: usize,
        more_fragments: bool,
        frag: &'a [u8],
    ) -> Fragment<'a> {
        // check if data is not fragmented
        if !more_fragments && frag_offset == 0 {
            return Fragment::NoFrag(frag);
        }
        // check if we already have a fragment
        if let Some(f) = self.ip_fragments.get_mut(&id) {
            if frag_offset > f.last_complete_offset {
                if let Some(_next_offset) = f.next_offset {
                    warn!("defrag: maybe second hole");
                    // we already do have data after a hole
                    // check if not a second hole
                    return Fragment::Error;
                } else {
                    // first data, after a hole
                    warn!(
                        "defrag: hole detected key={} len={} next offset={}",
                        id,
                        frag.len(),
                        frag_offset
                    );
                    f.next_data.extend_from_slice(frag);
                    f.next_offset = Some(frag_offset);
                    f.next_is_complete = !more_fragments;
                    return Fragment::Incomplete;
                }
            } else {
                warn!(
                    "defrag: adding data to buffer key={} len={} offset={}",
                    id,
                    frag.len(),
                    frag_offset
                );
                if frag_offset < f.buffer.len() {
                    warn!(
                        "defrag: overlapping data frag_offset {}, last_complete_offset={}",
                        frag_offset, f.last_complete_offset
                    );
                    f.buffer.truncate(frag_offset);
                }
                f.buffer.extend_from_slice(frag);
                if let Some(next_offset) = f.next_offset {
                    // we already have data after a hole. Did we filled it?
                    // check that we are not overlapping next_data
                    let new_buffer_len = f.buffer.len();
                    if new_buffer_len >= next_offset {
                        warn!("defrag: checking hole");
                        if new_buffer_len > next_offset + f.next_data.len() {
                            warn!("defrag: hole completely covered by overlapping data");
                            f.next_data.clear();
                            f.next_offset = None;
                            f.next_is_complete = false;
                        } else {
                            // check for partial cover
                            match new_buffer_len.cmp(&next_offset) {
                                Ordering::Greater => {
                                    warn!("defrag: hole partially covered");
                                    // we already know the next operations cannot underflow
                                    let bytes_to_skip = next_offset - new_buffer_len;
                                    f.buffer.extend_from_slice(&f.next_data[bytes_to_skip..]);
                                    f.last_complete_offset = f.buffer.len();
                                    f.next_data.clear();
                                    // leave next_is_complete unchanged
                                    f.next_offset = None;
                                }
                                Ordering::Equal => {
                                    warn!("defrag: hole exactly covered (probably a reorder)");
                                    f.buffer.append(&mut f.next_data);
                                    f.next_offset = None;
                                    f.last_complete_offset = f.buffer.len();
                                }
                                Ordering::Less => {
                                    // not fully covered - leave it
                                },
                            }
                        }
                    }
                } else {
                    f.last_complete_offset = f.buffer.len();
                }
            }
            // re-check for completion
            if (!more_fragments || f.next_is_complete) && f.next_offset.is_none() {
                match self.ip_fragments.remove(&id) {
                    Some(f) => {
                        warn!("defrag: done for id {}", id);
                        return Fragment::Complete(f.buffer);
                    }
                    None => {
                        error!("defrag: could not remove entry (while we know it exists!)");
                        return Fragment::Error;
                    }
                }
            }
            Fragment::Incomplete
        } else {
            // this is the first time we see data for this id
            warn!(
                "defrag: inserting buffer key={} len={} offset={}",
                id,
                frag.len(),
                frag_offset
            );
            self.ip_fragments
                .insert(id, DefragData::new(frag, frag_offset, !more_fragments));
            Fragment::Incomplete
        }
    }
}
