use fnv::FnvHashMap;
use libpcap_tools::{FiveTuple, Flow, FlowID};
use rand::prelude::*;
use rand_chacha::*;
use std::collections::hash_map::{Entry, Values};
use std::collections::HashMap;

/// Storage for flows
///
/// A `Flow` is identified by a `FlowID`.
/// Multiple `FlowID` may point to the same flow (direct and reverse flow, for ex.).
pub struct FlowMap {
    trng: ChaChaRng,
    flows: FnvHashMap<FlowID, Flow>,
    flows_id: HashMap<FiveTuple, FlowID>,
}

impl Default for FlowMap {
    fn default() -> Self {
        FlowMap {
            trng: ChaChaRng::from_rng(rand::thread_rng()).unwrap(),
            flows: FnvHashMap::default(),
            flows_id: HashMap::new(),
        }
    }
}

impl FlowMap {
    /// Use provided seed for the random number generator (flow IDs)
    ///
    /// This option is intended for use in testing
    pub fn with_rng_seed(self, seed: u64) -> Self {
        let trng = <ChaChaRng as SeedableRng>::seed_from_u64(seed);
        FlowMap { trng, ..self }
    }

    pub fn lookup_flow(&self, five_t: &FiveTuple) -> Option<FlowID> {
        self.flows_id.get(five_t).copied()
    }

    /// Return the number of flows
    #[inline]
    pub fn len(&self) -> usize {
        self.flows.len()
    }

    /// Returns true if the map contains no elements.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    /// Insert a flow in the hash tables.
    /// Takes ownership of five_t and flow
    pub fn insert_flow(&mut self, five_t: FiveTuple, flow: Flow) -> FlowID {
        let rev_id = self.flows_id.get(&five_t.get_reverse()).copied();
        if let Some(id) = rev_id {
            // insert reverse flow ID
            trace!("Inserting reverse flow ID 0x{:x}", id);
            self.flows_id.insert(five_t, id);
            return id;
        }
        // get a new flow index (XXX currently: random number)
        let id = self.trng.gen();
        trace!("Inserting new flow (id=0x{:x})", id);
        trace!("    flow: {:?}", flow);
        self.flows.insert(id, flow);
        self.flows_id.insert(five_t, id);
        id
    }

    /// Return a reference to the flow identified by flow_id
    #[inline]
    pub fn get_flow(&self, flow_id: FlowID) -> Option<&Flow> {
        self.flows.get(&flow_id)
    }

    /// Return a mutable reference to the flow identified by flow_id
    #[inline]
    pub fn get_flow_mut(&mut self, flow_id: FlowID) -> Option<&mut Flow> {
        self.flows.get_mut(&flow_id)
    }

    /// An iterator visiting all flows in arbitrary order.
    #[inline]
    pub fn values(&self) -> Values<FlowID, Flow> {
        self.flows.values()
    }

    /// Gets the given key's corresponding entry in the map for in-place manipulation.
    #[inline]
    pub fn entry(&mut self, flow_id: FlowID) -> Entry<FlowID, Flow> {
        self.flows.entry(flow_id)
    }

    /// Remove all flows
    pub fn clear(&mut self) {
        self.flows.clear();
        self.flows_id.clear();
    }
}
