
use sp_runtime::traits::{Block as BlockT, Hash as HashT, Header as HeaderT};
use sc_network_gossip::{MessageIntent, ValidatorContext};
use sc_network::{ObservedRole, PeerId, ReputationChange};
use sp_utils::mpsc::{tracing_unbounded, TracingUnboundedReceiver, TracingUnboundedSender};
use std::sync::{Arc, RwLock};

use std::collections::HashSet;

/// The peers we're connected do in gossip.
pub struct Peers {
    inner: HashSet<PeerId>
}

impl Default for Peers {
    fn default() -> Self {
        Peers { inner: HashSet::new() }
    }
}

impl Peers {
    fn new_peer(&mut self, who: PeerId) { self.inner.insert(who); }

    fn peer_disconnected(&mut self, who: PeerId) { self.inner.remove(&who); }

    fn reshuffle(&mut self) { self.inner.clear(); }
}

/// A validator for gossip messages.
pub(super) struct GossipValidator {
    inner: RwLock<Peers>,
    report_sender: TracingUnboundedSender<PeerReport>,
}

impl GossipValidator {
    pub fn new() -> (Arc<Self>, TracingUnboundedReceiver<PeerReport>){
        let (tx, rx) = tracing_unbounded("mpsc_grandpa_gossip_validator");
        let inner = RwLock::new(Peers::default());
        let val = GossipValidator {
            inner,
            report_sender: tx,
        };
        let val = Arc::new(val);
        (val, rx)
    }

    fn report(&self, who: PeerId, cost_benefit: ReputationChange) {
        let _ = self.report_sender.unbounded_send(PeerReport { who, cost_benefit });
    }

    pub fn do_validate(&self, _who: &PeerId, mut _data: &[u8]) {

    }
}

impl<Block: BlockT> sc_network_gossip::Validator<Block> for GossipValidator {
    /// New peer is connected.
    fn new_peer(&self, _context: &mut dyn ValidatorContext<Block>, who: &PeerId, _roles: ObservedRole) {
        let mut inner = self.inner.write().unwrap();
        inner.new_peer(who.clone());
    }

    /// New connection is dropped.
    fn peer_disconnected(&self, _context: &mut dyn ValidatorContext<Block>, who: &PeerId) {
        let mut inner = self.inner.write().unwrap();
        inner.peer_disconnected(who.clone());
    }

    /// Validate message.
    fn validate(
        &self,
        context: &mut dyn ValidatorContext<Block>,
        _who: &PeerId,
        data: &[u8]
    ) -> sc_network_gossip::ValidationResult<Block::Hash> {
        let topic: Block::Hash = get_topic::<Block>("multi-party-tss");
        context.broadcast_message(topic.clone(), data.to_vec(), true);
        sc_network_gossip::ValidationResult::ProcessAndKeep(topic)
    }

    /// Produce a closure for validating messages on a given topic.
    fn message_expired<'a>(&'a self) -> Box<dyn FnMut(Block::Hash, &[u8]) -> bool + 'a> {
        Box::new(move |_topic, _data| false)
    }

    /// Produce a closure for filtering egress messages.
    fn message_allowed<'a>(&'a self) -> Box<dyn FnMut(&PeerId, MessageIntent, &Block::Hash, &[u8]) -> bool + 'a> {
        Box::new(move |_who, _intent, _topic, _data| true)
    }
}

pub struct PeerReport {
    pub who: PeerId,
    pub cost_benefit: ReputationChange,
}

pub fn get_topic<Block: BlockT>(topic: &str) -> Block::Hash {
    <<Block::Header as HeaderT>::Hashing as HashT>::hash(topic.as_bytes())
}
