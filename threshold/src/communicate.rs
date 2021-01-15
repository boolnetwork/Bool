
use futures::prelude::*;
// use log::{debug, trace};
use parking_lot::Mutex;
use std::{pin::Pin, sync::Arc, task::{Context, Poll}};
use sp_blockchain::{Error as ClientError};
use sc_network::{PeerId, NetworkService};
use sc_network_gossip::{GossipEngine, Network as GossipNetwork};
use sp_runtime::traits::Block as BlockT;
use sp_runtime::ConsensusEngineId;
use sp_utils::mpsc::{TracingUnboundedReceiver};

use crate::gossip::{GossipValidator, PeerReport};

pub const TSS_ENGINE_ID: ConsensusEngineId = *b"LLTP";
pub const TSS_PROTOCOL_NAME: &'static str = "/abmatrix/multi-party-tss/1";

pub trait Network<Block: BlockT>: GossipNetwork<Block> + Clone + Send + 'static {

    fn local_id(&self) -> PeerId;
}

impl<B, H> Network<B> for Arc<NetworkService<B, H>> where
    B: BlockT,
    H: sc_network::ExHashT,
{
    fn local_id(&self) -> PeerId {
        self.local_peer_id().clone()
    }
}

pub struct NetworkBridge<B: BlockT, N: Network<B>> {
    service: N,
    pub gossip_engine: Arc<Mutex<GossipEngine<B>>>,
    validator: Arc<GossipValidator>,
    gossip_validator_report_stream: Arc<Mutex<TracingUnboundedReceiver<PeerReport>>>,
}

impl<B: BlockT, N: Network<B>> Unpin for NetworkBridge<B, N> {}

impl<B: BlockT, N: Network<B>> NetworkBridge<B, N> {
    pub fn new(service: N) -> Self {
        let (validator, report_stream) = GossipValidator::new();
        let report_stream = Arc::new(Mutex::new(report_stream));
        let gossip_engine = Arc::new(Mutex::new(GossipEngine::new(
            service.clone(),
            TSS_ENGINE_ID,
            TSS_PROTOCOL_NAME,
            validator.clone(),
        )));

        NetworkBridge {
            service,
            gossip_engine,
            validator,
            gossip_validator_report_stream: report_stream,
        }
    }
}

impl<B: BlockT, N: Network<B>> Future for NetworkBridge<B, N> {
    type Output = Result<(), Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        loop {
            match self.gossip_validator_report_stream.lock().poll_next_unpin(cx) {
                Poll::Ready(Some(PeerReport { who, cost_benefit })) => {
                    self.gossip_engine.lock().report(who, cost_benefit);
                },
                Poll::Ready(None) => return Poll::Ready(
                    Err(Error::Network("Gossip validator report stream closed.".into()))
                ),
                Poll::Pending => break,
            }
        }

        match self.gossip_engine.lock().poll_unpin(cx) {
            Poll::Ready(()) => return Poll::Ready(
                Err(Error::Network("Gossip engine future finished.".into()))
            ),
            Poll::Pending => {},
        }

        Poll::Pending
    }
}

impl<B: BlockT, N: Network<B>> Clone for NetworkBridge<B, N> {
    fn clone(&self) -> Self {
        NetworkBridge {
            service: self.service.clone(),
            gossip_engine: self.gossip_engine.clone(),
            validator: Arc::clone(&self.validator),
            gossip_validator_report_stream: self.gossip_validator_report_stream.clone(),
        }
    }
}

/// Errors that can occur while running.
#[derive(Debug)]
pub enum Error {
    /// A network error.
    Network(String),
    /// Could not complete a round on disk.
    Client(ClientError),
    /// An invariant has been violated (e.g. not finalizing pending change blocks in-order)
    Safety(String),
}

impl From<ClientError> for Error {
    fn from(e: ClientError) -> Self {
        Error::Client(e)
    }
}