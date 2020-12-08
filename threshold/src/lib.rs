
use futures::prelude::*;
use log::{error, info};
use sc_client_api::{backend::Backend, BlockchainEvents};
use sp_api::{ProvideRuntimeApi, CallApiAt};
use sp_blockchain::HeaderBackend;
use sp_runtime::traits::Block as BlockT;
use sp_transaction_pool::TransactionPool;
use sc_keystore::KeyStorePtr;
use sc_block_builder::BlockBuilderProvider;
use sc_network::PeerId;
use sc_network_gossip::GossipEngine;
use sp_utils::mpsc::{tracing_unbounded, TracingUnboundedReceiver, TracingUnboundedSender};
use parking_lot::Mutex;
use std::collections::{HashSet, HashMap};
use std::sync::{RwLock, Arc};
use std::time::{Duration, SystemTime};
use std::pin::Pin;
use std::task::{Poll, Context};

mod communicate;
mod gossip;
mod gg20_keygen_client;
mod gg20_sign_client;
mod common;
mod listening;
use common::{GossipMessage, TssResult, Key, Entry, MissionParam, vec_contains_vecu8};
use gg20_keygen_client::{gg20_keygen_client};
use gg20_sign_client::{gg20_sign_client};
use communicate::{NetworkBridge, Error, Network as NetworkT};
use gossip::{get_topic};
use listening::{WorkerCommand, start_listener};

pub struct TssWork<Block: BlockT, N: NetworkT<Block>> {
    worker: Pin<Box<dyn Future<Output = Result<(), Error>> + Send>>,
    network: NetworkBridge<Block, N>,
}

pub struct TssParams<N, C, A> {
    pub client: Arc<C>,
    pub pool: Arc<A>,
    pub network: N,
    pub keystore: KeyStorePtr,
}

impl<Block: BlockT, N: NetworkT<Block> + Sync> TssWork<Block, N> {
    fn new(
        command_rx: TracingUnboundedReceiver<WorkerCommand>,
        network: NetworkBridge<Block, N>,
    ) -> Self {
        let worker = Worker::new(
            network.gossip_engine.clone(),
            command_rx,
            network.service().local_id()
        );
        let worker = Box::pin(worker);
        TssWork {
            worker,
            network,
        }
    }
}

impl<Block: BlockT, N: NetworkT<Block> + Sync> Future for TssWork<Block, N>
{
    type Output = Result<(), Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        match Future::poll(Pin::new(&mut self.worker), cx) {
            Poll::Pending => {},
            Poll::Ready(e) => {
                match e {
                    Err(Error::Safety(error_string)) => {
                        return Poll::Ready(
                            Err(Error::Safety(format!("Worker has concluded for: {}.", error_string)))
                        )
                    },
                    _ => {
                        return Poll::Ready(
                            Err(Error::Safety("Unknown reason cause threshold shut down".into()))
                        )
                    },
                }
            }
        }

        Future::poll(Pin::new(&mut self.network), cx)
    }
}

pub struct Worker<B: BlockT> {
    db_mtx: Arc<RwLock<HashMap<Key, String>>>,
    id_list: Arc<RwLock<HashMap<u64, Vec<Vec<u8>>>>>,
    low_sender: Arc<Mutex<TracingUnboundedSender<String>>>,
    low_receiver: TracingUnboundedReceiver<String>,
    gossip_engine: Arc<Mutex<GossipEngine<B>>>,
    command_rx: TracingUnboundedReceiver<WorkerCommand>,
    messages: HashSet<Vec<u8>>,
    local_peer_id: PeerId,
}

impl<B: BlockT> Worker<B> {
    pub fn new(
        gossip_engine: Arc<Mutex<GossipEngine<B>>>,
        command_rx: TracingUnboundedReceiver<WorkerCommand>,
        local_peer_id: PeerId
    ) -> Self {
        let db_mtx = Arc::new(RwLock::new(HashMap::new()));
        let id_list = Arc::new(RwLock::new(HashMap::new()));
        let (low_sender, low_receiver) = tracing_unbounded("mpsc_mission_worker");
        let low_sender = Arc::new(Mutex::new(low_sender));
        Worker {
            db_mtx,
            id_list,
            low_sender,
            low_receiver,
            gossip_engine,
            command_rx,
            messages: HashSet::new(),
            local_peer_id
        }
    }

    fn handle_worker_command(&mut self, command: WorkerCommand) {
        match command {
            // run missions
            WorkerCommand::Keygen(index, store, n, t) => {
                let start_time = SystemTime::now();
                let local_peer_id = self.local_peer_id.clone();
                let mission_param = MissionParam { start_time, index, store, n, t, local_peer_id };

                async_std::task::spawn(
                    gg20_keygen_client(
                        self.low_sender.clone(),
                        self.db_mtx.clone(),
                        self.id_list.clone(),
                        mission_param
                    ).map_err(|e|{
                        // TODO: return the result to chain
                        info!(target: "afg", "keygen mission timeout: {:?}****************", e);
                    })
                );
            },
            WorkerCommand::Sign(index, store, n, t) => {
                let start_time = SystemTime::now();
                let local_peer_id = self.local_peer_id.clone();
                let mission_param = MissionParam { start_time, index, store, n, t, local_peer_id };

                async_std::task::spawn(
                    gg20_sign_client(
                        self.low_sender.clone(),
                        self.db_mtx.clone(),
                        self.id_list.clone(),
                        mission_param
                    ).map_err(|e|{
                        // TODO: return the result to chain
                        info!(target: "afg", "keysign mission timeout: {:?}****************", e);
                    })
                );
            },
        }
    }
}

impl<Block: BlockT> Future for Worker<Block> {
    type Output = Result<(), Error>;
    // TODO: how to open a task and close task
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        match Stream::poll_next(Pin::new(&mut self.command_rx), cx) {
            Poll::Pending => {},
            Poll::Ready(None) => {
                // the `commands_rx` stream should never conclude since it's never closed.
                return Poll::Ready(
                    Err(Error::Safety("`commands_rx` was closed.".into()))
                )
            },
            Poll::Ready(Some(command)) => {
                // some command issued externally
                self.handle_worker_command(command);
                cx.waker().wake_by_ref();
            }
        }

        // get messages from task, handle it(send to net or chain)
        match Stream::poll_next(Pin::new(&mut self.low_receiver), cx) {
            Poll::Ready(Some(data)) => {
                let topic = get_topic::<Block>("multi-party-tss");
                self.gossip_engine.lock().gossip_message(topic, data.as_bytes().to_vec(), false);
            },
            Poll::Ready(None) => {
                return Poll::Ready(
                    Err(Error::Safety("low receiver closed".into())))
            },
            Poll::Pending => {},
        }

        // receive messages from the network and store it
        let topic = get_topic::<Block>("multi-party-tss");
        let mut messages = self.gossip_engine.lock().messages_for(topic);
        loop {
            match Stream::poll_next(Pin::new(&mut messages), cx) {
                Poll::Ready(Some(notification)) => {
                    if !self.messages.contains(&notification.message.clone()) {
                        self.messages.insert(notification.message.clone());
                        let data = String::from_utf8_lossy(&notification.message);
                        let data: GossipMessage = serde_json::from_str(&data).unwrap();
                        match data {
                            GossipMessage::Chat(data) => {
                                let entry: Entry = serde_json::from_str(&data).unwrap();
                                loop {
                                    if let Ok(mut db) = self.db_mtx.try_write() {
                                        db.insert(entry.key.clone(), entry.value.clone());
                                        break;
                                    }
                                }
                            },
                            GossipMessage::Notify(data) => {
                                let entry: Entry = serde_json::from_str(&data).unwrap();
                                let index = entry.key.clone().as_str().split('-').collect::<Vec<&str>>()
                                    .pop().unwrap().parse::<u64>().unwrap();
                                let data: Vec<u8> = serde_json::from_str(&entry.value).unwrap();
                                loop {
                                    if let Ok(mut db) = self.id_list.try_write() {
                                        if let Some(mut vv) = db.get_mut(&index).cloned() {
                                            if !vec_contains_vecu8(&vv, &data){
                                                vv.push(data.clone());
                                            }
                                            db.insert(index, vv);
                                        } else { db.insert(index, vec![data]); }
                                        break;
                                    }
                                }
                            },
                        }
                    }
                },
                Poll::Ready(None) => {},
                Poll::Pending => break,
            }
        }

        Poll::Pending
    }
}

impl<Block: BlockT> Unpin for Worker<Block> {}

pub fn run_threshold<C, Block: BlockT, B, N, A>(
    params: TssParams<N, C, A>
) -> sp_blockchain::Result<impl Future<Output = ()> + Unpin + Send + 'static>
where
    A: TransactionPool<Block = Block> + 'static,
    Block::Hash: Ord + Into<sp_core::H256>,
    N: NetworkT<Block> + Send + Sync + Clone + 'static,
    B: Backend<Block> + Send + Sync + 'static,
    C: BlockBuilderProvider<B, Block, C> + HeaderBackend<Block> + ProvideRuntimeApi<Block> + BlockchainEvents<Block>
    + CallApiAt<Block> + Send + Sync + 'static,
{
    let TssParams {
        client,
        pool,
        network,
        keystore,
    } = params;

    let (command_tx, command_rx) = tracing_unbounded("mpsc_tss_command");

    let network = NetworkBridge::new(network);

    let work = TssWork::new(
        command_rx,
        network,
    );

    let work = work.map(|res| match res {
        Ok(()) => error!(target: "afg", "tss work future has concluded naturally, this should be unreachable."),
        Err(e) => error!(target: "afg", "tss work error: {:?}", e),
    });

    let listener = start_listener(client, pool, command_tx, keystore).then(|_| future::pending::<()>());

    Ok(future::select(work, listener).map(drop))
}

