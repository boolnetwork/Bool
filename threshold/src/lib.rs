
use futures::{
    prelude::*,
};
use log::{error, info};
use sc_client_api::{
    backend::{AuxStore, Backend},
    LockImportRun, BlockchainEvents, Finalizer, TransactionFor, ExecutorProvider,
};
// use parity_scale_codec::{Encode, Decode};
use sp_api::{ProvideRuntimeApi, CallApiAt};
use sp_blockchain::{HeaderBackend, Error as ClientError, HeaderMetadata};
use sp_runtime::traits::Block as BlockT;
use sp_consensus::{SelectChain, BlockImport};
use sp_transaction_pool::{TransactionPool};
use sc_keystore::KeyStorePtr;
use sc_block_builder::{BlockBuilderProvider};
use sc_network::PeerId;
use sc_network_gossip::GossipEngine;
use sp_utils::mpsc::{tracing_unbounded, TracingUnboundedReceiver, TracingUnboundedSender};
// use sc_telemetry::{telemetry, CONSENSUS_INFO, CONSENSUS_DEBUG};
use parking_lot::{Mutex};
use async_std;
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
use common::{GossipMessage, TssResult, Key, Entry, MissionParam};
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

impl<Block: BlockT, N: NetworkT<Block> + Sync, > TssWork<Block, N> {
    fn new(
        command_rx: TracingUnboundedReceiver<WorkerCommand>,
        network: NetworkBridge<Block, N>,
    ) -> Self {
        let worker = Worker::new(network.gossip_engine.clone(), command_rx);
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
            Poll::Pending => {}
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
    keygen_db_mtx: Arc<RwLock<HashMap<Key, String>>>,
    sign_db_mtx: Arc<RwLock<HashMap<Key, String>>>,
    keygen_ids: Arc<RwLock<HashMap<u64, Vec<Vec<u8>>>>>,
    sign_ids: Arc<RwLock<HashMap<u64, Vec<Vec<u8>>>>>,
    low_sender: Arc<Mutex<TracingUnboundedSender<String>>>,
    low_receiver: TracingUnboundedReceiver<String>,
    gossip_engine: Arc<Mutex<GossipEngine<B>>>,
    command_rx: TracingUnboundedReceiver<WorkerCommand>,
    messages: HashSet<Vec<u8>>,
    // counter: u16,
    // start_time: SystemTime,
}

impl<B: BlockT> Worker<B> {
    pub fn new(gossip_engine: Arc<Mutex<GossipEngine<B>>>, command_rx: TracingUnboundedReceiver<WorkerCommand>) -> Self {
        let keygen_db_mtx = Arc::new(RwLock::new(HashMap::new()));
        let sign_db_mtx = Arc::new(RwLock::new(HashMap::new()));
        let keygen_ids = Arc::new(RwLock::new(HashMap::new()));
        let sign_ids = Arc::new(RwLock::new(HashMap::new()));
        let (low_sender, low_receiver) = tracing_unbounded("mpsc_mission_worker");
        let low_sender = Arc::new(Mutex::new(low_sender));
        Worker {
            keygen_db_mtx,
            sign_db_mtx,
            keygen_ids,
            sign_ids,
            low_sender,
            low_receiver,
            gossip_engine,
            command_rx,
            messages: HashSet::new(),
            // counter: 0,
            // start_time: SystemTime::now()
        }
    }

    fn handle_worker_command(&mut self, command: WorkerCommand) {
        match command {
            // run missions
            WorkerCommand::Keygen(index, store, n, t) => {
                use async_std::future;
                let time = Duration::from_secs(30);
                let mission_param = MissionParam {
                    index,
                    store,
                    n,
                    t,
                };
                let mission = async_std::task::spawn(gg20_keygen_client(
                        self.low_sender.clone(),
                        self.keygen_db_mtx.clone(),
                        self.keygen_ids.clone(),
                        mission_param
                    ));
                // TODO: return the result to chain
                let _res = future::timeout(time, mission).map_err(|e|{});
            },
            WorkerCommand::Sign(index, store, n, t) => {
                use async_std::future;
                let time = Duration::from_secs(30);
                let mission_param = MissionParam {
                    index,
                    store,
                    n,
                    t,
                };
                let mission = async_std::task::spawn(gg20_sign_client(
                    self.low_sender.clone(),
                    self.keygen_db_mtx.clone(),
                    self.keygen_ids.clone(),
                    mission_param
                ));
                // TODO: return the result to chain
                let _res = future::timeout(time, mission).map_err(|e|{});
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
                            GossipMessage::Keygen(data) => {
                                let entry: Entry = serde_json::from_str(&data).unwrap();
                                loop {
                                    if let Ok(mut db) = self.keygen_db_mtx.try_write() {
                                        db.insert(entry.key.clone(), entry.value.clone());
                                        break;
                                    }
                                }
                            },
                            GossipMessage::Sign(data) => {
                                let entry: Entry = serde_json::from_str(&data).unwrap();
                                loop {
                                    if let Ok(mut db) = self.sign_db_mtx.try_write() {
                                        db.insert(entry.key.clone(), entry.value.clone());
                                        break;
                                    }
                                }
                            },
                            GossipMessage::KeygenNotify(data) => {
                                let entry: Entry = serde_json::from_str(&data).unwrap();
                                let index = entry.key.clone().as_str().split('-').pop().parse::<u64>();
                                let data: Vec<u8> = serde_json::from_str(&entry.value).unwrap();
                                loop {
                                    if let Ok(mut db) = self.keygen_ids.try_write() {
                                        let vv = *db.get(index).unwrap().clone();
                                        vv.insert(index, data.clone());
                                        db.insert(index, vv);
                                        break;
                                    }
                                }
                            },
                            GossipMessage::SignNotify(data) => {
                                let entry: Entry = serde_json::from_str(&data).unwrap();
                                let index = entry.key.clone().as_str().split('-').pop().parse::<u64>();
                                let data: Vec<u8> = serde_json::from_str(&entry.value).unwrap();
                                loop {
                                    if let Ok(mut db) = self.sign_ids.try_write() {
                                        let vv = *db.get(index).unwrap().clone();
                                        vv.insert(index, data.clone());
                                        db.insert(index, vv);
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

    // let telemetry_task = if let Some(telemetry_on_connect) = telemetry_on_connect {
    //     let events = future::ready(());
    //     future::Either::Left(events)
    // } else {
    //     future::Either::Right(future::pending())
    // };

    let work = TssWork::new(
        command_rx,
        network,
    );

    let work = work.map(|res| match res {
        Ok(()) => error!(target: "afg", "tss work future has concluded naturally, this should be unreachable."),
        Err(e) => error!(target: "afg", "tss work error: {:?}", e),
    });

    // // Make sure that `telemetry_task` doesn't accidentally finish and kill tss.
    // let telemetry_task = telemetry_task
    //     .then(|_| future::pending::<()>());

    let listener = start_listener(client, pool, command_tx, keystore).then(|_| future::pending::<()>());

    Ok(future::select(work, listener).map(drop))
}

/// A trait that includes all the client functionalities tss requires.
/// Ideally this would be a trait alias, we're not there yet.
/// tracking issue https://github.com/rust-lang/rust/issues/41517
pub trait ClientForTss<Block, BE>:
LockImportRun<Block, BE> + Finalizer<Block, BE> + AuxStore
+ HeaderMetadata<Block, Error = sp_blockchain::Error> + HeaderBackend<Block>
+ BlockchainEvents<Block> + ProvideRuntimeApi<Block> + ExecutorProvider<Block>
+ BlockImport<Block, Transaction = TransactionFor<BE, Block>, Error = sp_consensus::Error>
    where
        BE: Backend<Block>,
        Block: BlockT,
{}

impl<Block, BE, T> ClientForTss<Block, BE> for T
    where
        BE: Backend<Block>,
        Block: BlockT,
        T: LockImportRun<Block, BE> + Finalizer<Block, BE> + AuxStore
        + HeaderMetadata<Block, Error = sp_blockchain::Error> + HeaderBackend<Block>
        + BlockchainEvents<Block> + ProvideRuntimeApi<Block> + ExecutorProvider<Block>
        + BlockImport<Block, Transaction = TransactionFor<BE, Block>, Error = sp_consensus::Error>,
{}