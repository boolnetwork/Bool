
use futures::prelude::*;
use log::{error, info};
use sc_client_api::{backend::Backend, BlockchainEvents};
use sp_api::{ProvideRuntimeApi, CallApiAt};
use sp_blockchain::HeaderBackend;
use sp_core::Pair;
use sp_runtime::{generic::BlockId, traits::Block as BlockT};
use sp_transaction_pool::TransactionPool;
use sc_keystore::KeyStorePtr;
use sc_block_builder::BlockBuilderProvider;
use sc_network_gossip::GossipEngine;
use sp_utils::mpsc::{tracing_unbounded, TracingUnboundedReceiver, TracingUnboundedSender};
use parking_lot::Mutex;
use std::collections::{HashSet, HashMap};
use std::sync::{RwLock, Arc};
use std::time::SystemTime;
use std::pin::Pin;
use std::task::{Poll, Context};
use bool_runtime::apis::VendorApi;

mod communicate;
mod gossip;
mod gg20_keygen_client;
mod gg20_sign_client;
mod common;
mod listening;
use common::{GossipMessage, Key, Entry, MissionParam};
use gg20_keygen_client::{gg20_keygen_client};
use gg20_sign_client::{gg20_sign_client};
use communicate::{NetworkBridge, Error, Network as NetworkT};
use gossip::{get_topic};
use listening::{WorkerCommand, TssSender, TxSender, SuperviseClient, sr25519, PacketNonce,
                StorageKey, StorageEventStream, PrefixKey, MissionResult};

pub struct TssWork<Block: BlockT, N: NetworkT<Block>> {
    worker: Pin<Box<dyn Future<Output = Result<(), Error>> + Send>>,
    tss_sender: Pin<Box<dyn Future<Output = Result<(), Error>> + Send>>,
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
        result_sender: TracingUnboundedSender<(u32, MissionResult)>,
        tss_sender: Pin<Box<dyn Future<Output = Result<(), Error>> + Send>>,
    ) -> Self {
        let worker = Worker::new(
            network.gossip_engine.clone(),
            command_rx,
            result_sender
        );
        let worker = Box::pin(worker);
        TssWork {
            worker,
            tss_sender,
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

        match Future::poll(Pin::new(&mut self.tss_sender), cx) {
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
    low_sender: Arc<Mutex<TracingUnboundedSender<String>>>,
    low_receiver: TracingUnboundedReceiver<String>,
    gossip_engine: Arc<Mutex<GossipEngine<B>>>,
    command_rx: TracingUnboundedReceiver<WorkerCommand>,
    messages: HashSet<Vec<u8>>,
    result_sender: Arc<TracingUnboundedSender<(u32, MissionResult)>>,
}

impl<B: BlockT> Worker<B> {
    pub fn new(
        gossip_engine: Arc<Mutex<GossipEngine<B>>>,
        command_rx: TracingUnboundedReceiver<WorkerCommand>,
        result_sender: TracingUnboundedSender<(u32, MissionResult)>,
    ) -> Self {
        let db_mtx = Arc::new(RwLock::new(HashMap::new()));
        let (low_sender, low_receiver) = tracing_unbounded("mpsc_mission_worker");
        let low_sender = Arc::new(Mutex::new(low_sender));
        let result_sender = Arc::new(result_sender);
        Worker {
            db_mtx,
            low_sender,
            low_receiver,
            gossip_engine,
            command_rx,
            result_sender,
            messages: HashSet::new(),
        }
    }

    fn handle_worker_command(&mut self, command: WorkerCommand) {
        match command {
            // run missions
            WorkerCommand::Keygen(index, store, n, t, partners, local_id) => {
                let start_time = SystemTime::now();
                let mission_param = MissionParam { start_time, index, store, n, t, partners, local_id };
                async_std::task::spawn(
                    gg20_keygen_client(
                        self.low_sender.clone(),
                        self.db_mtx.clone(),
                        self.result_sender.clone(),
                        mission_param
                    ).map_err(|e|{ info!(target: "afg", "keygen mission failed: {:?}", e); })
                );
            },
            WorkerCommand::Sign(index, store, n, t, message_str, partners, local_id) => {
                let start_time = SystemTime::now();
                let mission_param = MissionParam { start_time, index, store, n, t, partners, local_id };
                let message_str = String::from_utf8_lossy(&message_str).into_owned();
                async_std::task::spawn(
                    gg20_sign_client(
                        self.low_sender.clone(),
                        self.db_mtx.clone(),
                        self.result_sender.clone(),
                        message_str,
                        mission_param
                    ).map_err(|e|{ info!(target: "afg", "sign mission failed: {:?}", e); })
                );
            },
        }
    }
}

impl<Block: BlockT> Future for Worker<Block> {
    type Output = Result<(), Error>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        match Stream::poll_next(Pin::new(&mut self.command_rx), cx) {
            Poll::Pending => {},
            Poll::Ready(None) => {
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
                            _ => ()
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
    B: Backend<Block> + Send + Sync + 'static + Unpin,
    C: BlockBuilderProvider<B, Block, C> + HeaderBackend<Block> + ProvideRuntimeApi<Block> + BlockchainEvents<Block>
    + CallApiAt<Block> + Send + Sync + 'static,
    C::Api: VendorApi<Block>,
{
    let TssParams {
        client,
        pool,
        network,
        keystore: _,
    } = params;
    let (command_tx, command_rx) = tracing_unbounded("mpsc_tss_command");
    let (result_tx, result_rx) = tracing_unbounded("mpsc_tss_result");
    // start listener
    let _sign_key = "2f2f416c69636508080808080808080808080808080808080808080808080808".to_string();
    let key = sr25519::Pair::from_string(&format!("//{}", "Eve"), None)
        .expect("static values are valid; qed");
    //let key_seed = sr25519::Pair::from_seed_slice(&[0x25,0xb4,0xfd,0x88,0x81,0x3f,0x5e,0x16,0xd4,0xbe,0xa6,0x28
    //	,0x39,0x02,0x89,0x57,0xf9,0xe3,0x40,0x10,0x8e,0x4e,0x93,0x73,0xd0,0x8b,0x31,0xb0,0xf6,0xe3,0x04,0x40]).unwrap();
    let info = client.info();
    let at = BlockId::Hash(info.best_hash);
    let tx_sender = TxSender::new(
        client,
        pool,
        key,
        Arc::new(parking_lot::Mutex::new(PacketNonce {nonce:0,last_block:at})),
    );
    let events_key = StorageKey(b"System Events".as_prefix_key());

    let storage_stream: StorageEventStream<Block::Hash> = tx_sender.get_notification_stream(Some(&[events_key]), None);

    let tss_sender = TssSender::new(tx_sender, command_tx, result_rx, storage_stream);

    //start work
    let network = NetworkBridge::new(network);
    let work = TssWork::new(
        command_rx,
        network,
        result_tx,
        Box::pin(tss_sender)
    );
    let work = work.map(|res| match res {
        Ok(()) => error!(target: "afg", "tss work future has concluded naturally, this should be unreachable."),
        Err(e) => error!(target: "afg", "tss work error: {:?}", e),
    });

    Ok(future::select(work, future::pending::<()>()).map(drop))
}

