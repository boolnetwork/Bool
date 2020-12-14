
use std::{sync::Arc};
use sp_runtime::{
    generic::{BlockId ,Era},
    traits::{Block as BlockT, Zero}
};
use sp_api::{ProvideRuntimeApi, CallApiAt};
//use sc_keystore::KeyStorePtr;
use parking_lot::Mutex;
use sp_core::Pair;
use sp_core::sr25519::Pair as edPair;
pub use sp_core::sr25519;
use sp_core::ecdsa;
use sc_client_api::{BlockchainEvents};

use futures::prelude::*;
use futures::executor::block_on;

use log::{debug, info};

use sp_blockchain::{HeaderBackend};

use parity_scale_codec::{Encode, Decode};

use sp_transaction_pool::{TransactionPool, TransactionFor};

use bool_runtime::{
    UncheckedExtrinsic ,Call, SignedPayload
};

use frame_system::{Call as SystemCall};
use pallet_tss::{Call as TssCall};

pub use bool_primitives::{AccountId, Signature, Balance, Index};
use sp_core::storage::{StorageKey, StorageData};
use sc_client_api::notifications::{StorageEventStream};

use sp_core::twox_128;
use std::marker::PhantomData;
use sc_client_api::backend;
use sc_block_builder::{BlockBuilderProvider};
use sc_keystore::KeyStorePtr;
use bool_runtime::{Event, Runtime } ;
use bool_primitives::Hash;
use frame_system::EventRecord;

use pallet_tss::{RawEvent};
use sp_utils::mpsc::{TracingUnboundedSender};

use futures::channel::mpsc;

#[derive(Debug, Clone)]
pub enum WorkerCommand {
    Keygen(u64, Vec<u8>, u16, u16),
    Sign(u64, Vec<u8>, u16, u16, Vec<u8>)
}

pub enum TssRole{
    Manager,
    Party,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TxType {
    Spv,
    System,
    TssKeyGen(Vec<u8>,Vec<Vec<u8>>),
    TssSign(Vec<u8>,Vec<Vec<u8>>),
}

#[derive(Debug, Clone)]
pub struct TxMessage {
    pub tx_type: TxType
}

impl TxMessage{
    pub fn new(data: TxType) -> Self{
        TxMessage{
            tx_type: data
        }
    }
}

trait PrefixKey {
    fn as_prefix_key(&self) -> Vec<u8>;
}

impl PrefixKey for [u8] {
    fn as_prefix_key(&self) -> Vec<u8> {
        let mut key = [0u8;32];
        let mut items = self.split(|spa| *spa == b' ');
        if let Some(module) = items.next() {
            key[0..16].copy_from_slice(&twox_128(module));
        }
        if let Some(name) = items.next() {
            key[16..].copy_from_slice(&twox_128(name));
        }
        key.to_vec()
    }
}

pub struct PacketNonce<B>
    where
        B: BlockT,
{
    pub nonce: u64, // to control nonce.
    pub last_block: BlockId<B>,
}

impl <B>PacketNonce<B>
    where
        B: BlockT,
{
    pub fn new() -> PacketNonce<B>{
        PacketNonce{
            nonce:0,
            last_block: BlockId::number(0.into()),
        }
    }
}

pub trait SuperviseClient<B>
    where
        B:BlockT
{
    fn get_notification_stream(&self,filter_keys: Option<&[StorageKey]>,
                               child_filter_keys: Option<&[(StorageKey, Option<Vec<StorageKey>>)]>) -> StorageEventStream<B::Hash>;
    // fn is_tss_party(&self) -> bool;
    //
    // fn submit(&self, message: TxMessage);
}

#[derive( Clone)]
pub struct TxSender<A,Block,B,C>
    where
        A: TransactionPool<Block = Block> + 'static,
        Block: BlockT,
        B: backend::Backend<Block> + Send + Sync + 'static,
    //C: BlockchainEvents<Block> + HeaderBackend<Block> + ProvideRuntimeApi<Block>,
        C: BlockBuilderProvider<B, Block, C> + HeaderBackend<Block> + ProvideRuntimeApi<Block> + BlockchainEvents<Block>
        + CallApiAt<Block> + Send + Sync + 'static,
        Block::Hash: Into<sp_core::H256>
{
    pub client: Arc<C>,
    pub tx_pool: Arc<A>,
    //pub key : KeyStorePtr,
    pub ed_key: edPair,
    pub packet_nonce: Arc<Mutex<PacketNonce<Block>>>,
    _phantom: PhantomData<B>,
}

impl<A,Block,B,C> TxSender<A,Block,B,C>
    where
        A: TransactionPool<Block = Block> + 'static,
        B: backend::Backend<Block> + Send + Sync + 'static,
        Block: BlockT,
        C: BlockBuilderProvider<B, Block, C> + HeaderBackend<Block> + ProvideRuntimeApi<Block> + BlockchainEvents<Block>
        + CallApiAt<Block> + Send + Sync + 'static,
        Block::Hash: Into<sp_core::H256>
{
    pub fn new(client:Arc<C>,tx_pool:Arc<A> /*,key:KeyStorePtr*/
               ,ed_key:edPair,packet_nonce:Arc<Mutex<PacketNonce<Block>>>) -> Self{
        TxSender{
            client:client,
            tx_pool:tx_pool,
            ed_key: ed_key,
            packet_nonce:packet_nonce,
            _phantom: PhantomData,
        }
    }

    // fn get_nonce(&self) -> u64 {
    //     let mut p_nonce = self.packet_nonce.lock();
    //     let info = self.client.info();
    //     let at: BlockId<Block> = BlockId::Hash(info.best_hash);
    //
    //     if p_nonce.last_block == at {
    //         p_nonce.nonce = p_nonce.nonce + 1;
    //     } else {
    //         p_nonce.nonce = self
    //             .client
    //             .runtime_api()
    //             .account_nonce(&at, &self.ed_key.public().0.into())
    //             .unwrap();
    //         p_nonce.last_block = at;
    //     }
    //
    //     p_nonce.nonce
    // }
}

impl<A,Block,B,C> SuperviseClient<Block> for TxSender<A,Block,B,C>
    where
        A: TransactionPool<Block = Block> + 'static,
        Block: BlockT,
        B: backend::Backend<Block> + Send + Sync + 'static,
        C: BlockBuilderProvider<B, Block, C> + HeaderBackend<Block> + ProvideRuntimeApi<Block> + BlockchainEvents<Block>
        + CallApiAt<Block> + Send + Sync + 'static,
        Block::Hash: Into<sp_core::H256>
{
    fn get_notification_stream(&self, filter_keys: Option<&[StorageKey]>,
                               child_filter_keys: Option<&[(StorageKey, Option<Vec<StorageKey>>)]>) -> StorageEventStream<Block::Hash> {
        self.client.storage_changes_notification_stream(filter_keys, child_filter_keys)
            .unwrap()
    }

    // fn is_tss_party(&self) -> bool {
    //     let info = self.client.info();
    //     let at: BlockId<Block> = BlockId::Hash(info.best_hash);
    //
    //     self.client
    //         .runtime_api()
    //         .is_tss_party(&at, &self.ed_key.public().0.into())
    //         .unwrap()
    // }

    // fn submit(&self, relay_message: TxMessage) {
    //     let local_id: AccountId = self.ed_key.public().0.into();
    //     let info = self.client.info();
    //     let at = BlockId::Hash(info.best_hash);
    //     {
    //         let nonce = self.get_nonce();
    //
    //         let function = match relay_message.tx_type {
    //             TxType::TssKeyGen(tss_pubkey, pk_vec) => Call::Tss(TssCall::key_created_result_is(tss_pubkey, pk_vec, vec![0u8])),
    //             TxType::TssSign(tss_pubkey, pk_vec) => Call::Tss(TssCall::key_created_result_is_bool(tss_pubkey, pk_vec, vec![0u8])),
    //             TxType::System => Call::System(SystemCall::remark(vec![1u8])),
    //             _ => Call::System(SystemCall::remark(vec![1u8])),
    //         };
    //
    //         let extra = |i: Index, f: Balance| {
    //             (
    //                 frame_system::CheckSpecVersion::<Runtime>::new(),
    //                 frame_system::CheckTxVersion::<Runtime>::new(),
    //                 frame_system::CheckGenesis::<Runtime>::new(),
    //                 frame_system::CheckEra::<Runtime>::from(Era::Immortal),
    //                 frame_system::CheckNonce::<Runtime>::from(i),
    //                 frame_system::CheckWeight::<Runtime>::new(),
    //                 pallet_transaction_payment::ChargeTransactionPayment::<Runtime>::from(f),
    //                 //Default::default(),
    //             )
    //         };
    //         let genesis_hash = self.client.hash(Zero::zero())
    //             .expect("Genesis block always exists; qed").unwrap().into();
    //         let version = self.client.runtime_version_at(&at).unwrap();
    //         let raw_payload = SignedPayload::from_raw(
    //             function,
    //             extra(nonce as u32, 0),
    //             (
    //                 version.spec_version,
    //                 version.transaction_version,
    //                 genesis_hash,
    //                 genesis_hash,
    //                 (),
    //                 (),
    //                 (),
    //             ),
    //         );
    //         let signature = raw_payload.using_encoded(|payload| self.ed_key.sign(payload));
    //         let (function, extra, _) = raw_payload.deconstruct();
    //
    //         let extrinsic =
    //             UncheckedExtrinsic::new_signed(function, local_id.into(), signature.into(), extra);
    //         let xt: TransactionFor<A> = Decode::decode(&mut &extrinsic.encode()[..]).unwrap();
    //         debug!(target: "witness", "extrinsic {:?}", xt);
    //         let source = sp_runtime::transaction_validity::TransactionSource::External;
    //         let result = block_on(self.tx_pool.submit_one(&at, source, xt));
    //         info!("SuperviseClient submit transaction {:?}", result);
    //     }
    // }
}

#[derive(Debug, Clone)]
pub struct TssSender<V,B> {
    pub spv: V,
    pub command_tx: TracingUnboundedSender<WorkerCommand>,
    pub a: std::marker::PhantomData<B>,
    pub mission_counter: Arc<Mutex<u64>>,
}

impl <V,B>TssSender<V,B>
    where   V: SuperviseClient<B> + Send + Sync + 'static,
            B: BlockT,
{
    pub fn new(spv: V, command_tx: TracingUnboundedSender<WorkerCommand>) -> Self {
        TssSender {
            spv: spv,
            command_tx,
            a: PhantomData,
            mission_counter: Arc::new(Mutex::new(0)),
        }
    }

    fn set_counter(&mut self, index: u64) {
        *self.mission_counter.lock() = index;
    }

    fn key_gen(&self, index: u64, store: Vec<u8>, n: u16, t: u16){
        self.command_tx.unbounded_send(WorkerCommand::Keygen(index, store, n, t)).expect("send command failed");
    }

    fn key_sign(&self, index: u64, store: Vec<u8>, n: u16, t: u16, message_str: Vec<u8>) {
        self.command_tx.unbounded_send(WorkerCommand::Sign(index, store, n, t, message_str)).expect("send command failed");
    }

    fn get_stream(&self, events_key:StorageKey) -> StorageEventStream<B::Hash> {
        self.spv.get_notification_stream(Some(&[events_key]), None)
    }

    pub fn start(mut self, _role: TssRole) -> impl Future<Output=()> + Send + 'static {
        let events_key = StorageKey(b"System Events".as_prefix_key());

        let storage_stream: StorageEventStream<B::Hash> = self.get_stream(events_key);

        let storage_stream = storage_stream
            .for_each( move|(_blockhash,change_set)| {
                let records: Vec<Vec<EventRecord<Event, Hash>>> = change_set
                    .iter()
                    .filter_map(|(_ , _, mbdata)| {
                        if let Some(StorageData(data)) = mbdata {
                            Decode::decode(&mut &data[..]).ok()
                        } else {
                            None
                        }
                    })
                    .collect();
                let events: Vec<Event> = records.concat().iter().cloned().map(|r| r.event).collect();
                events.iter().for_each(|event| {
                    // debug!(target:"keysign", "Event {:?}", event);
                    if let Event::pallet_tss(e) = event {
                        match e {
                            RawEvent::GenKey(index, store, n, t, _time) => {
                                if *self.mission_counter.lock() != *index {
                                    self.key_gen(*index, (*store).to_vec(), *n, *t);
                                    self.set_counter(*index);
                                }
                            },
                            RawEvent::Sign(index, store, n, t, message_str, _time) => {
                                if *self.mission_counter.lock() != *index {
                                    self.key_sign(*index, (*store).to_vec(), *n, *t, (*message_str).to_vec());
                                    self.set_counter(*index);
                                }
                            },
                            _ => {}
                        }
                    }
                });
                futures::future::ready(())
            });
        storage_stream
    }
}

