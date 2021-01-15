
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
use sc_client_api::{BlockchainEvents};

use futures::prelude::*;
use log::info;
use sp_blockchain::{HeaderBackend};
use parity_scale_codec::{Encode, Decode};
use sp_transaction_pool::{TransactionPool, TransactionFor};
use bool_runtime::{
    UncheckedExtrinsic , apis::VendorApi, Call, SignedPayload
};
// use frame_system::{Call as SystemCall};
use pallet_thresh::{Call as ThreshCall};
pub use bool_primitives::{AccountId, Signature, Balance, Index};
pub use sp_core::storage::{StorageKey, StorageData};
pub use sc_client_api::notifications::{StorageEventStream};
use sp_core::twox_128;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Poll, Context};
use sc_client_api::backend;
use sc_block_builder::{BlockBuilderProvider};
use bool_runtime::{Event, Runtime } ;
use bool_primitives::Hash;
use frame_system::EventRecord;
use pallet_thresh::{RawEvent, ThreshMode, ThreshPublic, SignResult, ErrorType};
use sp_utils::mpsc::{TracingUnboundedSender, TracingUnboundedReceiver};
use crate::communicate::Error;

#[derive(Clone, PartialEq, Debug, Encode, Decode)]
pub enum RType {
    Success(Vec<u8>),
    Failed(ErrorType<AccountId>),
}

#[derive(Clone, PartialEq, Debug, Encode, Decode)]
pub enum MType {
    Keygen,
    Sign
}

#[derive(Clone, PartialEq, Debug, Encode, Decode)]
pub struct MissionResult {
    // who: AccountId,
    pub mtype: MType,
    pub rtype: RType,
    pub message: Vec<u8>
}

impl MissionResult {
    pub fn new(mtype: MType, rtype: RType, message: Vec<u8>) -> Self {
        MissionResult {
            mtype, rtype, message
        }
    }
}

#[derive(Debug, Clone)]
pub enum WorkerCommand {
    Keygen(u32, Vec<u8>, u16, u16, Vec<AccountId>, AccountId),
    Sign(u32, Vec<u8>, u16, u16, Vec<u8>, Vec<AccountId>, AccountId)
}

#[derive(Debug, Clone)]
pub struct TxMessage {
    pub index: u32,
    pub result: MissionResult
}

impl TxMessage{
    pub fn new(index: u32, result: MissionResult) -> Self{
        TxMessage{
            index,
            result
        }
    }
}

pub trait PrefixKey {
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
    where B: BlockT,
{
    pub nonce: u64, // to control nonce.
    pub last_block: BlockId<B>,
}

impl<B> PacketNonce<B>
    where B: BlockT,
{
    pub fn new() -> PacketNonce<B>{
        PacketNonce{
            nonce:0,
            last_block: BlockId::number(0.into()),
        }
    }
}

pub trait SuperviseClient<B>
    where B: BlockT
{
    fn get_notification_stream(&self,filter_keys: Option<&[StorageKey]>,
                               child_filter_keys: Option<&[(StorageKey, Option<Vec<StorageKey>>)]>) -> StorageEventStream<B::Hash>;
    // fn is_tss_party(&self) -> bool;
    //
    fn submit(&self, message: TxMessage);

    fn get_account_id(&self) -> AccountId;
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
        C::Api: VendorApi<Block>,
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
        C::Api: VendorApi<Block>,
        Block::Hash: Into<sp_core::H256>
{
    pub fn new(
        client:Arc<C>,tx_pool:Arc<A> /*,key:KeyStorePtr*/,
        ed_key:edPair,packet_nonce:Arc<Mutex<PacketNonce<Block>>>
    ) -> Self{
        TxSender{
            client: client,
            tx_pool: tx_pool,
            ed_key: ed_key,
            packet_nonce: packet_nonce,
            _phantom: PhantomData,
        }
    }

    fn get_nonce(&self) -> u64 {
        let mut p_nonce = self.packet_nonce.lock();
        let info = self.client.info();
        let at: BlockId<Block> = BlockId::Hash(info.best_hash);

        if p_nonce.last_block == at {
            p_nonce.nonce = p_nonce.nonce + 1;
        } else {
            p_nonce.nonce = self
                .client
                .runtime_api()
                .account_nonce(&at, &self.ed_key.public().0.into())
                .unwrap();
            p_nonce.last_block = at;
        }

        p_nonce.nonce
    }
}

impl<A,Block,B,C> SuperviseClient<Block> for TxSender<A,Block,B,C>
    where
        A: TransactionPool<Block = Block> + 'static,
        Block: BlockT,
        B: backend::Backend<Block> + Send + Sync + 'static,
        C: BlockBuilderProvider<B, Block, C> + HeaderBackend<Block> + ProvideRuntimeApi<Block> + BlockchainEvents<Block>
        + CallApiAt<Block> + Send + Sync + 'static,
        C::Api: VendorApi<Block>,
        Block::Hash: Into<sp_core::H256>
{
    fn get_notification_stream(&self, filter_keys: Option<&[StorageKey]>,
                               child_filter_keys: Option<&[(StorageKey, Option<Vec<StorageKey>>)]>) -> StorageEventStream<Block::Hash> {
        self.client.storage_changes_notification_stream(filter_keys, child_filter_keys)
            .unwrap()
    }

    fn submit(&self, relay_message: TxMessage) {
        let local_id: AccountId = self.ed_key.public().0.into();
        let info = self.client.info();
        let at = BlockId::Hash(info.best_hash);
        {
            let nonce = self.get_nonce();

            let function = match relay_message.result.mtype.clone() {
                MType::Keygen => {
                    match relay_message.result.rtype.clone() {
                        RType::Success(s) => {
                            Call::Thresh(ThreshCall::group(relay_message.index, ThreshPublic::new(s), Vec::new()))
                        },
                        RType::Failed(e) => {
                            Call::Thresh(ThreshCall::group_error(relay_message.index, e, Vec::new()))
                        }
                    }
                },
                MType::Sign => {
                    match relay_message.result.rtype.clone() {
                        RType::Success(s) => {
                            Call::Thresh(ThreshCall::sign(relay_message.index, relay_message.result.message, SignResult::new(s), Vec::new()))
                        },
                        RType::Failed(e) => {
                            Call::Thresh(ThreshCall::sign_error(relay_message.index, relay_message.result.message, e, Vec::new()))
                        }
                    }
                }
            };

            let extra = |i: Index, f: Balance| {
                (
                    frame_system::CheckSpecVersion::<Runtime>::new(),
                    frame_system::CheckTxVersion::<Runtime>::new(),
                    frame_system::CheckGenesis::<Runtime>::new(),
                    frame_system::CheckEra::<Runtime>::from(Era::Immortal),
                    frame_system::CheckNonce::<Runtime>::from(i),
                    frame_system::CheckWeight::<Runtime>::new(),
                    pallet_transaction_payment::ChargeTransactionPayment::<Runtime>::from(f),
                    //Default::default(),
                )
            };
            let genesis_hash = self.client.hash(Zero::zero())
                .expect("Genesis block always exists; qed").unwrap().into();
            let version = self.client.runtime_version_at(&at).unwrap();
            let raw_payload = SignedPayload::from_raw(
                function,
                extra(nonce as u32, 0),
                (
                    version.spec_version,
                    version.transaction_version,
                    genesis_hash,
                    genesis_hash,
                    (),
                    (),
                    (),
                ),
            );
            let signature = raw_payload.using_encoded(|payload| self.ed_key.sign(payload));
            let (function, extra, _) = raw_payload.deconstruct();

            let extrinsic =
                UncheckedExtrinsic::new_signed(function, local_id.into(), signature.into(), extra);
            let xt: TransactionFor<A> = Decode::decode(&mut &extrinsic.encode()[..]).unwrap();
            // debug!(target: "witness", "extrinsic {:?}", xt);
            let source = sp_runtime::transaction_validity::TransactionSource::External;
            let result = async_std::task::spawn(self.tx_pool.submit_one(&at, source, xt));
            info!("SuperviseClient submit transaction {:?}", result);
        }
    }

    fn get_account_id(&self) -> AccountId {
        self.ed_key.public().0.into()
    }
}

#[derive(Debug)]
pub struct TssSender<V, B>
    where   V: SuperviseClient<B> + Send + Sync + 'static,
            B: BlockT,
{
    pub spv: V,
    pub command_tx: TracingUnboundedSender<WorkerCommand>,
    pub result_rx: TracingUnboundedReceiver<(u32, MissionResult)>,
    pub a: std::marker::PhantomData<B>,
    pub storage_stream: StorageEventStream<B::Hash>
}

impl <V, B>TssSender<V,B>
    where   V: SuperviseClient<B> + Send + Sync + 'static,
            B: BlockT,
{
    pub fn new(spv: V, command_tx: TracingUnboundedSender<WorkerCommand>,
               result_rx: TracingUnboundedReceiver<(u32, MissionResult)>,
               storage_stream: StorageEventStream<B::Hash>
    ) -> Self {
        TssSender {
            spv: spv,
            command_tx,
            result_rx,
            a: PhantomData,
            storage_stream
        }
    }

    fn key_gen(&self, index: u32, store: Vec<u8>, mode: ThreshMode, partners: Vec<AccountId>, local_id: AccountId){
        self.command_tx.unbounded_send(WorkerCommand::Keygen(index, store, mode.n, mode.t, partners, local_id))
            .expect("send command failed");
    }

    fn key_sign(&self, index: u32, store: Vec<u8>, mode: ThreshMode, message_str: Vec<u8>, partners: Vec<AccountId>, local_id: AccountId) {
        self.command_tx.unbounded_send(WorkerCommand::Sign(index, store, mode.n, mode.t, message_str, partners, local_id))
            .expect("send command failed");
    }
}

impl<V, B> Future for TssSender<V,B>
    where   V: SuperviseClient<B> + Send + Sync + 'static,
            B: BlockT,
{
    type Output = Result<(), Error>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        match Stream::poll_next(Pin::new(&mut self.storage_stream), cx) {
            Poll::Pending => {},
            Poll::Ready(None) => {
                return Poll::Ready(
                    Err(Error::Safety("`storage_stream` was closed.".into()))
                )
            },
            Poll::Ready(Some((_blockhash,change_set))) => {
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
                let mut events = events.iter().cloned();
                loop {
                    match events.next() {
                        Some(event) => {
                            if let Event::pallet_thresh(e) = event {
                                match e {
                                    RawEvent::TryGroup(index, mode, partners) => {
                                        let local_id: AccountId = self.spv.get_account_id();
                                        if contains_id(partners.clone(), local_id.clone()) {
                                            let store = format!("key{}.store", index).as_bytes().to_vec();
                                            self.key_gen(index, store, mode, partners, local_id);
                                        }
                                    },
                                    RawEvent::TrySign(index, mode, message_str, partners) => {
                                        let local_id: AccountId = self.spv.get_account_id();
                                        if contains_id(partners.clone(), local_id.clone()) {
                                            let store = format!("key{}.store", index).as_bytes().to_vec();
                                            self.key_sign(index, store, mode, (*message_str).to_vec(), partners, local_id);
                                        }
                                    },
                                    _ => ()
                                }
                            }
                        },
                        None => break,
                    }
                }
            }
        }

        match Stream::poll_next(Pin::new(&mut self.result_rx), cx) {
            Poll::Pending => {},
            Poll::Ready(None) => {
                return Poll::Ready(
                    Err(Error::Safety("`result_rx` was closed.".into()))
                )
            },
            Poll::Ready(Some((index, result))) => {
                let tx_message = TxMessage::new(index, result);
                self.spv.submit(tx_message);
            },
        }

        Poll::Pending
    }
}

impl<V, B> Unpin for TssSender<V, B>
    where   V: SuperviseClient<B> + Send + Sync + 'static,
            B: BlockT,
{}

pub fn contains_id(vec: Vec<AccountId>, local_id: AccountId) -> bool {
    for id in vec.clone() {
        if local_id == id { return true; }
    }
    false
}