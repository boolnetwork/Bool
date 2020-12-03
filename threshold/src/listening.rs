
use std::{sync::Arc, u64};

use sp_runtime::{
    generic::{BlockId ,Era},
    traits::{Block as BlockT, Zero}
};
use sp_api::{ProvideRuntimeApi, CallApiAt};
//use sc_keystore::KeyStorePtr;
use parking_lot::Mutex;
use sp_core::Pair;
use sp_core::sr25519::Pair as edPair;
use sp_core::sr25519;
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
// use pallet_tss::{Call as TssCall};

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
use std::thread;
use sp_utils::mpsc::{TracingUnboundedSender};

use futures::channel::mpsc;

#[derive(Debug, Clone)]
pub enum WorkerCommand {
    Keygen(u64, Vec<u8>, u64, u64),
    Sign(u64, Vec<u8>, u64, u64)
}

pub enum TssRole{
    Manager,
    Party,
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
    //             TxType::System => Call::System(SystemCall::remark(vec![1u8])),
    //             TxType::TssKeyGen(tss_pubkey, pk_vec) => Call::Tss(TssCall::key_created_result_is(tss_pubkey, pk_vec, vec![0u8])),
    //             TxType::TssKeyGenBool(tss_pubkey, pk_vec) => Call::Tss(TssCall::key_created_result_is_bool(tss_pubkey, pk_vec, vec![0u8])),
    //             TxType::TssKeyGenFc(tss_pubkey, pk_vec) => Call::Tss(TssCall::key_created_result_is_fc(tss_pubkey, pk_vec, vec![0u8])),
    //             TxType::BtcAddressSet(tss_pubkey) => Call::BtcBridge(BtcBridgeCall::set_tss_revice_address(tss_pubkey)),
    //             TxType::Signature(signed_btc_tx) => Call::BtcBridge(BtcBridgeCall::put_signedbtctxproposal(signed_btc_tx)),
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
    pub tss: u64,
    pub command_tx: TracingUnboundedSender<WorkerCommand>,
    pub a: std::marker::PhantomData<B>,
}

impl <V,B>TssSender<V,B>
    where   V: SuperviseClient<B> + Send + Sync + 'static,
            B: BlockT,
{
    pub fn new(spv: V, command_tx: TracingUnboundedSender<WorkerCommand>) -> Self {
        TssSender {
            spv: spv,
            tss: 5,
            command_tx,
            a: PhantomData,
        }
    }

    fn key_gen(&self, index: u64, store: Vec<u8>, n: u64, t: u64){
        let store2 = "boolbtc.store";
        // TODO: need return result in the future
        // match key_gen(store2){
        //     Ok((pk,pk_vec)) => {
        //         let data = TxMessage::new(TxType::TssKeyGen(pk.to_vec(),pk_vec));
        //         self.submit_tx(data);
        //         let data2 = TxMessage::new(TxType::BtcAddressSet(pk.to_vec()));
        //         self.submit_tx(data2);
        //         set_pubkey(pk.to_vec(),store2);
        //     },
        //     _ => return ,
        // }
        self.command_tx.unbounded_send(WorkerCommand::Keygen(index, store, n, t));
    }

    fn key_sign(&self, index: u64, store: Vec<u8>, n: u64, t: u64) /*-> Option<Vec<u8>>*/{
        // let pubkey = self.spv.tss_pubkey();
        // debug!(target:"keysign", "pubkey {:?}", pubkey);
        self.command_tx.unbounded_send(WorkerCommand::Sign(index, store, n, t));
    }

    fn get_stream(&self, events_key:StorageKey) -> StorageEventStream<B::Hash> {
        self.spv.get_notification_stream(Some(&[events_key]), None)
    }

    pub fn start(self, _role: TssRole) -> impl Future<Output=()> + Send + 'static {
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
                                self.key_gen(*index, *store, *n, *t);
                            },
                            RawEvent::Sign(index, store, n, t, _time) => {
                                self.key_sign(*index, *store, *n, *t);
                            },
                            _ => {}
                        }
                    }
                });
                futures::future::ready(())
            });
        storage_stream//.select(on_exit).then(|_| Ok(()))
    }
}

pub fn start_listener<A, B, C, Block>(
    client: Arc<C>,
    pool: Arc<A>,
    command_tx: TracingUnboundedSender<WorkerCommand>,
    _keystore: KeyStorePtr,
) -> impl Future<Output = ()> + Send + 'static
    where
        A: TransactionPool<Block = Block> + 'static,
        Block: BlockT,
        B: backend::Backend<Block> + Send + Sync + 'static,
        C: BlockBuilderProvider<B, Block, C> + HeaderBackend<Block> + ProvideRuntimeApi<Block> + BlockchainEvents<Block>
        + CallApiAt<Block> + Send + Sync + 'static,
        Block::Hash: Into<sp_core::H256>
{

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

    let tss_sender = TssSender::new(tx_sender, command_tx);

    tss_sender.start(TssRole::Party)
}
