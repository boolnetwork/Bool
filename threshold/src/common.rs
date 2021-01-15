use std::{iter::repeat, thread, time::{SystemTime, Duration}};

use crypto::{
    aead::{AeadDecryptor, AeadEncryptor},
    aes::KeySize::KeySize256,
    aes_gcm::AesGcm,
};
use curv::{
    arithmetic::traits::Converter,
    elliptic::curves::traits::{ECPoint, ECScalar},
    BigInt, FE, GE,
};
use sc_network::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{RwLock, Arc};
use parking_lot::{Mutex};
use sp_utils::mpsc::{TracingUnboundedSender};
pub use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::ErrorType;
use bool_primitives::AccountId;

pub type Key = String;

#[allow(dead_code)]
pub const AES_KEY_BYTES_LEN: usize = 32;

pub const TIME_LIMIT: Duration = Duration::from_secs(10);

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct AEAD {
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub enum GossipMessage {
    Chat(String),
    Notify(String),
}

#[derive(Clone, PartialEq, Debug)]
pub struct MissionParam {
    pub start_time: SystemTime,
    pub index: u32,
    pub store: Vec<u8>,
    pub n: u16,
    pub t: u16,
    pub partners: Vec<AccountId>,
    pub local_id: AccountId
}

#[derive(Clone, PartialEq, Debug)]
pub enum GossipType {
    Chat
}

// TODO: need more details
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub enum TssResult {
    KeygenResult(String),
    SignResult(String)
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Entry {
    pub key: Key,
    pub value: String,
}

#[derive(Serialize, Deserialize)]
pub struct Params {
    pub parties: String,
    pub threshold: String,
}

#[allow(dead_code)]
pub fn aes_encrypt(key: &[u8], plaintext: &[u8]) -> AEAD {
    let nonce: Vec<u8> = repeat(3).take(12).collect();
    let aad: [u8; 0] = [];
    let mut gcm = AesGcm::new(KeySize256, key, &nonce[..], &aad);
    let mut out: Vec<u8> = repeat(0).take(plaintext.len()).collect();
    let mut out_tag: Vec<u8> = repeat(0).take(16).collect();
    gcm.encrypt(&plaintext[..], &mut out[..], &mut out_tag[..]);
    AEAD {
        ciphertext: out.to_vec(),
        tag: out_tag.to_vec(),
    }
}

#[allow(dead_code)]
pub fn aes_decrypt(key: &[u8], aead_pack: AEAD) -> Vec<u8> {
    let mut out: Vec<u8> = repeat(0).take(aead_pack.ciphertext.len()).collect();
    let nonce: Vec<u8> = repeat(3).take(12).collect();
    let aad: [u8; 0] = [];
    let mut gcm = AesGcm::new(KeySize256, key, &nonce[..], &aad);
    gcm.decrypt(&aead_pack.ciphertext[..], &mut out, &aead_pack.tag[..]);
    out
}

#[allow(dead_code)]
pub fn broadcast_data(
    tx: Arc<Mutex<TracingUnboundedSender<String>>>,
    party_num_int: u16,
    round: &str,
    index: u32,
    data: String,
    ty: GossipType
) {
    let key = format!("{}-{}-{}", party_num_int, round, index);
    let entry: Entry = Entry{
        key,
        value: data,
    };
    let data = serde_json::to_string(&entry).unwrap();
    let data = match ty {
        GossipType::Chat => GossipMessage::Chat(data),
    };
    let data = serde_json::to_string(&data).unwrap();
    assert!(tx.lock().unbounded_send(data).is_ok());
}

#[allow(dead_code)]
pub fn sendp2p_data(
    tx: Arc<Mutex<TracingUnboundedSender<String>>>,
    party_from: u16,
    party_to: u16,
    round: &str,
    index: u32,
    data: String,
    ty: GossipType
) {
    let key = format!("{}-{}-{}-{}", party_from, party_to, round, index);
    let entry: Entry = Entry{
        key,
        value: data,
    };
    let data = serde_json::to_string(&entry).unwrap();
    let data = match ty {
        GossipType::Chat => GossipMessage::Chat(data),
    };
    let data = serde_json::to_string(&data).unwrap();
    assert!(tx.lock().unbounded_send(data).is_ok());
}
#[allow(dead_code)]
pub fn get_data_broadcasted(
    db_mtx: Arc<RwLock<HashMap<Key, String>>>,
    party_num: u16,
    n: u16,
    delay: Duration,
    round: &str,
    index: u32,
    start_time: SystemTime
) -> Result<Vec<String>, ErrorType> {
    let mut ans_vec: Vec<String> = Vec::new();
    for i in 1..=n {
        if i != party_num {
            let key = format!("{}-{}-{}", i, round, index);
            loop {
                {
                    let db = db_mtx.read().unwrap();
                    // timeout handle
                    if time_check_out(start_time, TIME_LIMIT) {
                        let mut err_res: Vec<usize> = Vec::new();
                        for i in 1..=n {
                            if i != party_num {
                                let key = format!("{}-{}-{}", i, round, index);
                                if let None = db.get(&key) { err_res.push(i.into()); }
                            }
                        }
                        let error_type = format!("index-{}-{}-timeout", index, round).to_string();
                        return Err(ErrorType::new(error_type, err_res));
                    }
                    // normal handle
                    if let Some(data) = db.get(&key) {
                        let da: String = (*data).clone().to_string();
                        ans_vec.push(da);
                        // println!("[{:?}] party {:?} => party {:?}", round, i, party_num);
                        break;
                    }
                }
                thread::sleep(delay);
            }
        }
    }
    Ok(ans_vec)
}
#[allow(dead_code)]
pub fn get_data_p2p(
    db_mtx: Arc<RwLock<HashMap<Key, String>>>,
    party_num: u16,
    n: u16,
    delay: Duration,
    round: &str,
    index: u32,
    start_time: SystemTime
) -> Result<Vec<String>, ErrorType> {
    let mut ans_vec: Vec<String> = Vec::new();
    for i in 1..=n {
        if i != party_num {
            let key = format!("{}-{}-{}-{}", i, party_num, round, index);
            loop {
                {
                    let db = db_mtx.read().unwrap();
                    // timeout handle
                    if time_check_out(start_time, TIME_LIMIT) {
                        let mut err_res: Vec<usize> = Vec::new();
                        for i in 1..=n {
                            if i != party_num {
                                let key = format!("{}-{}-{}-{}", i, party_num, round, index);
                                if let None = db.get(&key) { err_res.push(i.into()); }
                            }
                        }
                        let error_type = format!("index-{}-{}-timeout", index, round).to_string();
                        return Err(ErrorType::new(error_type, err_res));
                    }
                    // normal handle
                    if let Some(data) = db.get(&key) {
                        let da: String = (*data).clone().to_string();
                        ans_vec.push(da);
                        // println!("[{:?}] party {:?} => party {:?}", round, i, party_num);
                        break;
                    }
                }
                thread::sleep(delay);
            }
        }
    }
    Ok(ans_vec)
}

#[allow(dead_code)]
pub fn check_sig(r: &FE, s: &FE, msg: &BigInt, pk: &GE) {
    use secp256k1::{verify, Message, PublicKey, PublicKeyFormat, Signature};

    let raw_msg = BigInt::to_vec(&msg);
    let mut msg: Vec<u8> = Vec::new(); // padding
    msg.extend(vec![0u8; 32 - raw_msg.len()]);
    msg.extend(raw_msg.iter());

    let msg = Message::parse_slice(msg.as_slice()).unwrap();
    let mut raw_pk = pk.pk_to_key_slice();
    if raw_pk.len() == 64 {
        raw_pk.insert(0, 4u8);
    }
    let pk = PublicKey::parse_slice(&raw_pk, Some(PublicKeyFormat::Full)).unwrap();

    let mut compact: Vec<u8> = Vec::new();
    let bytes_r = &r.get_element()[..];
    compact.extend(vec![0u8; 32 - bytes_r.len()]);
    compact.extend(bytes_r.iter());

    let bytes_s = &s.get_element()[..];
    compact.extend(vec![0u8; 32 - bytes_s.len()]);
    compact.extend(bytes_s.iter());

    let secp_sig = Signature::parse_slice(compact.as_slice()).unwrap();

    let is_correct = verify(&msg, &secp_sig, &pk);
    assert!(is_correct);
}

fn time_check_out(start_time: SystemTime, time_limit: Duration) -> bool {
    if start_time.elapsed().unwrap() >= time_limit { return true; }
    false
}

pub fn get_party_num(partners: &Vec<AccountId>, local_id: &AccountId) -> Option<u16> {
    for i in 0..partners.len() {
        if partners[i] == *local_id { return Some((i+1) as u16); }
    }
    None
}

pub fn get_bad_actors(partners: Vec<AccountId>, bad_actors: Vec<usize>) -> Vec<AccountId> {
    let mut res = Vec::new();
    for num in bad_actors {
        res.push(partners[num].clone());
    }
    res
}