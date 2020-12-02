use std::{iter::repeat, thread, time::Duration};

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
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, HashMap};
use std::sync::{RwLock, Arc};
use parking_lot::{Mutex};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::ErrorType;
use sp_utils::mpsc::{TracingUnboundedSender};

pub type Key = String;

#[allow(dead_code)]
pub const AES_KEY_BYTES_LEN: usize = 32;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct AEAD {
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub enum GossipMessage {
    Keygen(String),
    Sign(String),
    KeygenNotify(String),
    SignNotify(String),
}

#[derive(Clone, PartialEq, Debug)]
pub enum PartyType {
    Keygen,
    Sign,
    KeygenNotify,
    SignNotify,
}

// TODO: need more details
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub enum TssResult {
    KeygenResult(),
    SignResult()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ErrorMessage {
    NetError,
    DataError(ErrorType)
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
pub fn broadcast_ch(
    tx: Arc<Mutex<TracingUnboundedSender<String>>>,
    party_num_int: u16,
    round: &str,
    data: String,
    ty: PartyType
) {
    let key = format!("{}-{}", party_num_int, round);
    let entry: Entry = Entry{
        key,
        value: data,
    };
    let data = serde_json::to_string(&entry).unwrap();
    let data = match ty {
        PartyType::KeygenNotify => GossipMessage::KeygenNotify(data),
        PartyType::SignNotify => GossipMessage::SignNotify(data),
        PartyType::Keygen => GossipMessage::Keygen(data),
        PartyType::Sign => GossipMessage::Sign(data),
    };
    let data = serde_json::to_string(&data).unwrap();
    assert!(tx.lock().unbounded_send(data).is_ok());
}

#[allow(dead_code)]
pub fn sendp2p_ch(
    tx: Arc<Mutex<TracingUnboundedSender<String>>>,
    party_from: u16,
    party_to: u16,
    round: &str,
    data: String,
    ty: PartyType
) {
    let key = format!("{}-{}-{}", party_from, party_to, round);
    let entry: Entry = Entry{
        key,
        value: data,
    };
    let data = serde_json::to_string(&entry).unwrap();
    let data = match ty {
        PartyType::KeygenNotify => GossipMessage::KeygenNotify(data),
        PartyType::SignNotify => GossipMessage::SignNotify(data),
        PartyType::Keygen => GossipMessage::Keygen(data),
        PartyType::Sign => GossipMessage::Sign(data),
    };
    let data = serde_json::to_string(&data).unwrap();
    assert!(tx.lock().unbounded_send(data).is_ok());
}
#[allow(dead_code)]
pub fn poll_for_broadcasts_ch(
    db_mtx: Arc<RwLock<HashMap<Key, String>>>,
    party_num: u16,
    n: u16,
    delay: Duration,
    round: &str
) -> Vec<String> {
    let mut ans_vec: Vec<String> = Vec::new();
    for i in 1..=n {
        if i != party_num {
            let key = format!("{}-{}", i, round);
            loop {
                {
                    let db = db_mtx.read().unwrap();
                    if let Some(data) = db.get(&key) {
                        let da: String = (*data).clone().to_string();
                        ans_vec.push(da);
                        println!("[{:?}] party {:?} => party {:?}", round, i, party_num);
                        break;
                    }
                }
                thread::sleep(delay);
            }
        }
    }
    ans_vec
}
#[allow(dead_code)]
pub fn poll_for_p2p_ch(
    db_mtx: Arc<RwLock<HashMap<Key, String>>>,
    party_num: u16,
    n: u16,
    delay: Duration,
    round: &str
) -> Vec<String> {
    let mut ans_vec: Vec<String> = Vec::new();
    for i in 1..=n {
        if i != party_num {
            let key = format!("{}-{}-{}", i, party_num, round);
            loop {
                {
                    let db = db_mtx.read().unwrap();
                    if let Some(data) = db.get(&key) {
                        let da: String = (*data).clone().to_string();
                        ans_vec.push(da);
                        println!("[{:?}] party {:?} => party {:?}", round, i, party_num);
                        break;
                    }
                }
                thread::sleep(delay);
            }
        }
    }
    ans_vec
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
#[allow(dead_code)]
pub fn get_party_num(map: &HashSet<Vec<u8>>, id: &Vec<u8>) -> u16 {
    let mut res: u16 = 1;
    for vv in (*map).clone() {
        if compare_id(id, &vv) {
            res += 1;
        }
    }
    res
}
#[allow(dead_code)]
fn compare_id(myid: &Vec<u8>, otid: &Vec<u8>) -> bool {
    for i in 0..(*myid).len() {
        if (*myid)[i] < (*otid)[i] { return false; }
        else if (*myid)[i] > (*otid)[i] { return true; }
    }
    false
}
