#![allow(non_snake_case)]

use curv::arithmetic::traits::Converter;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::traits::*;
use curv::{FE, GE, BigInt};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::orchestrate::*;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::{
    KeyGenBroadcastMessage1, KeyGenDecommitMessage1, Keys, Parameters, SharedKeys,
};
use paillier::*;
use serde::{Deserialize, Serialize};
use std::{fs, time};
use zk_paillier::zkproofs::DLogStatement;

use libp2p::{identity, PeerId};
use sp_utils::mpsc::{TracingUnboundedSender};
use std::collections::{HashMap, HashSet};
use std::sync::{RwLock, Arc};
use parking_lot::{Mutex};
use std::time::{SystemTime};
// use std::hash::{Hash, Hasher};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::ErrorType;

use crate::common::{aes_decrypt, aes_encrypt, Params, AEAD, Key, AES_KEY_BYTES_LEN, PartyType,
            poll_for_broadcasts_ch, poll_for_p2p_ch, broadcast_ch, sendp2p_ch, get_party_num,
            TssResult };

impl From<Params> for Parameters {
    fn from(item: Params) -> Self {
        Parameters {
            share_count: item.parties.parse::<u16>().unwrap(),
            threshold: item.threshold.parse::<u16>().unwrap(),
        }
    }
}

pub async fn gg20_keygen_client (
    tx: Arc<Mutex<TracingUnboundedSender<String>>>,
    db_mtx: Arc<RwLock<HashMap<Key, String>>>,
    peer_ids: Arc<RwLock<HashSet<Vec<u8>>>>
) -> Result<TssResult, ErrorType> {
    let totaltime = SystemTime::now();

    let params: Parameters = serde_json::from_str::<Params>(
        &std::fs::read_to_string("params.json").expect("Could not read input params file"),
    ).unwrap().into();
    let params_lis = params.clone();

    let mut party_num_int: u16 = 0;

    let delay = time::Duration::from_millis(25);

    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id: PeerId = PeerId::from(local_key.public());
    loop{
        if let Ok(mut peer_ids) = peer_ids.try_write() {
            (*peer_ids).insert(local_peer_id.clone().as_bytes().to_vec());
            break;
        }
    }


    // tell other node the local_peer_id
    broadcast_ch(
        tx.clone(),
        party_num_int,
        "keygen_notify",
        serde_json::to_string(&local_peer_id.clone().as_bytes()).unwrap(),
        PartyType::KeygenNotify
    );

    // get party_num_int
    loop{
        if let Ok(peer_ids) = peer_ids.try_read() {
            if (peer_ids.len() as u16) == params_lis.share_count {
                party_num_int = get_party_num(&peer_ids, &local_peer_id.as_bytes().to_vec());
                break;
            }
        }
    }

    let input_stage1 = KeyGenStage1Input {
        index: (party_num_int - 1) as usize,
    };
    let res_stage1: KeyGenStage1Result = keygen_stage1(&input_stage1);

    // broadcast test
    broadcast_ch(
        tx.clone(),
        party_num_int,
        "round1",
        serde_json::to_string(&res_stage1.bc_com1_l).unwrap(),
        PartyType::Keygen
    );

    let round1_ans_vec = poll_for_broadcasts_ch(
        db_mtx.clone(),
        party_num_int,
        params.share_count,
        delay,
        "round1"
    );
    let mut bc1_vec = round1_ans_vec
        .iter()
        .map(|m| serde_json::from_str::<KeyGenBroadcastMessage1>(m).unwrap())
        .collect::<Vec<_>>();

    bc1_vec.insert(party_num_int as usize - 1, res_stage1.bc_com1_l);

    broadcast_ch(
        tx.clone(),
        party_num_int,
        "round2",
        serde_json::to_string(&res_stage1.decom1_l).unwrap(),
        PartyType::Keygen
    );
    let round2_ans_vec = poll_for_broadcasts_ch(
        db_mtx.clone(),
        party_num_int,
        params.share_count,
        delay,
        "round2"
    );
    let mut decom1_vec = round2_ans_vec
        .iter()
        .map(|m| serde_json::from_str::<KeyGenDecommitMessage1>(m).unwrap())
        .collect::<Vec<_>>();
    decom1_vec.insert(party_num_int as usize - 1, res_stage1.decom1_l);
    let input_stage2 = KeyGenStage2Input {
        index: (party_num_int - 1) as usize,
        params_s: params.clone(),
        party_keys_s: res_stage1.party_keys_l.clone(),
        decom1_vec_s: decom1_vec.clone(),
        bc1_vec_s: bc1_vec.clone(),
    };
    let res_stage2 = keygen_stage2(&input_stage2).expect("keygen stage 2 failed.");

    let mut point_vec: Vec<GE> = Vec::new();
    let mut enc_keys: Vec<Vec<u8>> = Vec::new();
    for i in 1..=params.share_count {
        point_vec.push(decom1_vec[(i - 1) as usize].y_i);
        if i != party_num_int {
            let key_bn: BigInt = (decom1_vec[(i - 1) as usize].y_i.clone()
                * res_stage1.party_keys_l.u_i)
                .x_coor()
                .unwrap();
            let key_bytes = BigInt::to_vec(&key_bn);
            let mut template: Vec<u8> = vec![0u8; AES_KEY_BYTES_LEN - key_bytes.len()];
            template.extend_from_slice(&key_bytes[..]);
            enc_keys.push(template);
        }
    }

    let (head, tail) = point_vec.split_at(1);
    let y_sum = tail.iter().fold(head[0], |acc, x| acc + x);

    let mut j = 0;
    for (k, i) in (1..=params.share_count).enumerate() {
        if i != party_num_int {
            // prepare encrypted ss for party i:
            let key_i = &enc_keys[j];
            let plaintext = BigInt::to_vec(&res_stage2.secret_shares_s[k].to_big_int());
            let aead_pack_i = aes_encrypt(key_i, &plaintext);
            // This client does not implement the identifiable abort protocol.
            // If it were these secret shares would need to be broadcasted to indetify the
            // malicious party.
            sendp2p_ch(
                tx.clone(),
                party_num_int,
                i,
                "round3",
                serde_json::to_string(&aead_pack_i).unwrap(),
                PartyType::Keygen
            );
            j += 1;
        }
    }
    // get shares from other parties.
    let round3_ans_vec = poll_for_p2p_ch(
        db_mtx.clone(),
        party_num_int,
        params.share_count,
        delay,
        "round3"
    );
    // decrypt shares from other parties.
    let mut j = 0;
    let mut party_shares: Vec<FE> = Vec::new();
    for i in 1..=params.share_count {
        if i == party_num_int {
            party_shares.push(res_stage2.secret_shares_s[(i - 1) as usize]);
        } else {
            let aead_pack: AEAD = serde_json::from_str(&round3_ans_vec[j]).unwrap();
            let key_i = &enc_keys[j];
            let out = aes_decrypt(key_i, aead_pack);
            let out_bn = BigInt::from(&out[..]);
            let out_fe = ECScalar::from(&out_bn);
            party_shares.push(out_fe);

            j += 1;
        }
    }

    broadcast_ch(
        tx.clone(),
        party_num_int,
        "round4",
        serde_json::to_string(&res_stage2.vss_scheme_s).unwrap(),
        PartyType::Keygen
    );

    //get vss_scheme for others.
    let round4_ans_vec = poll_for_broadcasts_ch(
        db_mtx.clone(),
        party_num_int,
        params.share_count,
        delay,
        "round4"
    );

    let mut j = 0;
    let mut vss_scheme_vec: Vec<VerifiableSS> = Vec::new();
    for i in 1..=params.share_count {
        if i == party_num_int {
            vss_scheme_vec.push(res_stage2.vss_scheme_s.clone());
        } else {
            let vss_scheme_j: VerifiableSS = serde_json::from_str(&round4_ans_vec[j]).unwrap();
            vss_scheme_vec.push(vss_scheme_j);
            j += 1;
        }
    }
    let input_stage3 = KeyGenStage3Input {
        party_keys_s: res_stage1.party_keys_l.clone(),
        vss_scheme_vec_s: vss_scheme_vec.clone(),
        secret_shares_vec_s: party_shares,
        y_vec_s: point_vec.clone(),
        index_s: (party_num_int - 1) as usize,
        params_s: params.clone(),
    };
    let res_stage3 = keygen_stage3(&input_stage3).expect("stage 3 keygen failed.");
    // round 5: send dlog proof
    broadcast_ch(
        tx.clone(),
        party_num_int,
        "round5",
        serde_json::to_string(&res_stage3.dlog_proof_s).unwrap(),
        PartyType::Keygen
    );

    let round5_ans_vec = poll_for_broadcasts_ch(
        db_mtx.clone(),
        party_num_int,
        params.share_count,
        delay,
        "round5"
    );

    let mut j = 0;
    let mut dlog_proof_vec: Vec<DLogProof> = Vec::new();
    for i in 1..=params.share_count {
        if i == party_num_int {
            dlog_proof_vec.push(res_stage3.dlog_proof_s.clone());
        } else {
            let dlog_proof_j: DLogProof = serde_json::from_str(&round5_ans_vec[j]).unwrap();
            dlog_proof_vec.push(dlog_proof_j);
            j += 1;
        }
    }

    let input_stage4 = KeyGenStage4Input {
        params_s: params.clone(),
        dlog_proof_vec_s: dlog_proof_vec.clone(),
        y_vec_s: point_vec.clone(),
    };
    let _ = keygen_stage4(&input_stage4).expect("keygen stage4 failed.");
    //save key to file:
    let paillier_key_vec = (0..params.share_count)
        .map(|i| bc1_vec[i as usize].e.clone())
        .collect::<Vec<EncryptionKey>>();
    let h1_h2_N_tilde_vec = bc1_vec
        .iter()
        .map(|bc1| bc1.dlog_statement.clone())
        .collect::<Vec<DLogStatement>>();
    let party_key_pair = PartyKeyPair {
        party_keys_s: res_stage1.party_keys_l.clone(),
        shared_keys: res_stage3.shared_keys_s.clone(),
        party_num_int_s: party_num_int,
        vss_scheme_vec_s: vss_scheme_vec.clone(),
        paillier_key_vec_s: paillier_key_vec,
        y_sum_s: y_sum,
        h1_h2_N_tilde_vec_s: h1_h2_N_tilde_vec,
    };
    fs::write(
        "key.store",
        serde_json::to_string(&party_key_pair).unwrap(),
    )
    .expect("Unable to save !");

    let tt = SystemTime::now();
    let difference = tt.duration_since(totaltime).unwrap().as_secs_f32();
    println!("total time: {:?}", difference);

    // TODO: should result the result to the chain
    Ok(TssResult::KeygenResult())
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyKeyPair {
    pub party_keys_s: Keys,
    pub shared_keys: SharedKeys,
    pub party_num_int_s: u16,
    pub vss_scheme_vec_s: Vec<VerifiableSS>,
    pub paillier_key_vec_s: Vec<EncryptionKey>,
    pub y_sum_s: GE,
    pub h1_h2_N_tilde_vec_s: Vec<DLogStatement>,
}