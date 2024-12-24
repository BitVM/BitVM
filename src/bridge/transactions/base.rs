use bitcoin::{Amount, OutPoint, PublicKey, Script, Transaction, Txid, XOnlyPublicKey};
use core::cmp;
use itertools::Itertools;
use musig2::{secp256k1::schnorr::Signature, PubNonce};
use std::collections::HashMap;

use crate::bridge::graphs::base::MIN_RELAY_FEE_RATE;

use super::pre_signed_musig2::{verify_public_nonce, PreSignedMusig2Transaction};

// TODO: set to larger value to be compatible with future tx modifications
pub const RELAY_FEE_BUFFER_MULTIPLIER: f32 = 1.0;
pub const MIN_RELAY_FEE_KICK_OFF_1: u64 =
    (6231 as f32 * RELAY_FEE_BUFFER_MULTIPLIER) as u64 * MIN_RELAY_FEE_RATE;
pub const MIN_RELAY_FEE_START_TIME: u64 =
    (408 as f32 * RELAY_FEE_BUFFER_MULTIPLIER) as u64 * MIN_RELAY_FEE_RATE;
pub const MIN_RELAY_FEE_START_TIME_TIMEOUT: u64 =
    (264 as f32 * RELAY_FEE_BUFFER_MULTIPLIER) as u64 * MIN_RELAY_FEE_RATE;
pub const MIN_RELAY_FEE_KICK_OFF_2: u64 =
    (5461 as f32 * RELAY_FEE_BUFFER_MULTIPLIER) as u64 * MIN_RELAY_FEE_RATE;
pub const MIN_RELAY_FEE_KICK_OFF_TIMEOUT: u64 =
    (181 as f32 * RELAY_FEE_BUFFER_MULTIPLIER) as u64 * MIN_RELAY_FEE_RATE;
pub const MIN_RELAY_FEE_TAKE_1: u64 =
    (372 as f32 * RELAY_FEE_BUFFER_MULTIPLIER) as u64 * MIN_RELAY_FEE_RATE;
pub const MIN_RELAY_FEE_TAKE_2: u64 =
    (347 as f32 * RELAY_FEE_BUFFER_MULTIPLIER) as u64 * MIN_RELAY_FEE_RATE;
pub const MIN_RELAY_FEE_PEG_IN_DEPOSIT: u64 =
    (122 as f32 * RELAY_FEE_BUFFER_MULTIPLIER) as u64 * MIN_RELAY_FEE_RATE;
pub const MIN_RELAY_FEE_PEG_IN_CONFIRM: u64 =
    (173 as f32 * RELAY_FEE_BUFFER_MULTIPLIER) as u64 * MIN_RELAY_FEE_RATE;
pub const MIN_RELAY_FEE_PEG_IN_REFUND: u64 =
    (138 as f32 * RELAY_FEE_BUFFER_MULTIPLIER) as u64 * MIN_RELAY_FEE_RATE;
pub const MIN_RELAY_FEE_PEG_OUT: u64 =
    (122 as f32 * RELAY_FEE_BUFFER_MULTIPLIER) as u64 * MIN_RELAY_FEE_RATE;
pub const MIN_RELAY_FEE_ASSERT: u64 =
    (232 as f32 * RELAY_FEE_BUFFER_MULTIPLIER) as u64 * MIN_RELAY_FEE_RATE;
pub const MIN_RELAY_FEE_CHALLENGE: u64 =
    (317 as f32 * RELAY_FEE_BUFFER_MULTIPLIER) as u64 * MIN_RELAY_FEE_RATE;
pub const MIN_RELAY_FEE_DISPROVE: u64 =
    (363 as f32 * RELAY_FEE_BUFFER_MULTIPLIER) as u64 * MIN_RELAY_FEE_RATE;
pub const MIN_RELAY_FEE_DISPROVE_CHAIN: u64 =
    (224 as f32 * RELAY_FEE_BUFFER_MULTIPLIER) as u64 * MIN_RELAY_FEE_RATE;

pub struct Input {
    pub outpoint: OutPoint,
    pub amount: Amount,
}

pub struct InputWithScript<'a> {
    pub outpoint: OutPoint,
    pub amount: Amount,
    pub script: &'a Script,
}

pub trait BaseTransaction {
    // fn initialize(&mut self, context: &dyn BaseContext);

    // TODO: Use musig2 to aggregate signatures
    // fn pre_sign(&mut self, context: &dyn BaseContext);

    // TODO: Implement default that goes through all leaves and checks if one of them is executable
    // TODO: Return a Result with an Error in case the witness can't be created
    fn finalize(&mut self) -> Transaction;
}

// This will often trigger 'Invalid Schnorr signature'
// TODO: fix or deprecate, maybe search for output not affect by pre-sign
pub fn deduct_relay_fee(tx: &mut Transaction) {
    let relay_fee = Amount::from_sat(tx.vsize() as u64 * MIN_RELAY_FEE_RATE);
    let largest_output_index = tx
        .output
        .iter()
        .enumerate()
        .max_by(|(_, o1), (_, o2)| o1.value.cmp(&o2.value))
        .map(|(i, _)| i)
        .expect("Transaction output is empty");
    tx.output[largest_output_index].value -= relay_fee;
}

pub fn merge_transactions(
    destination_transaction: &mut Transaction,
    source_transaction: &Transaction,
) {
    for i in destination_transaction.input.len()..source_transaction.input.len() {
        destination_transaction
            .input
            .push(source_transaction.input[i].clone());
    }

    for i in 0..cmp::min(
        destination_transaction.input.len(),
        source_transaction.input.len(),
    ) {
        // TODO: takes longer witness data but should combine both
        // TODO: merge signatures after Musig2 feature is ready
        if destination_transaction.input[i].witness.len()
            < source_transaction.input[i].witness.len()
        {
            destination_transaction.input[i].witness = source_transaction.input[i].witness.clone();
        }
    }

    for i in destination_transaction.output.len()..source_transaction.output.len() {
        destination_transaction
            .output
            .push(source_transaction.output[i].clone());
    }
}

// assumes source_transaction is the latest
pub fn merge_musig2_nonces_and_signatures(
    destination_transaction: &mut dyn PreSignedMusig2Transaction,
    source_transaction: &dyn PreSignedMusig2Transaction,
) {
    let nonces = destination_transaction.musig2_nonces_mut();
    merge_hash_maps(nonces, source_transaction.musig2_nonces().clone());

    let nonce_signatures = destination_transaction.musig2_nonce_signatures_mut();
    merge_hash_maps(
        nonce_signatures,
        source_transaction.musig2_nonce_signatures().clone(),
    );

    let signatures = destination_transaction.musig2_signatures_mut();
    merge_hash_maps(signatures, source_transaction.musig2_signatures().clone());
}

// merge the nonce/signature hashmaps. We can't just do a.extend(b) since that would just overwrite the inner
// hashmap rather than merging it
fn merge_hash_maps<T: Clone>(
    a: &mut HashMap<usize, HashMap<PublicKey, T>>,
    b: HashMap<usize, HashMap<PublicKey, T>>,
) {
    let all_keys = a
        .keys()
        .chain(b.keys())
        .unique()
        .cloned()
        .collect::<Vec<_>>();
    for key in all_keys {
        let q = a.entry(key).or_default();
        let w = b.get(&key).cloned().unwrap_or(HashMap::new());
        q.extend(w.clone());
    }
}

pub fn validate_transaction(
    transaction: &Transaction,
    comparison_transaction: &Transaction,
) -> bool {
    for i in 0..comparison_transaction.input.len() {
        if transaction.input[i].previous_output != comparison_transaction.input[i].previous_output
            || transaction.input[i].script_sig != comparison_transaction.input[i].script_sig
            || transaction.input[i].sequence != comparison_transaction.input[i].sequence
        {
            println!(
                "Input mismatch on transaction: {} input index: {}",
                transaction.compute_txid(),
                i
            );
            return false;
        }
    }

    for i in 0..comparison_transaction.output.len() {
        if transaction.output[i].value != comparison_transaction.output[i].value
            || transaction.output[i].script_pubkey != comparison_transaction.output[i].script_pubkey
        {
            println!(
                "Output mismatch on transaction: {} output index: {}",
                transaction.compute_txid(),
                i
            );
            return false;
        }
    }

    true
}

fn verify_public_nonces(
    all_nonces: &HashMap<usize, HashMap<PublicKey, PubNonce>>,
    all_sigs: &HashMap<usize, HashMap<PublicKey, Signature>>,
    txid: Txid,
) -> bool {
    let mut ret_val = true;

    for (i, nonces) in all_nonces {
        for (pubkey, nonce) in nonces {
            if !verify_public_nonce(&all_sigs[i][pubkey], nonce, &XOnlyPublicKey::from(*pubkey)) {
                eprintln!(
                    "Failed to verify public nonce for pubkey {pubkey} on tx:input {txid}:{i}."
                );
                ret_val = false;
            }
        }
    }

    ret_val
}

pub fn verify_public_nonces_for_tx(tx: &impl PreSignedMusig2Transaction) -> bool {
    verify_public_nonces(
        tx.musig2_nonces(),
        tx.musig2_nonce_signatures(),
        tx.tx().compute_txid(),
    )
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use bitcoin::{
        key::{
            constants::{SCHNORR_SIGNATURE_SIZE, SECRET_KEY_SIZE},
            Keypair, Secp256k1,
        },
        PublicKey, Txid,
    };
    use musig2::{secp256k1::schnorr::Signature, PubNonce};

    use crate::bridge::{
        contexts::base::generate_keys_from_secret,
        transactions::{pre_signed_musig2::get_nonce_message, signing_musig2::generate_nonce},
    };

    use super::verify_public_nonces;

    const DUMMY_TXID: &str = "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456";

    fn get_test_nonces() -> (
        HashMap<usize, HashMap<PublicKey, PubNonce>>,
        HashMap<usize, HashMap<PublicKey, Signature>>,
    ) {
        const SIGNERS: usize = 3;
        const INPUTS: usize = 4;

        // Generate keys
        let mut keypairs: Vec<Keypair> = Vec::new();
        let mut pubkeys: Vec<PublicKey> = Vec::new();
        for signer in 0..SIGNERS {
            let (_, keypair, pubkey) = generate_keys_from_secret(
                bitcoin::Network::Bitcoin,
                &hex::encode([(signer + 1) as u8; SECRET_KEY_SIZE]),
            );
            keypairs.push(keypair);
            pubkeys.push(pubkey);
        }

        // Generate and sign nonces
        let mut all_nonces: HashMap<usize, HashMap<PublicKey, PubNonce>> = HashMap::new();
        let mut all_sigs: HashMap<usize, HashMap<PublicKey, Signature>> = HashMap::new();
        for input in 0..INPUTS {
            let mut nonces: HashMap<PublicKey, PubNonce> = HashMap::new();
            let mut sigs: HashMap<PublicKey, Signature> = HashMap::new();
            for signer in 0..SIGNERS {
                let secret_nonce = generate_nonce();

                nonces.insert(pubkeys[signer], secret_nonce.public_nonce());

                let nonce_signature = Secp256k1::new().sign_schnorr(
                    &get_nonce_message(&secret_nonce.public_nonce()),
                    &keypairs[signer],
                );
                sigs.insert(pubkeys[signer], nonce_signature);
            }
            all_nonces.insert(input, nonces);
            all_sigs.insert(input, sigs);
        }
        (all_nonces, all_sigs)
    }

    #[test]
    fn test_verify_public_nonces_all_valid_signatures() {
        let (all_nonces, all_sigs) = get_test_nonces();

        assert!(
            verify_public_nonces(&all_nonces, &all_sigs, DUMMY_TXID.parse::<Txid>().unwrap()),
            "verify_public_nonces() did not return true on success"
        );
    }

    #[test]
    fn test_verify_public_nonces_invalid_signature() {
        let (all_nonces, mut all_sigs) = get_test_nonces();

        let input_index = all_sigs.len() / 2;
        let pubkey = *all_sigs[&input_index].keys().next().unwrap();
        let mut bad_sig = all_sigs[&input_index][&pubkey].serialize();
        bad_sig[SCHNORR_SIGNATURE_SIZE - 1] += 1;
        all_sigs
            .get_mut(&input_index)
            .unwrap()
            .insert(pubkey, Signature::from_slice(&bad_sig).unwrap());

        assert!(
            !verify_public_nonces(&all_nonces, &all_sigs, DUMMY_TXID.parse::<Txid>().unwrap()),
            "verify_public_nonces() did not return false on invalid signature"
        );
    }
}
