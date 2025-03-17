use super::pre_signed_musig2::{verify_public_nonce, PreSignedMusig2Transaction};
use crate::{
    error::{Error, ValidationError},
    graphs::base::MIN_RELAY_FEE_RATE,
};
use bitcoin::{Amount, OutPoint, PublicKey, Script, Transaction, Txid, XOnlyPublicKey};
use core::cmp;
use esplora_client::TxStatus;
use itertools::Itertools;
use musig2::{secp256k1::schnorr::Signature, PubNonce};
use std::collections::HashMap;

// TODO: set to larger value to be compatible with future tx modifications
pub const RELAY_FEE_BUFFER_MULTIPLIER: f32 = 1.0;
pub const MIN_RELAY_FEE_KICK_OFF_1: u64 = relay_fee(6231);
pub const MIN_RELAY_FEE_START_TIME: u64 = relay_fee(407);
pub const MIN_RELAY_FEE_START_TIME_TIMEOUT: u64 = relay_fee(265);
pub const MIN_RELAY_FEE_KICK_OFF_2: u64 = relay_fee(5461);
pub const MIN_RELAY_FEE_KICK_OFF_TIMEOUT: u64 = relay_fee(182);
pub const MIN_RELAY_FEE_TAKE_1: u64 = relay_fee(380);
pub const MIN_RELAY_FEE_TAKE_2: u64 = relay_fee(347);
pub const MIN_RELAY_FEE_PEG_IN_DEPOSIT: u64 = relay_fee(122);
pub const MIN_RELAY_FEE_PEG_IN_CONFIRM: u64 = relay_fee(173);
pub const MIN_RELAY_FEE_PEG_IN_REFUND: u64 = relay_fee(138);
pub const MIN_RELAY_FEE_PEG_OUT: u64 = relay_fee(122);
pub const MIN_RELAY_FEE_PEG_OUT_CONFIRM: u64 = relay_fee(122);
pub const MIN_RELAY_FEE_ASSERT: u64 = relay_fee(232);
pub const MIN_RELAY_FEE_ASSERT_INITIAL: u64 = relay_fee(48953);
pub const MIN_RELAY_FEE_ASSERT_COMMIT1: u64 = relay_fee(739137);
pub const MIN_RELAY_FEE_ASSERT_COMMIT2: u64 = relay_fee(470440);
pub const MIN_RELAY_FEE_ASSERT_FINAL: u64 = relay_fee(352);
pub const MIN_RELAY_FEE_CHALLENGE: u64 = relay_fee(317);
pub const MIN_RELAY_FEE_DISPROVE: u64 = relay_fee(238785);
pub const MIN_RELAY_FEE_DISPROVE_CHAIN: u64 = relay_fee(389370);

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
    fn name(&self) -> &'static str;
    // fn initialize(&mut self, context: &dyn BaseContext);

    // TODO: Use musig2 to aggregate signatures
    // fn pre_sign(&mut self, context: &dyn BaseContext);

    // TODO: Implement default that goes through all leaves and checks if one of them is executable
    // TODO: Return a Result with an Error in case the witness can't be created
    fn finalize(&self) -> Transaction;
}

pub const fn relay_fee(vsize: usize) -> u64 {
    (vsize as f32 * RELAY_FEE_BUFFER_MULTIPLIER) as u64 * MIN_RELAY_FEE_RATE
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
    tx_name: &'static str,
) -> Result<(), Error> {
    for i in 0..comparison_transaction.input.len() {
        if transaction.input[i].previous_output != comparison_transaction.input[i].previous_output
            || transaction.input[i].script_sig != comparison_transaction.input[i].script_sig
            || transaction.input[i].sequence != comparison_transaction.input[i].sequence
        {
            return Err(Error::Validation(ValidationError::TxValidationFailed(
                tx_name,
                transaction.compute_txid(),
                i,
            )));
        }
    }

    for i in 0..comparison_transaction.output.len() {
        if transaction.output[i].value != comparison_transaction.output[i].value
            || transaction.output[i].script_pubkey != comparison_transaction.output[i].script_pubkey
        {
            return Err(Error::Validation(ValidationError::TxValidationFailed(
                tx_name,
                transaction.compute_txid(),
                i,
            )));
        }
    }

    Ok(())
}

pub fn validate_witness(
    tx: &Transaction,
    tx_name: &'static str,
    tx_status_res: Result<TxStatus, esplora_client::Error>,
    onchain_tx_res: Result<Option<Transaction>, esplora_client::Error>,
) -> Result<(), Error> {
    let txid = tx.compute_txid();
    let tx_status = tx_status_res.map_err(Error::Esplora)?;

    if tx_status.confirmed {
        let result_tx = onchain_tx_res.map_err(Error::Esplora)?;
        match result_tx {
            Some(onchain_tx) => {
                for i in 0..tx.input.len() {
                    if !tx.input[i].witness.is_empty()
                        && tx.input[i].witness != onchain_tx.input[i].witness
                    {
                        return Err(Error::Validation(ValidationError::WitnessMismatch(
                            tx_name, txid, i,
                        )));
                    }
                }
                Ok(())
            }
            None => Err(Error::Other(format!(
                "Esplora failed to retrieve a confirmed tx with id: {}",
                txid
            ))),
        }
    } else {
        Ok(())
    }
}

fn verify_public_nonces(
    all_nonces: &HashMap<usize, HashMap<PublicKey, PubNonce>>,
    all_sigs: &HashMap<usize, HashMap<PublicKey, Signature>>,
    txid: Txid,
    tx_name: &'static str,
) -> Result<(), Error> {
    for (i, nonces) in all_nonces {
        for (pubkey, nonce) in nonces {
            if !verify_public_nonce(&all_sigs[i][pubkey], nonce, &XOnlyPublicKey::from(*pubkey)) {
                eprintln!(
                    "Failed to verify public nonce for pubkey {pubkey} on tx:input {txid}:{i}."
                );
                return Err(Error::Validation(ValidationError::NoncesValidationFailed(
                    tx_name, *pubkey, txid, *i,
                )));
            }
        }
    }

    Ok(())
}

pub fn verify_public_nonces_for_tx(
    tx: &(impl BaseTransaction + PreSignedMusig2Transaction),
) -> Result<(), Error> {
    verify_public_nonces(
        tx.musig2_nonces(),
        tx.musig2_nonce_signatures(),
        tx.tx().compute_txid(),
        tx.name(),
    )
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, str::FromStr};

    use bitcoin::{
        absolute,
        key::{
            constants::{SCHNORR_SIGNATURE_SIZE, SECRET_KEY_SIZE},
            Keypair,
        },
        Amount, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    };
    use esplora_client::TxStatus;
    use musig2::{secp256k1::schnorr::Signature, PubNonce};

    use crate::{
        contexts::base::generate_keys_from_secret,
        error::{Error, ValidationError},
        transactions::{pre_signed_musig2::get_nonce_message, signing_musig2::generate_nonce},
    };

    use super::{validate_witness, verify_public_nonces};

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
            let (keypair, pubkey) = generate_keys_from_secret(
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

                let nonce_signature =
                    keypairs[signer].sign_schnorr(get_nonce_message(&secret_nonce.public_nonce()));
                sigs.insert(pubkeys[signer], nonce_signature);
            }
            all_nonces.insert(input, nonces);
            all_sigs.insert(input, sigs);
        }
        (all_nonces, all_sigs)
    }

    fn get_test_tx() -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_str(
                        "0e6719ac074b0e3cac76d057643506faa1c266b322aa9cf4c6f635fe63b14327",
                    )
                    .unwrap(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                script_pubkey: ScriptBuf::new(),
                value: Amount::from_sat(0),
            }],
        }
    }

    #[test]
    fn test_verify_public_nonces_all_valid_signatures() {
        let (all_nonces, all_sigs) = get_test_nonces();

        assert!(
            verify_public_nonces(
                &all_nonces,
                &all_sigs,
                DUMMY_TXID.parse::<Txid>().unwrap(),
                "test_tx"
            )
            .is_ok(),
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

        let result = verify_public_nonces(
            &all_nonces,
            &all_sigs,
            DUMMY_TXID.parse::<Txid>().unwrap(),
            "test_tx",
        );

        assert!(matches!(
            result,
            Err(Error::Validation(ValidationError::NoncesValidationFailed(
                _,
                _,
                _,
                _
            )))
        ));

        if let Err(Error::Validation(ValidationError::NoncesValidationFailed(
            tx_name,
            _pubkey,
            _txid,
            _input_index,
        ))) = result
        {
            assert_eq!(tx_name, "test_tx");
            assert_eq!(_pubkey, pubkey);
            assert_eq!(_txid, DUMMY_TXID.parse::<Txid>().unwrap());
            assert_eq!(input_index, input_index);
        }
    }

    #[test]
    fn test_verify_witness_mismatch() {
        let mut tx = get_test_tx();
        tx.input[0].witness = vec![vec![0u8; 32]].into();

        let onchain_tx_res = Ok(Some(get_test_tx()));
        let tx_status_res = Ok(TxStatus {
            confirmed: true,
            block_height: None,
            block_hash: None,
            block_time: None,
        });
        let result = validate_witness(&tx, "test_tx", tx_status_res, onchain_tx_res);

        assert!(matches!(
            result,
            Err(Error::Validation(ValidationError::WitnessMismatch(_, _, _)))
        ));

        if let Err(Error::Validation(ValidationError::WitnessMismatch(
            tx_name,
            txid,
            input_index,
        ))) = result
        {
            assert_eq!(tx_name, "test_tx");
            assert_eq!(txid, tx.compute_txid());
            assert_eq!(input_index, 0);
        }
    }

    #[test]
    fn test_verify_witness_match() {
        let mut tx = get_test_tx();
        tx.input[0].witness = vec![vec![0u8; 32]].into();

        let onchain_tx_res = Ok(Some(tx.clone()));
        let tx_status_res = Ok(TxStatus {
            confirmed: true,
            block_height: None,
            block_hash: None,
            block_time: None,
        });
        let result = validate_witness(&tx, "test_tx", tx_status_res, onchain_tx_res);

        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_empty_witness_and_not_empty_onchain_witness() {
        let tx = get_test_tx();
        let mut onchain_tx = tx.clone();
        onchain_tx.input[0].witness = vec![vec![0u8; 32]].into();

        let onchain_tx_res = Ok(Some(onchain_tx));
        let tx_status_res = Ok(TxStatus {
            confirmed: true,
            block_height: None,
            block_hash: None,
            block_time: None,
        });
        let result = validate_witness(&tx, "test_tx", tx_status_res, onchain_tx_res);

        assert!(result.is_ok());
    }
}
