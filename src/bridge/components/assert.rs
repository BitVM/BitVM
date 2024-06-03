use crate::treepp::*;
use bitcoin::{
    absolute,
    hashes::{ripemd160, Hash},
    key::Secp256k1,
    taproot::{TaprootBuilder, TaprootSpendInfo},
    Address, Amount, Network, OutPoint, Sequence,
    Transaction, TxIn, TxOut, Witness, XOnlyPublicKey,
};

use super::super::context::BridgeContext;
use super::super::graph::FEE_AMOUNT;

use super::bridge::*;
use super::helper::*;

// Specialized for assert leaves currently.a
// TODO: Attach the pubkeys after constructing leaf scripts
pub type LockScript = fn(u32) -> Script;

pub type UnlockWitness = fn(u32) -> Vec<Vec<u8>>;

pub struct AssertLeaf {
    pub lock: LockScript,
    pub unlock: UnlockWitness,
}

pub struct AssertTransaction {
    tx: Transaction,
    prev_outs: Vec<TxOut>,
}

impl AssertTransaction {
    pub fn new(context: &BridgeContext, input: OutPoint, input_value: Amount) -> Self {
        let n_of_n_pubkey = context
            .n_of_n_pubkey
            .expect("n_of_n_pubkey is required in context");
        let connector_c_output = TxOut {
            value: input_value - Amount::from_sat(FEE_AMOUNT),
            // TODO: This has to be KickOff transaction address
            script_pubkey: Address::p2tr_tweaked(
                connector_c_spend_info(n_of_n_pubkey).0.output_key(),
                Network::Testnet,
            )
            .script_pubkey(),
        };
        let input = TxIn {
            previous_output: input,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        };
        AssertTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![input],
                output: vec![connector_c_output],
            },
            prev_outs: vec![],
        }
    }
}

impl BridgeTransaction for AssertTransaction {
    fn pre_sign(&mut self, context: &BridgeContext) {
        todo!();
    }

    fn finalize(&self, context: &BridgeContext) -> Transaction { todo!() }
}

pub fn assert_leaf() -> AssertLeaf {
    AssertLeaf {
        lock: |index| {
            script! {
                // TODO: Operator_key?
                OP_RIPEMD160
                { ripemd160::Hash::hash(format!("SECRET_{}", index).as_bytes()).as_byte_array().to_vec() }
                OP_EQUALVERIFY
                { index }
                OP_DROP
                OP_TRUE
            }
        },
        unlock: |index| vec![format!("SECRET_{}", index).as_bytes().to_vec()],
    }
}

pub fn generate_assert_leaves() -> Vec<Script> {
    // TODO: Scripts with n_of_n_pubkey and one of the commitments disprove leaves in each leaf (Winternitz signatures)
    let mut leaves = Vec::with_capacity(1000);
    let locking_template = assert_leaf().lock;
    for i in 0..1000 {
        leaves.push(locking_template(i));
    }
    leaves
}

// Returns the TaprootSpendInfo for the Commitment Taptree and the corresponding pre_sign_output
pub fn connector_c_spend_info(
    n_of_n_pubkey: XOnlyPublicKey,
) -> (TaprootSpendInfo, TaprootSpendInfo) {
    let secp = Secp256k1::new();

    let scripts = generate_assert_leaves();
    let script_weights = scripts.iter().map(|script| (1, script.clone()));
    let commitment_taptree_info = TaprootBuilder::with_huffman_tree(script_weights)
        .expect("Unable to add assert leaves")
        // Finalizing with n_of_n_pubkey allows the key-path spend with the
        // n_of_n
        .finalize(&secp, n_of_n_pubkey)
        .expect("Unable to finalize assert transaction connector c taproot");
    let pre_sign_info = TaprootBuilder::new()
        .add_leaf(0, generate_pre_sign_script(n_of_n_pubkey))
        .expect("Unable to add pre_sign script as leaf")
        .finalize(&secp, n_of_n_pubkey)
        .expect("Unable to finalize OP_CHECKSIG taproot");
    (pre_sign_info, commitment_taptree_info)
}

pub fn connector_c_address(n_of_n_pubkey: XOnlyPublicKey) -> Address {
    Address::p2tr_tweaked(
        connector_c_spend_info(n_of_n_pubkey).1.output_key(),
        Network::Testnet,
    )
}

pub fn connector_c_pre_sign_address(n_of_n_pubkey: XOnlyPublicKey) -> Address {
    Address::p2tr_tweaked(
        connector_c_spend_info(n_of_n_pubkey).0.output_key(),
        Network::Testnet,
    )
}
