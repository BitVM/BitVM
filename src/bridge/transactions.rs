use crate::treepp::*;
use bitcoin::{
    absolute,
    hashes::{ripemd160, Hash},
    key::{Keypair, Secp256k1},
    secp256k1::{All, Message},
    sighash::{Prevouts, SighashCache},
    taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo},
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, TapLeafHash, TapSighashType,
    Transaction, TxIn, TxOut, Witness, XOnlyPublicKey,
};

use super::graph::{FEE_AMOUNT, N_OF_N_SECRET};

// Specialized for assert leaves currently.a
// TODO: Attach the pubkeys after constructing leaf scripts
type LockScript = fn(u32, XOnlyPublicKey) -> Script;

type UnlockWitness = fn(u32) -> Vec<Vec<u8>>;

struct AssertLeaf {
    pub lock: LockScript,
    pub unlock: UnlockWitness,
}

pub struct BridgeContext {
    secp: Secp256k1<All>,
    operator_key: Option<Keypair>,
    n_of_n_pubkey: Option<XOnlyPublicKey>,
    // TODO: current_height: Height,
    // TODO: participants secret for the n-of-n keypair
    // TODO: Store learned preimages here
}

impl BridgeContext {
    pub fn new() -> Self {
        BridgeContext {
            secp: Secp256k1::new(),
            operator_key: None,
            n_of_n_pubkey: None,
        }
    }

    pub fn set_operator_key(&mut self, operator_key: Keypair) {
        self.operator_key = Some(operator_key);
    }

    pub fn set_n_of_n_pubkey(&mut self, n_of_n_pubkey: XOnlyPublicKey) {
        self.n_of_n_pubkey = Some(n_of_n_pubkey);
    }
}

pub struct AssertTransaction {
    tx: Transaction,
    prev_outs: Vec<TxOut>,
}

pub struct DisproveTransaction {
    tx: Transaction,
    prev_outs: Vec<TxOut>,
    script_index: u32,
}

pub trait BridgeTransaction {
    //TODO: Use musig2 to aggregate signatures
    fn pre_sign(self: &mut Self, context: &BridgeContext);

    // TODO: Implement default that goes through all leaves and checks if one of them is executable
    // TODO: Return a Result with an Error in case the witness can't be created
    fn finalize(self: &Self, context: &BridgeContext) -> Transaction;
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
                connector_c_spend_info(n_of_n_pubkey).output_key(),
                Network::Testnet,
            )
            .script_pubkey(),
        };
        let input = TxIn {
            previous_output: input,
            script_sig: Script::new(),
            sequence: Sequence(0xFFFFFFFF),
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
    fn pre_sign(self: &mut Self, context: &BridgeContext) {
        todo!();
    }

    fn finalize(self: &Self, context: &BridgeContext) -> Transaction { todo!() }
}

impl DisproveTransaction {
    pub fn new(
        context: &BridgeContext,
        input: OutPoint,
        input_value: Amount,
        script_index: u32,
    ) -> Self {
        let n_of_n_pubkey = context
            .n_of_n_pubkey
            .expect("n_of_n_pubkey required in context");

        let burn_output = TxOut {
            value: (input_value - Amount::from_sat(FEE_AMOUNT)) / 2,
            // TODO: Unspendable script_pubkey
            script_pubkey: connector_c_address(n_of_n_pubkey).script_pubkey(),
        };

        let input = TxIn {
            previous_output: input,
            script_sig: Script::new(),
            sequence: Sequence(0xFFFFFFFF),
            witness: Witness::default(),
        };
        DisproveTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![input],
                output: vec![burn_output],
            },
            prev_outs: vec![TxOut {
                value: input_value,
                script_pubkey: connector_c_address(n_of_n_pubkey).script_pubkey(),
            }],
            script_index,
        }
    }
}

impl BridgeTransaction for DisproveTransaction {
    //TODO: Real presign
    fn pre_sign(self: &mut Self, context: &BridgeContext) {
        let n_of_n_key = Keypair::from_seckey_str(&context.secp, N_OF_N_SECRET).unwrap();

        // Create the signature with n_of_n_key as part of the setup
        let mut sighash_cache = SighashCache::new(&self.tx);
        let prevouts = Prevouts::All(&self.prev_outs);
        let prevout_leaf = (
            (assert_leaf().lock)(self.script_index, n_of_n_key.x_only_public_key().0),
            LeafVersion::TapScript,
        );

        // Use Single to sign only the burn input with the n_of_n_key
        let sighash_type = TapSighashType::Single;
        let leaf_hash =
            TapLeafHash::from_script(prevout_leaf.0.clone().as_script(), LeafVersion::TapScript);
        let sighash = sighash_cache
            .taproot_script_spend_signature_hash(0, &prevouts, leaf_hash, sighash_type)
            .expect("Failed to construct sighash");

        let msg = Message::from(sighash);
        let signature = context.secp.sign_schnorr_no_aux_rand(&msg, &n_of_n_key);

        let signature_with_type = bitcoin::taproot::Signature {
            signature,
            sighash_type,
        };
        self.tx.input[0].witness.push(signature_with_type.to_vec());
    }

    fn finalize(self: &Self, context: &BridgeContext) -> Transaction {
        let n_of_n_pubkey = context
            .n_of_n_pubkey
            .expect("n_of_n_pubkey required in context");

        let prevout_leaf = (
            (assert_leaf().lock)(self.script_index, n_of_n_pubkey),
            LeafVersion::TapScript,
        );
        let control_block = connector_c_spend_info(n_of_n_pubkey)
            .control_block(&prevout_leaf)
            .expect("Unable to create Control block");

        // Push the unlocking values, script and control_block onto the witness.
        let mut tx = self.tx.clone();
        // Unlocking script
        let mut witness_vec = (assert_leaf().unlock)(self.script_index);
        // Pre-sign signature
        witness_vec.extend_from_slice(&tx.input[0].witness.to_vec());
        // Script and Control block
        witness_vec.extend_from_slice(&[prevout_leaf.0.to_bytes(), control_block.serialize()]);

        tx.input[0].witness = Witness::from(witness_vec);
        tx
    }
}

fn assert_leaf() -> AssertLeaf {
    AssertLeaf {
        lock: |index, n_of_n_pubkey| {
            script! {
                { n_of_n_pubkey }
                OP_CHECKSIGVERIFY
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

// Currently only connector B.
pub fn generate_kickoff_leaves(
    n_of_n_pubkey: XOnlyPublicKey,
    operator_pubkey: XOnlyPublicKey,
) -> Vec<ScriptBuf> {
    // TODO: Single script with n_of_n_pubkey (Does something break if we don't sign with
    // operator_key?). Spendable by revealing all commitments
    todo!()
}

pub fn generate_assert_leaves(n_of_n_pubkey: XOnlyPublicKey) -> Vec<ScriptBuf> {
    // TODO: Scripts with n_of_n_pubkey and one of the commitments disprove leaves in each leaf (Winternitz signatures)
    let mut leaves = Vec::with_capacity(1000);
    let locking_template = assert_leaf().lock;
    for i in 0..1000 {
        leaves.push(locking_template(i, n_of_n_pubkey));
    }
    leaves
}

pub fn connector_c_spend_info(n_of_n_pubkey: XOnlyPublicKey) -> TaprootSpendInfo {
    let secp = Secp256k1::new();

    let scripts = generate_assert_leaves(n_of_n_pubkey);
    let script_weights = scripts.iter().map(|script| (1, script.clone()));
    TaprootBuilder::with_huffman_tree(script_weights)
        .expect("Unable to add assert leaves")
        // Finalizing with n_of_n_pubkey allows the key-path spend with the
        // n_of_n
        .finalize(&secp, n_of_n_pubkey)
        .expect("Unable to finalize assert transaction connector c taproot")
}

pub fn connector_c_address(n_of_n_pubkey: XOnlyPublicKey) -> Address {
    Address::p2tr_tweaked(
        connector_c_spend_info(n_of_n_pubkey).output_key(),
        Network::Testnet,
    )
}

#[cfg(test)]
mod tests {

    use crate::bridge::{
        client::BitVMClient,
        graph::{INITIAL_AMOUNT, N_OF_N_SECRET, OPERATOR_SECRET},
    };

    use super::*;

    use bitcoin::consensus::encode::serialize_hex;

    #[tokio::test]
    async fn test_disprove_tx() {
        let secp = Secp256k1::new();
        let n_of_n_key = Keypair::from_seckey_str(&secp, N_OF_N_SECRET).unwrap();
        let operator_key = Keypair::from_seckey_str(&secp, OPERATOR_SECRET).unwrap();
        let client = BitVMClient::new();
        let funding_utxo = client
            .get_initial_utxo(connector_c_address(n_of_n_key.x_only_public_key().0))
            .await
            .unwrap_or_else(|| {
                panic!(
                    "Fund {:?} with {} sats at https://faucet.mutinynet.com/",
                    connector_c_address(n_of_n_key.x_only_public_key().0),
                    INITIAL_AMOUNT
                );
            });
        let funding_outpoint = OutPoint {
            txid: funding_utxo.txid,
            vout: funding_utxo.vout,
        };
        let prev_tx_out = TxOut {
            value: Amount::from_sat(INITIAL_AMOUNT),
            script_pubkey: connector_c_address(n_of_n_key.x_only_public_key().0).script_pubkey(),
        };
        let mut context = BridgeContext::new();
        context.set_n_of_n_pubkey(n_of_n_key.x_only_public_key().0);
        context.set_operator_key(operator_key);

        let mut disprove_tx = DisproveTransaction::new(
            &context,
            funding_outpoint,
            Amount::from_sat(INITIAL_AMOUNT),
            1,
        );

        disprove_tx.pre_sign(&context);
        let tx = disprove_tx.finalize(&context);
        println!("Script Path Spend Transaction: {:?}\n", tx);
        let result = client.esplora.broadcast(&tx).await;
        println!("Txid: {:?}", tx.compute_txid());
        println!("Broadcast result: {:?}\n", result);
        println!("Transaction hex: \n{}", serialize_hex(&tx));
        assert!(result.is_ok());
    }
}
