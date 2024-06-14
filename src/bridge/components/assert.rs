use crate::bridge::graph::N_OF_N_SECRET;
use crate::treepp::*;
use bitcoin::key::Keypair;
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::LeafVersion;
use bitcoin::{
    absolute, Amount, Sequence, TapLeafHash, TapSighashType, Transaction, TxIn, TxOut, Witness,
};
use musig2::secp256k1::Message;

use super::super::context::BridgeContext;
use super::super::graph::{DUST_AMOUNT, FEE_AMOUNT};

use super::bridge::*;
use super::helper::*;

pub struct AssertTransaction {
    tx: Transaction,
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<Script>,
}

impl AssertTransaction {
    pub fn new(context: &BridgeContext, input0: Input) -> Self {
        let n_of_n_pubkey = context
            .n_of_n_pubkey
            .expect("n_of_n_pubkey is required in context");

        let _input0 = TxIn {
            previous_output: input0.0,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        };

        let total_input_amount = input0.1 - Amount::from_sat(FEE_AMOUNT);

        let _output0 = TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: generate_timelock_script_address(&n_of_n_pubkey, 2).script_pubkey(),
        };

        let _output1 = TxOut {
            value: total_input_amount - Amount::from_sat(DUST_AMOUNT) * 2,
            script_pubkey: super::connector_c::generate_pre_sign_address(&n_of_n_pubkey)
                .script_pubkey(),
        };

        let _output2 = TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: super::connector_c::generate_address(&n_of_n_pubkey).script_pubkey(),
        };

        AssertTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input0],
                output: vec![_output0, _output1, _output2],
            },
            prev_outs: vec![TxOut {
                value: input0.1,
                script_pubkey: super::connector_b::generate_address(&n_of_n_pubkey).script_pubkey(),
            }],
            prev_scripts: vec![super::connector_b::generate_leaf1(&n_of_n_pubkey)],
        }
    }
}

impl BridgeTransaction for AssertTransaction {
    fn pre_sign(&mut self, context: &BridgeContext) {
        let n_of_n_key = Keypair::from_seckey_str(&context.secp, N_OF_N_SECRET).unwrap();
        let n_of_n_pubkey = context
            .n_of_n_pubkey
            .expect("n_of_n_pubkey required in context");

        let mut sighash_cache = SighashCache::new(&self.tx);
        let prevouts = Prevouts::All(&self.prev_outs);
        let prevout_leaf = (self.prev_scripts[0].clone(), LeafVersion::TapScript);

        let sighash_type = TapSighashType::All;
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

        // Fill in the pre_sign/checksig input's witness
        let spend_info = super::connector_b::generate_spend_info(&n_of_n_pubkey);
        let control_block = spend_info
            .control_block(&prevout_leaf)
            .expect("Unable to create Control block");
        self.tx.input[0].witness.push(signature_with_type.to_vec());
        self.tx.input[0].witness.push(prevout_leaf.0.to_bytes());
        self.tx.input[0].witness.push(control_block.serialize());
    }

    fn finalize(&self, _context: &BridgeContext) -> Transaction { self.tx.clone() }
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        consensus::encode::serialize_hex,
        key::{Keypair, Secp256k1},
        Amount, OutPoint,
    };

    use crate::bridge::{
        client::BitVMClient,
        components::{assert::AssertTransaction, bridge::BridgeTransaction, connector_b},
        context::BridgeContext,
        graph::{N_OF_N_SECRET, ONE_HUNDRED, OPERATOR_SECRET},
    };

    #[tokio::test]
    async fn test_assert_tx() {
        let secp = Secp256k1::new();
        let n_of_n_key = Keypair::from_seckey_str(&secp, N_OF_N_SECRET).unwrap();
        let operator_key = Keypair::from_seckey_str(&secp, OPERATOR_SECRET).unwrap();
        let client = BitVMClient::new();
        let input_value = Amount::from_sat(ONE_HUNDRED * 2 / 100);
        let funding_utxo = client
            .get_initial_utxo(
                connector_b::generate_address(&n_of_n_key.x_only_public_key().0),
                input_value,
            )
            .await
            .unwrap_or_else(|| {
                panic!(
                    "Fund {:?} with {} sats at https://faucet.mutinynet.com/",
                    connector_b::generate_address(&n_of_n_key.x_only_public_key().0),
                    input_value.to_sat()
                );
            });
        let funding_outpoint = OutPoint {
            txid: funding_utxo.txid,
            vout: funding_utxo.vout,
        };
        let mut context = BridgeContext::new();
        context.set_n_of_n_pubkey(n_of_n_key.x_only_public_key().0);
        context.set_operator_key(operator_key);

        let mut assert_tx = AssertTransaction::new(&context, (funding_outpoint, input_value));

        assert_tx.pre_sign(&context);
        let tx = assert_tx.finalize(&context);
        println!("Script Path Spend Transaction: {:?}\n", tx);
        let result = client.esplora.broadcast(&tx).await;
        println!("Txid: {:?}", tx.compute_txid());
        println!("Broadcast result: {:?}\n", result);
        println!("Transaction hex: \n{}", serialize_hex(&tx));
        assert!(result.is_ok());
    }
}
