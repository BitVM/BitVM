use crate::{bridge::graph::N_OF_N_SECRET, treepp::*};
use bitcoin::{
    absolute,
    key::Keypair,
    secp256k1::Message,
    sighash::{Prevouts, SighashCache},
    taproot::LeafVersion,
    Amount, Sequence, TapLeafHash, TapSighashType, Transaction, TxIn, TxOut, Witness,
    XOnlyPublicKey,
};

use super::super::context::BridgeContext;
use super::super::graph::{DEPOSITOR_SECRET, FEE_AMOUNT};

use super::bridge::*;
use super::connector_z::*;
use super::helper::*;

pub struct PegInConfirmTransaction {
    tx: Transaction,
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<Script>,
    evm_address: String,
}

impl PegInConfirmTransaction {
    pub fn new(context: &BridgeContext, input0: Input, evm_address: String) -> Self {
        let n_of_n_pubkey = context
            .n_of_n_pubkey
            .expect("n_of_n_pubkey is required in context");
        let depositor_pubkey = context
            .depositor_pubkey
            .expect("depositor_pubkey is required in context");

        let _input0 = TxIn {
            previous_output: input0.0,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        };

        let total_input_amount = input0.1 - Amount::from_sat(FEE_AMOUNT);

        let _output0 = TxOut {
            value: total_input_amount,
            script_pubkey: generate_pay_to_pubkey_script_address(&n_of_n_pubkey).script_pubkey(),
        };

        PegInConfirmTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input0],
                output: vec![_output0],
            },
            prev_outs: vec![TxOut {
                value: input0.1,
                script_pubkey: generate_address(&evm_address, &n_of_n_pubkey, &depositor_pubkey)
                    .script_pubkey(),
            }],
            prev_scripts: vec![generate_leaf1(
                &evm_address,
                &n_of_n_pubkey,
                &depositor_pubkey,
            )],
            evm_address,
        }
    }

    fn pre_sign_input0(
        &mut self,
        context: &BridgeContext,
        n_of_n_pubkey: &XOnlyPublicKey,
        depositor_key: &Keypair,
        depositor_pubkey: &XOnlyPublicKey,
    ) {
        let input_index = 0;

        let evm_address = &self.evm_address;

        let prevouts = Prevouts::All(&self.prev_outs);
        let prevout_leaf = (
            self.prev_scripts[input_index].clone(),
            LeafVersion::TapScript,
        );

        let sighash_type = TapSighashType::All;
        let leaf_hash = TapLeafHash::from_script(&prevout_leaf.0, prevout_leaf.1);

        let sighash = SighashCache::new(&self.tx)
            .taproot_script_spend_signature_hash(input_index, &prevouts, leaf_hash, sighash_type)
            .expect("Failed to construct sighash");

        let depositor_signature = context
            .secp
            .sign_schnorr_no_aux_rand(&Message::from(sighash), depositor_key);
        self.tx.input[input_index].witness.push(
            bitcoin::taproot::Signature {
                signature: depositor_signature,
                sighash_type,
            }
            .to_vec(),
        );

        let n_of_n_key = Keypair::from_seckey_str(&context.secp, N_OF_N_SECRET).unwrap();
        let n_of_n_signature = context
            .secp
            .sign_schnorr_no_aux_rand(&Message::from(sighash), &n_of_n_key);
        self.tx.input[input_index].witness.push(
            bitcoin::taproot::Signature {
                signature: n_of_n_signature,
                sighash_type,
            }
            .to_vec(),
        );

        let spend_info = generate_spend_info(evm_address, n_of_n_pubkey, depositor_pubkey);
        let control_block = spend_info
            .control_block(&prevout_leaf)
            .expect("Unable to create Control block");
        self.tx.input[input_index]
            .witness
            .push(prevout_leaf.0.to_bytes());
        self.tx.input[input_index]
            .witness
            .push(control_block.serialize());
    }
}

impl BridgeTransaction for PegInConfirmTransaction {
    fn pre_sign(&mut self, context: &BridgeContext) {
        let n_of_n_pubkey = context
            .n_of_n_pubkey
            .expect("n_of_n_pubkey required in context");

        let depositor_key = Keypair::from_seckey_str(&context.secp, DEPOSITOR_SECRET).unwrap();
        let depositor_pubkey = context
            .depositor_pubkey
            .expect("depositor_pubkey is required in context");

        self.pre_sign_input0(context, &n_of_n_pubkey, &depositor_key, &depositor_pubkey);
    }

    fn finalize(&self, context: &BridgeContext) -> Transaction { self.tx.clone() }
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
        components::{bridge::BridgeTransaction, connector_z},
        context::BridgeContext,
        graph::{
            DEPOSITOR_SECRET, DUST_AMOUNT, EVM_ADDRESS, FEE_AMOUNT, INITIAL_AMOUNT, N_OF_N_SECRET,
            ONE_HUNDRED, OPERATOR_SECRET,
        },
    };

    use super::PegInConfirmTransaction;

    #[tokio::test]
    async fn test_peg_in_confirm_tx() {
        let secp = Secp256k1::new();
        let n_of_n_key = Keypair::from_seckey_str(&secp, N_OF_N_SECRET).unwrap();
        let n_of_n_pubkey = n_of_n_key.x_only_public_key().0;
        let depositor_key = Keypair::from_seckey_str(&secp, DEPOSITOR_SECRET).unwrap();
        let depositor_pubkey = depositor_key.x_only_public_key().0;
        let client = BitVMClient::new();
        let input_value = Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT);

        let funding_utxo_address = connector_z::generate_address(
            &EVM_ADDRESS.to_string(),
            &n_of_n_pubkey,
            &depositor_pubkey,
        );
        let funding_utxo = client
            .get_initial_utxo(funding_utxo_address.clone(), input_value)
            .await
            .unwrap_or_else(|| {
                panic!(
                    "Fund {:?} with {} sats at https://faucet.mutinynet.com/",
                    funding_utxo_address,
                    input_value.to_sat()
                );
            });
        let funding_outpoint = OutPoint {
            txid: funding_utxo.txid,
            vout: funding_utxo.vout,
        };
        let mut context = BridgeContext::new();
        context.set_n_of_n_pubkey(n_of_n_pubkey);
        context.set_depositor_pubkey(depositor_pubkey);

        let mut peg_in_confirm_tx = PegInConfirmTransaction::new(
            &context,
            (funding_outpoint, input_value),
            EVM_ADDRESS.to_string(),
        );

        peg_in_confirm_tx.pre_sign(&context);
        let tx = peg_in_confirm_tx.finalize(&context);
        println!("Script Path Spend Transaction: {:?}\n", tx);
        let result = client.esplora.broadcast(&tx).await;
        println!("Txid: {:?}", tx.txid());
        println!("Broadcast result: {:?}\n", result);
        println!("Transaction hex: \n{}", serialize_hex(&tx));
        assert!(result.is_ok());
    }
}
