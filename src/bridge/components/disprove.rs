use crate::treepp::*;
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
use super::super::graph::{FEE_AMOUNT, N_OF_N_SECRET, UNSPENDABLE_PUBKEY};

use super::bridge::*;
use super::connector_c::*;
use super::helper::*;
pub struct DisproveTransaction {
    tx: Transaction,
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<Script>,
    script_index: u32,
}

impl DisproveTransaction {
    pub fn new(
        context: &BridgeContext,
        pre_sign_input: Input,
        connector_c_input: Input,
        script_index: u32,
    ) -> Self {
        let n_of_n_pubkey = context
            .n_of_n_pubkey
            .expect("n_of_n_pubkey required in context");

        let _input0 = TxIn {
            previous_output: pre_sign_input.0,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        };

        let _input1 = TxIn {
            previous_output: connector_c_input.0,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        };

        let total_input_amount =
            pre_sign_input.1 + connector_c_input.1 - Amount::from_sat(FEE_AMOUNT); // Question: What is this fee?

        let _output0 = TxOut {
            value: total_input_amount / 2,
            script_pubkey: generate_pay_to_pubkey_script(&UNSPENDABLE_PUBKEY),
        };

        DisproveTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input0, _input1],
                output: vec![_output0],
            },
            prev_outs: vec![
                TxOut {
                    value: pre_sign_input.1,
                    script_pubkey: generate_pre_sign_address(&n_of_n_pubkey).script_pubkey(),
                },
                TxOut {
                    value: connector_c_input.1,
                    script_pubkey: generate_address(&n_of_n_pubkey).script_pubkey(),
                },
            ],
            prev_scripts: vec![generate_pre_sign_leaf0(&n_of_n_pubkey)],
            script_index,
        }
    }

    fn pre_sign_input0(
        &mut self,
        context: &BridgeContext,
        n_of_n_key: &Keypair,
        n_of_n_pubkey: &XOnlyPublicKey,
    ) {
        let input_index = 0;
        let leaf_index = 0; // TODO fix this

        let prevouts = Prevouts::All(&self.prev_outs);
        let prevout_leaf = (
            self.prev_scripts[input_index].clone(),
            LeafVersion::TapScript,
        );

        let sighash_type = TapSighashType::Single;
        let leaf_hash =
            TapLeafHash::from_script(prevout_leaf.0.clone().as_script(), prevout_leaf.1);
        let mut sighash_cache = SighashCache::new(&self.tx);
        let sighash = sighash_cache
            .taproot_script_spend_signature_hash(leaf_index, &prevouts, leaf_hash, sighash_type)
            .expect("Failed to construct sighash");

        let signature = context
            .secp
            .sign_schnorr_no_aux_rand(&Message::from(sighash), n_of_n_key); // This is where all n of n verifiers will sign
        self.tx.input[input_index].witness.push(
            bitcoin::taproot::Signature {
                signature,
                sighash_type,
            }
            .to_vec(),
        );

        let spend_info = generate_spend_info(n_of_n_pubkey).0;
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

impl BridgeTransaction for DisproveTransaction {
    fn pre_sign(&mut self, context: &BridgeContext) {
        let n_of_n_key = Keypair::from_seckey_str(&context.secp, N_OF_N_SECRET).unwrap();
        let n_of_n_pubkey = context
            .n_of_n_pubkey
            .expect("n_of_n_pubkey required in context");

        self.pre_sign_input0(context, &n_of_n_key, &n_of_n_pubkey);
    }

    fn finalize(&self, context: &BridgeContext) -> Transaction {
        let input_index = 1;

        let n_of_n_pubkey = context
            .n_of_n_pubkey
            .expect("n_of_n_pubkey required in context");

        let prevout_leaf = (
            (assert_leaf().lock)(self.script_index),
            LeafVersion::TapScript,
        );
        let spend_info = generate_spend_info(&n_of_n_pubkey).1;
        let control_block = spend_info
            .control_block(&prevout_leaf)
            .expect("Unable to create Control block");

        // Push the unlocking values, script and control_block onto the witness.
        let mut tx = self.tx.clone();
        // Unlocking script
        let mut witness_vec = (assert_leaf().unlock)(self.script_index);
        // Script and Control block
        witness_vec.extend_from_slice(&[prevout_leaf.0.to_bytes(), control_block.serialize()]);

        tx.input[input_index].witness = Witness::from(witness_vec);
        tx
    }
}

#[cfg(test)]
mod tests {

    use bitcoin::{
        key::{Keypair, Secp256k1}, Address, Amount, Network, OutPoint, TxOut
    };

    use crate::bridge::client::BitVMClient;
    use crate::bridge::context::BridgeContext;
    use crate::bridge::graph::{DEPOSITOR_SECRET, DUST_AMOUNT, INITIAL_AMOUNT, N_OF_N_SECRET, OPERATOR_SECRET, UNSPENDABLE_PUBKEY};
    use super::BridgeTransaction;
    use super::super::connector_c::*;
    use super::*;

    use bitcoin::consensus::encode::serialize_hex;

    #[tokio::test]
    async fn test_should_be_able_to_submit_disprove_tx_successfully() {
        let secp = Secp256k1::new();

        let operator_key = Keypair::from_seckey_str(&secp, OPERATOR_SECRET).unwrap();
        let n_of_n_key = Keypair::from_seckey_str(&secp, N_OF_N_SECRET).unwrap();
        let n_of_n_pubkey = n_of_n_key.x_only_public_key().0;
        let depositor_key = Keypair::from_seckey_str(&secp, DEPOSITOR_SECRET).unwrap();
        let depositor_pubkey = depositor_key.x_only_public_key().0;

        let client = BitVMClient::new();
        let funding_utxo_1 = client
            .get_initial_utxo(
                generate_address(&n_of_n_pubkey),
                Amount::from_sat(INITIAL_AMOUNT),
            )
            .await
            .unwrap_or_else(|| {
                panic!(
                    "Fund {:?} with {} sats at https://faucet.mutinynet.com/",
                    generate_address(&n_of_n_pubkey),
                    INITIAL_AMOUNT
                );
            });
        println!("funding_utxo_1.txid {}", funding_utxo_1.txid.as_raw_hash());
        println!("funding_utxo_1.value {}", funding_utxo_1.value);
        let funding_utxo_0 = client
            .get_initial_utxo(
                generate_pre_sign_address(&n_of_n_pubkey),  // TODO: should put n_of_n_pubkey alone
                // Address::from_script(&generate_pre_sign_script(n_of_n_key.x_only_public_key().0), Network::Testnet).unwrap(),
                Amount::from_sat(DUST_AMOUNT),
            )
            .await
            .unwrap_or_else(|| {
                panic!(
                    "Fund {:?} with {} sats at https://faucet.mutinynet.com/",
                    generate_pre_sign_address(&n_of_n_pubkey),
                    DUST_AMOUNT
                );
            });
        let funding_outpoint_0 = OutPoint {
            txid: funding_utxo_0.txid,
            vout: funding_utxo_0.vout,
        };
        let funding_outpoint_1 = OutPoint {
            txid: funding_utxo_1.txid,
            vout: funding_utxo_1.vout,
        };
        // let prev_tx_out_1 = TxOut {
        //     value: Amount::from_sat(INITIAL_AMOUNT),
        //     script_pubkey: connector_c_address(n_of_n_key.x_only_public_key().0).script_pubkey(),
        // };
        // let prev_tx_out_0 = TxOut {
        //     value: Amount::from_sat(DUST_AMOUNT),
        //     script_pubkey: connector_c_pre_sign_address(n_of_n_key.x_only_public_key().0)
        //         .script_pubkey(),
        // };
        let mut context = BridgeContext::new();
        context.set_operator_key(operator_key);
        context.set_n_of_n_pubkey(n_of_n_pubkey);
        context.set_unspendable_pubkey(*UNSPENDABLE_PUBKEY);
        context.set_depositor_pubkey(depositor_pubkey);

        let mut disprove_tx = DisproveTransaction::new(
            &context,
            (funding_outpoint_0, Amount::from_sat(DUST_AMOUNT)),
            (funding_outpoint_1, Amount::from_sat(INITIAL_AMOUNT)),
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

    #[tokio::test]
    async fn test_should_be_able_to_submit_disprove_tx_with_verifier_added_to_output_successfully() {
        let secp = Secp256k1::new();

        let operator_key = Keypair::from_seckey_str(&secp, OPERATOR_SECRET).unwrap();
        let n_of_n_key = Keypair::from_seckey_str(&secp, N_OF_N_SECRET).unwrap();
        let n_of_n_pubkey = n_of_n_key.x_only_public_key().0;
        let depositor_key = Keypair::from_seckey_str(&secp, DEPOSITOR_SECRET).unwrap();
        let depositor_pubkey = depositor_key.x_only_public_key().0;
        
        let client = BitVMClient::new();
        let funding_utxo_1 = client
            .get_initial_utxo(
                generate_address(&n_of_n_pubkey),
                Amount::from_sat(INITIAL_AMOUNT),
            )
            .await
            .unwrap_or_else(|| {
                panic!(
                    "Fund {:?} with {} sats at https://faucet.mutinynet.com/",
                    generate_address(&n_of_n_pubkey),
                    INITIAL_AMOUNT
                );
            });
        let funding_utxo_0 = client
            .get_initial_utxo(
                generate_pre_sign_address(&n_of_n_pubkey),
                Amount::from_sat(DUST_AMOUNT),
            )
            .await
            .unwrap_or_else(|| {
                panic!(
                    "Fund {:?} with {} sats at https://faucet.mutinynet.com/",
                    generate_pre_sign_address(&n_of_n_pubkey),
                    DUST_AMOUNT
                );
            });
        let funding_outpoint_0 = OutPoint {
            txid: funding_utxo_0.txid,
            vout: funding_utxo_0.vout,
        };
        let funding_outpoint_1 = OutPoint {
            txid: funding_utxo_1.txid,
            vout: funding_utxo_1.vout,
        };
        // let prev_tx_out_1 = TxOut {
        //     value: Amount::from_sat(INITIAL_AMOUNT),
        //     script_pubkey: connector_c_address(n_of_n_key.x_only_public_key().0).script_pubkey(),
        // };
        // let prev_tx_out_0 = TxOut {
        //     value: Amount::from_sat(DUST_AMOUNT),
        //     script_pubkey: connector_c_pre_sign_address(n_of_n_key.x_only_public_key().0)
        //         .script_pubkey(),
        // };
        let mut context = BridgeContext::new();
        context.set_operator_key(operator_key);
        context.set_n_of_n_pubkey(n_of_n_key.x_only_public_key().0);
        context.set_unspendable_pubkey(*UNSPENDABLE_PUBKEY);
        context.set_depositor_pubkey(depositor_pubkey);

        let mut disprove_tx = DisproveTransaction::new(
            &context,
            (funding_outpoint_0, Amount::from_sat(DUST_AMOUNT)),
            (funding_outpoint_1, Amount::from_sat(INITIAL_AMOUNT)),
            1,
        );

        disprove_tx.pre_sign(&context);
        let mut tx = disprove_tx.finalize(&context);

        let verifier_secret: &str = "aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeeeffffffffff1234";
        let verifier_keypair = Keypair::from_seckey_str(&secp, verifier_secret).unwrap();
        let verifier_pubkey = verifier_keypair.x_only_public_key().0;

        let verifier_output = TxOut {
            value: (Amount::from_sat(INITIAL_AMOUNT) - Amount::from_sat(FEE_AMOUNT)) / 2,
            script_pubkey: generate_pay_to_pubkey_script(&verifier_pubkey),
        };

        tx.output.push(verifier_output);

        println!("Script Path Spend Transaction: {:?}\n", tx);
        let result = client.esplora.broadcast(&tx).await;
        println!("Txid: {:?}", tx.compute_txid());
        println!("Broadcast result: {:?}\n", result);
        println!("Transaction hex: \n{}", serialize_hex(&tx));
        assert!(result.is_ok());
    }
}
