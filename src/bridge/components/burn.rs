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
use super::super::graph::FEE_AMOUNT;

use super::bridge::*;
use super::connector_b::*;
use super::helper::*;
pub struct BurnTransaction {
    tx: Transaction,
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<Script>,
    num_block_connector_b_timelock: u32,
}

impl BurnTransaction {
    pub fn new(context: &BridgeContext, input0: Input, num_block_connector_b_timelock: u32) -> Self {
        let n_of_n_taproot_public_key = context
            .n_of_n_taproot_public_key
            .expect("n_of_n_taproot_public_key is required in context");

        let _input0 = TxIn {
            previous_output: input0.outpoint,
            script_sig: Script::new(),
            sequence: Sequence(num_block_connector_b_timelock),
            witness: Witness::default(),
        };

        let total_input_amount = input0.amount - Amount::from_sat(FEE_AMOUNT);

        // Output[0]: value=V*2%*95% to burn
        let _output0 = TxOut {
            value: total_input_amount * 95 / 100,
            script_pubkey: generate_pay_to_pubkey_script(&UNSPENDABLE_PUBKEY), // TODO： should use op_return script for burning, but esplora does not support maxburnamount parameter  
        };

        BurnTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input0],
                output: vec![_output0],
            },
            prev_outs: vec![TxOut {
                value: input0.amount,
                script_pubkey: generate_taproot_address(&n_of_n_taproot_public_key, num_block_connector_b_timelock).script_pubkey(),
            }],
            prev_scripts: vec![generate_taproot_leaf2(&n_of_n_taproot_public_key, num_block_connector_b_timelock)],
            num_block_connector_b_timelock,
        }
    }

    fn pre_sign_input0(
        &mut self,
        context: &BridgeContext,
        n_of_n_keypair: &Keypair,
        n_of_n_taproot_public_key: &XOnlyPublicKey,
    ) {
        let input_index = 0;

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
            .taproot_script_spend_signature_hash(input_index, &prevouts, leaf_hash, sighash_type)
            .expect("Failed to construct sighash");

        let signature = context
            .secp
            .sign_schnorr_no_aux_rand(&Message::from(sighash), n_of_n_keypair); // This is where all n of n verifiers will sign
        self.tx.input[input_index].witness.push(
            bitcoin::taproot::Signature {
                signature,
                sighash_type,
            }
            .to_vec(),
        );

        let spend_info = generate_taproot_spend_info(n_of_n_taproot_public_key, self.num_block_connector_b_timelock);
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

impl BridgeTransaction for BurnTransaction {
    fn pre_sign(&mut self, context: &BridgeContext) {
        let n_of_n_keypair = context
            .n_of_n_keypair
            .expect("n_of_n_keypair required in context");

        let n_of_n_taproot_public_key = context
            .n_of_n_taproot_public_key
            .expect("n_of_n_taproot_public_key required in context");

        self.pre_sign_input0(context, &n_of_n_keypair, &n_of_n_taproot_public_key);
    }

    fn finalize(&self, context: &BridgeContext) -> Transaction {
        self.tx.clone()
    }
}

#[cfg(test)]
mod tests {

    use bitcoin::{
        consensus::encode::serialize_hex, key::{Keypair, Secp256k1}, Amount, OutPoint, TxOut
    };

    use crate::bridge::client::BitVMClient;
    use crate::bridge::context::BridgeContext;
    use crate::bridge::graph::{INITIAL_AMOUNT, N_OF_N_SECRET, OPERATOR_SECRET, DEPOSITOR_SECRET};
    use crate::bridge::components::bridge::BridgeTransaction;
    use crate::bridge::components::connector_b::*;
    use super::*;

    #[tokio::test]
    async fn test_should_be_able_to_submit_burn_tx_successfully() {
        let secp = Secp256k1::new();
        
        let operator_key = Keypair::from_seckey_str(&secp, OPERATOR_SECRET).unwrap();
        let n_of_n_key = Keypair::from_seckey_str(&secp, N_OF_N_SECRET).unwrap();
        let n_of_n_pubkey = n_of_n_key.x_only_public_key().0;
        let depositor_key = Keypair::from_seckey_str(&secp, DEPOSITOR_SECRET).unwrap();
        let depositor_pubkey = depositor_key.x_only_public_key().0;
        let num_blocks_timelock = 120; // 1 hour on mutinynet

        let client = BitVMClient::new();

        let funding_utxo_0 = client
            .get_initial_utxo(
                generate_taproot_address(&n_of_n_pubkey, num_blocks_timelock),
                Amount::from_sat(INITIAL_AMOUNT),
            )
            .await
            .unwrap_or_else(|| {
                panic!(
                    "Fund {:?} with {} sats at https://faucet.mutinynet.com/",
                    generate_taproot_address(&n_of_n_pubkey, num_blocks_timelock),
                    INITIAL_AMOUNT
                );
            });

        let funding_outpoint_0 = OutPoint {
            txid: funding_utxo_0.txid,
            vout: funding_utxo_0.vout,
        };

        let mut context = BridgeContext::new();
        context.set_operator_key(operator_key);
        context.set_n_of_n_pubkey(n_of_n_pubkey);
        context.set_unspendable_pubkey(*UNSPENDABLE_PUBKEY);
        context.set_depositor_pubkey(depositor_pubkey);

        let mut burn_tx = BurnTransaction::new(
            &context,
            Input {
                outpoint: funding_outpoint_0,
                amount: Amount::from_sat(INITIAL_AMOUNT)
            },
            num_blocks_timelock
        );

        burn_tx.pre_sign(&context);
        let tx = burn_tx.finalize(&context);
        println!("Script Path Spend Transaction: {:?}\n", tx);

        let result = client.esplora.broadcast(&tx).await;
        println!("Txid: {:?}", tx.compute_txid());
        println!("Broadcast result: {:?}\n", result);
        println!("Transaction hex: \n{}", serialize_hex(&tx));
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_should_be_able_to_submit_burn_tx_with_verifier_added_to_output_successfully() {
        let secp = Secp256k1::new();
        
        let operator_key = Keypair::from_seckey_str(&secp, OPERATOR_SECRET).unwrap();
        let n_of_n_key = Keypair::from_seckey_str(&secp, N_OF_N_SECRET).unwrap();
        let n_of_n_pubkey = n_of_n_key.x_only_public_key().0;
        let depositor_key = Keypair::from_seckey_str(&secp, DEPOSITOR_SECRET).unwrap();
        let depositor_pubkey = depositor_key.x_only_public_key().0;
        let num_blocks_timelock = 0;

        let client = BitVMClient::new();

        let funding_utxo_0 = client
            .get_initial_utxo(
                generate_address(&n_of_n_pubkey, num_blocks_timelock),
                Amount::from_sat(INITIAL_AMOUNT),
            )
            .await
            .unwrap_or_else(|| {
                panic!(
                    "Fund {:?} with {} sats at https://faucet.mutinynet.com/",
                    generate_address(&n_of_n_pubkey, num_blocks_timelock),
                    INITIAL_AMOUNT
                );
            });

        let funding_outpoint_0 = OutPoint {
            txid: funding_utxo_0.txid,
            vout: funding_utxo_0.vout,
        };

        let mut context = BridgeContext::new();
        context.set_operator_key(operator_key);
        context.set_n_of_n_pubkey(n_of_n_pubkey);
        context.set_unspendable_pubkey(*UNSPENDABLE_PUBKEY);
        context.set_depositor_pubkey(depositor_pubkey);

        let mut burn_tx = BurnTransaction::new(
            &context,
            Input {
                outpoint: funding_outpoint_0,
                amount: Amount::from_sat(INITIAL_AMOUNT)
            },
            num_blocks_timelock
        );

        burn_tx.pre_sign(&context);
        let mut tx = burn_tx.finalize(&context);

        let verifier_secret: &str = "aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeeeffffffffff1234";
        let verifier_key = Keypair::from_seckey_str(&secp, verifier_secret).unwrap();

        let verifier_output = TxOut {
            value: (Amount::from_sat(INITIAL_AMOUNT) - Amount::from_sat(FEE_AMOUNT)) * 5 / 100,
            script_pubkey: generate_pay_to_pubkey_script(&verifier_key.x_only_public_key().0),
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