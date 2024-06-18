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
use num_traits::ToBytes;

use super::super::context::BridgeContext;
use super::super::graph::{FEE_AMOUNT, N_OF_N_SECRET, OPERATOR_SECRET};

use super::bridge::*;
use super::helper::*;

pub struct Take1Transaction {
    tx: Transaction,
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<Script>,
}

impl Take1Transaction {
    pub fn new(
        context: &BridgeContext,
        input0: Input,
        input1: Input,
        input2: Input,
        input3: Input,
    ) -> Self {
        let operator_pubkey = context
            .operator_pubkey
            .expect("operator_pubkey is required in context");
        let n_of_n_pubkey = context
            .n_of_n_pubkey
            .expect("n_of_n_pubkey is required in context");
        let n_of_n_pubkey_normal = context
            .n_of_n_pubkey_normal
            .expect("n_of_n_pubkey_normal is required in context");

        let _input0 = TxIn {
            previous_output: input0.0,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        };

        let _input1 = TxIn {
            previous_output: input1.0,
            script_sig: Script::new(),
            sequence: Sequence(u32::try_from(NUM_BLOCKS_PER_WEEK * 2).ok().unwrap() & 0xFFFFFFFF),
            witness: Witness::default(),
        };

        let _input2 = TxIn {
            previous_output: input2.0,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        };

        let _input3 = TxIn {
            previous_output: input3.0,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        };

        let total_input_amount =
            input0.1 + input1.1 + input2.1 + input3.1 - Amount::from_sat(FEE_AMOUNT);

        let _output0 = TxOut {
            value: total_input_amount,
            script_pubkey: generate_pay_to_pubkey_script_address(&operator_pubkey).script_pubkey(),
        };

        Take1Transaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input0, _input1, _input2, _input3],
                output: vec![_output0],
            },
            prev_outs: vec![
                TxOut {
                    value: input0.1,
                    script_pubkey: generate_pay_to_pubkey_script_address2(&n_of_n_pubkey_normal)
                        .script_pubkey(),
                },
                TxOut {
                    value: input1.1,
                    script_pubkey: generate_timelock_script_address2(&n_of_n_pubkey_normal, 2)
                        .script_pubkey(),
                },
                TxOut {
                    value: input2.1,
                    script_pubkey: super::connector_a::generate_address(
                        &operator_pubkey,
                        &n_of_n_pubkey,
                    )
                    .script_pubkey(),
                },
                TxOut {
                    value: input3.1,
                    script_pubkey: super::connector_b::generate_address(&n_of_n_pubkey)
                        .script_pubkey(),
                },
            ],
            prev_scripts: vec![
                generate_pay_to_pubkey_script2(&n_of_n_pubkey_normal),
                generate_timelock_script2(&n_of_n_pubkey_normal, 2),
                super::connector_a::generate_leaf0(&operator_pubkey),
                super::connector_b::generate_leaf0(&n_of_n_pubkey),
            ],
        }
    }

    fn pre_sign_input0(&mut self, context: &BridgeContext, n_of_n_key: &Keypair) {
        let input_index = 0;

        let sighash_type = bitcoin::EcdsaSighashType::All;
        let mut sighash_cache = SighashCache::new(&self.tx);
        let sighash = sighash_cache
            .p2wsh_signature_hash(
                input_index,
                &self.prev_scripts[input_index],
                self.prev_outs[input_index].value,
                sighash_type,
            )
            .expect("Failed to construct sighash");

        let signature = context
            .secp
            .sign_ecdsa(&Message::from(sighash), &n_of_n_key.secret_key());
        self.tx.input[input_index]
            .witness
            .push_ecdsa_signature(&bitcoin::ecdsa::Signature {
                signature,
                sighash_type,
            });

        self.tx.input[input_index]
            .witness
            .push(&self.prev_scripts[input_index]); // TODO to_bytes() may be needed
    }

    fn pre_sign_input1(&mut self, context: &BridgeContext, n_of_n_key: &Keypair) {
        let input_index = 1;

        let sighash_type = bitcoin::EcdsaSighashType::All;
        let mut sighash_cache = SighashCache::new(&self.tx);
        let sighash = sighash_cache
            .p2wsh_signature_hash(
                input_index,
                &self.prev_scripts[input_index],
                self.prev_outs[input_index].value,
                sighash_type,
            )
            .expect("Failed to construct sighash");

        let signature = context
            .secp
            .sign_ecdsa(&Message::from(sighash), &n_of_n_key.secret_key());
        self.tx.input[input_index]
            .witness
            .push_ecdsa_signature(&bitcoin::ecdsa::Signature {
                signature,
                sighash_type,
            });

        self.tx.input[input_index]
            .witness
            .push(&self.prev_scripts[input_index]); // TODO to_bytes() may be needed
    }

    fn pre_sign_input2(
        &mut self,
        context: &BridgeContext,
        operator_key: &Keypair,
        operator_pubkey: &XOnlyPublicKey,
        n_of_n_pubkey: &XOnlyPublicKey,
    ) {
        let input_index = 2;

        let prevouts = Prevouts::All(&self.prev_outs);
        let prevout_leaf = (
            self.prev_scripts[input_index].clone(),
            LeafVersion::TapScript,
        );

        let sighash_type = TapSighashType::All;
        let leaf_hash =
            TapLeafHash::from_script(prevout_leaf.0.clone().as_script(), prevout_leaf.1);
        let mut sighash_cache = SighashCache::new(&self.tx);
        let sighash = sighash_cache
            .taproot_script_spend_signature_hash(input_index, &prevouts, leaf_hash, sighash_type)
            .expect("Failed to construct sighash");

        let signature = context
            .secp
            .sign_schnorr_no_aux_rand(&Message::from(sighash), operator_key);
        self.tx.input[input_index].witness.push(
            bitcoin::taproot::Signature {
                signature,
                sighash_type,
            }
            .to_vec(),
        );

        let spend_info = super::connector_a::generate_spend_info(operator_pubkey, n_of_n_pubkey);
        let control_block = spend_info
            .control_block(&prevout_leaf)
            .expect("Unable to create Control block");
        self.tx.input[input_index]
            .witness
            .push(prevout_leaf.0.to_bytes()); // TODO to_bytes() may NOT be needed
        self.tx.input[input_index]
            .witness
            .push(control_block.serialize());
    }

    fn pre_sign_input3(
        &mut self,
        context: &BridgeContext,
        n_of_n_key: &Keypair,
        n_of_n_pubkey: &XOnlyPublicKey,
    ) {
        let input_index = 3;

        let prevouts = Prevouts::All(&self.prev_outs);
        let prevout_leaf = (
            self.prev_scripts[input_index].clone(),
            LeafVersion::TapScript,
        );

        let sighash_type = TapSighashType::All;
        let leaf_hash =
            TapLeafHash::from_script(prevout_leaf.0.clone().as_script(), prevout_leaf.1);
        let mut sighash_cache = SighashCache::new(&self.tx);
        let sighash = sighash_cache
            .taproot_script_spend_signature_hash(input_index, &prevouts, leaf_hash, sighash_type)
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

        let spend_info = super::connector_b::generate_spend_info(n_of_n_pubkey);
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

impl BridgeTransaction for Take1Transaction {
    fn pre_sign(&mut self, context: &BridgeContext) {
        let n_of_n_key = Keypair::from_seckey_str(&context.secp, N_OF_N_SECRET).unwrap();
        let n_of_n_pubkey = context
            .n_of_n_pubkey
            .expect("n_of_n_pubkey required in context");

        let operator_key = Keypair::from_seckey_str(&context.secp, OPERATOR_SECRET).unwrap();
        let operator_pubkey = context
            .operator_pubkey
            .expect("operator_pubkey is required in context");

        self.pre_sign_input0(context, &n_of_n_key);
        self.pre_sign_input1(context, &n_of_n_key);
        self.pre_sign_input2(context, &operator_key, &operator_pubkey, &n_of_n_pubkey);
        self.pre_sign_input3(context, &n_of_n_key, &n_of_n_pubkey);
    }

    fn finalize(&self, context: &BridgeContext) -> Transaction { self.tx.clone() }
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        consensus::encode::serialize_hex,
        key::{Keypair, Secp256k1},
        Amount, PublicKey,
    };

    use crate::bridge::{
        client::BitVMClient,
        components::{
            bridge::BridgeTransaction,
            connector_a, connector_b,
            helper::generate_pay_to_pubkey_script_address,
            take1::{
                generate_pay_to_pubkey_script_address2, generate_timelock_script_address,
                generate_timelock_script_address2, Take1Transaction,
            },
        },
        context::BridgeContext,
        graph::{
            DUST_AMOUNT, FEE_AMOUNT, INITIAL_AMOUNT, N_OF_N_SECRET, ONE_HUNDRED, OPERATOR_SECRET,
        },
        tests::helper::generate_stub_outpoint,
    };

    #[tokio::test]
    async fn test_take1_tx() {
        let secp = Secp256k1::new();
        let client = BitVMClient::new();
        let operator_key = Keypair::from_seckey_str(&secp, OPERATOR_SECRET).unwrap();
        let operator_pubkey = operator_key.x_only_public_key().0;
        let n_of_n_key = Keypair::from_seckey_str(&secp, N_OF_N_SECRET).unwrap();
        let n_of_n_pubkey = n_of_n_key.x_only_public_key().0;
        let n_of_n_pubkey_normal = PublicKey::from(n_of_n_key.public_key());

        let input_value0 = Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT);
        let funding_utxo_address0 = generate_pay_to_pubkey_script_address2(&n_of_n_pubkey_normal);
        let funding_outpoint0 =
            generate_stub_outpoint(&client, &funding_utxo_address0, input_value0).await;

        let input_value1 = Amount::from_sat(DUST_AMOUNT);
        let funding_utxo_address1 = generate_timelock_script_address2(&n_of_n_pubkey_normal, 2);
        let funding_outpoint1 =
            generate_stub_outpoint(&client, &funding_utxo_address1, input_value1).await;

        let input_value2 = Amount::from_sat(DUST_AMOUNT);
        let funding_utxo_address2 = connector_a::generate_address(&operator_pubkey, &n_of_n_pubkey);
        let funding_outpoint2 =
            generate_stub_outpoint(&client, &funding_utxo_address2, input_value2).await;

        let input_value3 = Amount::from_sat(ONE_HUNDRED * 2 / 100);
        let funding_utxo_address3 = connector_b::generate_address(&n_of_n_pubkey);
        let funding_outpoint3 =
            generate_stub_outpoint(&client, &funding_utxo_address3, input_value3).await;

        let mut context = BridgeContext::new();
        context.set_n_of_n_pubkey(n_of_n_pubkey);
        context.set_n_of_n_pubkey_normal(n_of_n_pubkey_normal);
        context.set_operator_key(operator_key);

        let mut take1_tx = Take1Transaction::new(
            &context,
            (funding_outpoint0, input_value0),
            (funding_outpoint1, input_value1),
            (funding_outpoint2, input_value2),
            (funding_outpoint3, input_value3),
        );

        take1_tx.pre_sign(&context);
        let tx = take1_tx.finalize(&context);
        println!("Script Path Spend Transaction: {:?}\n", tx);
        let result = client.esplora.broadcast(&tx).await;
        println!("Txid: {:?}", tx.txid());
        println!("Broadcast result: {:?}\n", result);
        println!("Transaction hex: \n{}", serialize_hex(&tx));
        assert!(result.is_ok());
    }
}
