use crate::treepp::*;
use bitcoin::{
    absolute,
    sighash::{Prevouts, SighashCache},
    taproot::LeafVersion,
    Amount, Network, Sequence, TapLeafHash, TapSighashType, Transaction, TxIn, TxOut, Witness,
};
use musig2::secp256k1::Message;

use super::{
    super::{
        context::BridgeContext,
        graph::{DUST_AMOUNT, FEE_AMOUNT},
    },
    bridge::*,
    connector_2::Connector2,
    connector_3::Connector3,
    connector_b::ConnectorB,
    connector_c::ConnectorC,
    helper::*,
};

pub struct AssertTransaction {
    tx: Transaction,
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<Script>,
    connector_b: ConnectorB,
}

impl AssertTransaction {
    pub fn new(context: &BridgeContext, input0: Input) -> Self {
        let n_of_n_public_key = context
            .n_of_n_public_key
            .expect("n_of_n_public_key is required in context");

        let n_of_n_taproot_public_key = context
            .n_of_n_taproot_public_key
            .expect("n_of_n_taproot_public_key is required in context");

        let connector_2 = Connector2::new(Network::Testnet, &n_of_n_public_key);
        let connector_3 = Connector3::new(Network::Testnet, &n_of_n_public_key);
        let connector_b = ConnectorB::new(Network::Testnet, &n_of_n_taproot_public_key);
        let connector_c = ConnectorC::new(Network::Testnet, &n_of_n_taproot_public_key);

        let _input0 = connector_b.generate_taproot_leaf1_tx_in(&input0);

        let total_input_amount = input0.amount - Amount::from_sat(FEE_AMOUNT);

        let _output0 = TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: connector_2.generate_script_address().script_pubkey(),
        };

        let _output1 = TxOut {
            value: total_input_amount - Amount::from_sat(DUST_AMOUNT) * 2,
            script_pubkey: connector_3.generate_script_address().script_pubkey(),
        };

        let _output2 = TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: connector_c.generate_taproot_address().script_pubkey(),
        };

        AssertTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input0],
                output: vec![_output0, _output1, _output2],
            },
            prev_outs: vec![TxOut {
                value: input0.amount,
                script_pubkey: connector_b.generate_taproot_address().script_pubkey(),
            }],
            prev_scripts: vec![connector_b.generate_taproot_leaf1()],
            connector_b,
        }
    }
}

impl BridgeTransaction for AssertTransaction {
    fn pre_sign(&mut self, context: &BridgeContext) {
        let n_of_n_keypair = context
            .n_of_n_keypair
            .expect("n_of_n_keypair required in context");

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
        let signature = context.secp.sign_schnorr_no_aux_rand(&msg, &n_of_n_keypair);

        let signature_with_type = bitcoin::taproot::Signature {
            signature,
            sighash_type,
        };

        // Fill in the pre_sign/checksig input's witness
        let spend_info = self.connector_b.generate_taproot_spend_info();
        let control_block = spend_info
            .control_block(&prevout_leaf)
            .expect("Unable to create Control block");
        self.tx.input[0].witness.push(signature_with_type.to_vec());
        self.tx.input[0].witness.push(prevout_leaf.0.to_bytes());
        self.tx.input[0].witness.push(control_block.serialize());
    }

    fn finalize(&self, _context: &BridgeContext) -> Transaction { self.tx.clone() }
}
