use super::super::context::BridgeContext;
use bitcoin::{
    absolute,
    EcdsaSighashType,
    key::Keypair,
    secp256k1::Message,
    sighash::{Prevouts, SighashCache},
    taproot::LeafVersion,
    Amount, Network, Script, TapLeafHash, TapSighashType, Transaction, TxOut,
};

pub trait BridgeTransaction {
    // TODO: Use musig2 to aggregate signatures
    fn pre_sign(&mut self, context: &BridgeContext);

    // TODO: Implement default that goes through all leaves and checks if one of them is executable
    // TODO: Return a Result with an Error in case the witness can't be created
    fn finalize(&self, context: &BridgeContext) -> Transaction;

    // TODO
    // fn serialize() -> String;
    // fn deserialize() -> BridgeTransaction;
}

// pub fn pre_sign_script_input(context: &BridgeContext, tx: &mut Transaction, input_index: usize, sighash_type: EcdsaSighashType, script: &Script, value: Amount, keypair: &Keypair) {
//     let mut sighash_cache = SighashCache::new(tx);
//     let sighash = sighash_cache
//         .p2wsh_signature_hash(
//             input_index,
//             script,
//             value,
//             sighash_type,
//         )
//         .expect("Failed to construct sighash");

//     let signature = context
//         .secp
//         .sign_ecdsa(&Message::from(sighash), &keypair.secret_key());

//     tx.input[input_index]
//         .witness
//         .push_ecdsa_signature(&bitcoin::ecdsa::Signature {
//             signature,
//             sighash_type,
//         });

//     tx.input[input_index]
//         .witness
//         .push(script); // TODO to_bytes() may be needed
// }

// pub fn pre_sign_taproot_input() {
//     let input_index = 0;

//     let prevouts = Prevouts::All(&self.prev_outs);
//     let prevout_leaf = (
//         self.prev_scripts[input_index].clone(),
//         LeafVersion::TapScript,
//     );

//     let sighash_type = TapSighashType::All;
//     let leaf_hash = TapLeafHash::from_script(&prevout_leaf.0, prevout_leaf.1);

//     let sighash = SighashCache::new(&self.tx)
//         .taproot_script_spend_signature_hash(input_index, &prevouts, leaf_hash, sighash_type)
//         .expect("Failed to construct sighash");

//     let depositor_signature = context
//         .secp
//         .sign_schnorr_no_aux_rand(&Message::from(sighash), depositor_keypair);
//     self.tx.input[input_index].witness.push(
//         bitcoin::taproot::Signature {
//             signature: depositor_signature,
//             sighash_type,
//         }
//         .to_vec(),
//     );

//     let n_of_n_signature = context
//         .secp
//         .sign_schnorr_no_aux_rand(&Message::from(sighash), n_of_n_keypair);
//     self.tx.input[input_index].witness.push(
//         bitcoin::taproot::Signature {
//             signature: n_of_n_signature,
//             sighash_type,
//         }
//         .to_vec(),
//     );

//     let spend_info = self.connector_z.generate_taproot_spend_info();
//     let control_block = spend_info
//         .control_block(&prevout_leaf)
//         .expect("Unable to create Control block");
//     self.tx.input[input_index]
//         .witness
//         .push(prevout_leaf.0.to_bytes());
//     self.tx.input[input_index]
//         .witness
//         .push(control_block.serialize());
// }