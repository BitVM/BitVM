use bitcoin::{
    key::Keypair,
    secp256k1::Message,
    sighash::{Prevouts, SighashCache},
    taproot::{LeafVersion, TaprootSpendInfo},
    Amount, EcdsaSighashType, PublicKey, Script, ScriptBuf, TapLeafHash, TapSighashType,
    Transaction, TxOut,
};

use super::super::{contexts::base::BaseContext, scripts::generate_p2wpkh_address};

pub fn generate_p2wsh_schnorr_signature(
    context: &dyn BaseContext,
    tx: &mut Transaction,
    input_index: usize,
    sighash_type: EcdsaSighashType,
    script: &Script,
    value: Amount,
    keypair: &Keypair,
) -> bitcoin::ecdsa::Signature {
    let mut sighash_cache = SighashCache::new(tx);

    let sighash = sighash_cache
        .p2wsh_signature_hash(input_index, script, value, sighash_type)
        .expect("Failed to construct sighash");

    let signature = context
        .secp()
        .sign_ecdsa(&Message::from(sighash), &keypair.secret_key());

    bitcoin::ecdsa::Signature {
        signature,
        sighash_type,
    }
}

pub fn push_p2wsh_signature_to_witness(
    context: &dyn BaseContext,
    tx: &mut Transaction,
    input_index: usize,
    sighash_type: EcdsaSighashType,
    script: &Script,
    value: Amount,
    keypair: &Keypair,
) {
    let signature = generate_p2wsh_schnorr_signature(
        context,
        tx,
        input_index,
        sighash_type,
        script,
        value,
        keypair,
    );

    tx.input[input_index]
        .witness
        .push_ecdsa_signature(&signature);
}

pub fn push_p2wsh_script_to_witness(tx: &mut Transaction, input_index: usize, script: &Script) {
    tx.input[input_index].witness.push(script); // TODO to_bytes() may be needed
}

pub fn populate_p2wsh_witness(
    context: &dyn BaseContext,
    tx: &mut Transaction,
    input_index: usize,
    sighash_type: EcdsaSighashType,
    script: &Script,
    value: Amount,
    keypairs: &Vec<&Keypair>,
) {
    for keypair in keypairs {
        push_p2wsh_signature_to_witness(
            context,
            tx,
            input_index,
            sighash_type,
            script,
            value,
            keypair,
        );
    }
    push_p2wsh_script_to_witness(tx, input_index, script);
}

pub fn generate_p2wpkh_schnorr_signature(
    context: &dyn BaseContext,
    tx: &mut Transaction,
    input_index: usize,
    sighash_type: EcdsaSighashType,
    value: Amount,
    public_key: &PublicKey,
    keypair: &Keypair,
) -> bitcoin::ecdsa::Signature {
    let mut sighash_cache = SighashCache::new(tx);

    let sighash = sighash_cache
        .p2wpkh_signature_hash(
            input_index,
            &generate_p2wpkh_address(context.network(), &public_key).script_pubkey(),
            value,
            sighash_type,
        )
        .expect("Failed to construct sighash");

    let signature = context
        .secp()
        .sign_ecdsa(&Message::from(sighash), &keypair.secret_key());

    bitcoin::ecdsa::Signature {
        signature,
        sighash_type,
    }
}

pub fn push_p2wpkh_signature_to_witness(
    context: &dyn BaseContext,
    tx: &mut Transaction,
    input_index: usize,
    sighash_type: EcdsaSighashType,
    value: Amount,
    public_key: &PublicKey,
    keypair: &Keypair,
) {
    let signature = generate_p2wpkh_schnorr_signature(
        context,
        tx,
        input_index,
        sighash_type,
        value,
        public_key,
        keypair,
    );

    tx.input[input_index]
        .witness
        .push_ecdsa_signature(&signature);
}

pub fn push_p2wpkh_public_key_to_witness(
    tx: &mut Transaction,
    input_index: usize,
    public_key: &PublicKey,
) {
    tx.input[input_index].witness.push(public_key.to_bytes());
}

pub fn populate_p2wpkh_witness(
    context: &dyn BaseContext,
    tx: &mut Transaction,
    input_index: usize,
    sighash_type: EcdsaSighashType,
    value: Amount,
    public_key: &PublicKey,
    keypair: &Keypair,
) {
    push_p2wpkh_signature_to_witness(
        context,
        tx,
        input_index,
        sighash_type,
        value,
        public_key,
        keypair,
    );
    push_p2wpkh_public_key_to_witness(tx, input_index, public_key);
}

pub fn generate_taproot_leaf_schnorr_signature(
    context: &dyn BaseContext,
    tx: &mut Transaction,
    prev_outs: &Vec<TxOut>,
    input_index: usize,
    sighash_type: TapSighashType,
    script: &Script,
    keypair: &Keypair,
) -> bitcoin::taproot::Signature {
    let leaf_hash = TapLeafHash::from_script(script, LeafVersion::TapScript);

    let sighash;
    if sighash_type == TapSighashType::AllPlusAnyoneCanPay
        || sighash_type == TapSighashType::SinglePlusAnyoneCanPay
        || sighash_type == TapSighashType::NonePlusAnyoneCanPay
    {
        sighash = SighashCache::new(tx)
            .taproot_script_spend_signature_hash(
                input_index,
                &Prevouts::One(input_index, &prev_outs[input_index]),
                leaf_hash,
                sighash_type,
            )
            .expect("Failed to construct sighash");
    } else {
        sighash = SighashCache::new(tx)
            .taproot_script_spend_signature_hash(
                input_index,
                &Prevouts::All(&prev_outs),
                leaf_hash,
                sighash_type,
            )
            .expect("Failed to construct sighash");
    }

    let signature = context
        .secp()
        .sign_schnorr_no_aux_rand(&Message::from(sighash), keypair);

    bitcoin::taproot::Signature {
        signature,
        sighash_type,
    }
}

pub fn push_taproot_leaf_unlock_data_to_witness(
    tx: &mut Transaction,
    input_index: usize,
    unlock_data: Vec<Vec<u8>>,
) {
    for element in unlock_data.iter() {
        if element.len() == 1 && element[0] == 0 {
            tx.input[input_index].witness.push(vec![]); // minimal encoding of 0 is an empty vector
        } else {
            tx.input[input_index].witness.push(element);
        }
    }
}

pub fn push_taproot_leaf_script_and_control_block_to_witness(
    tx: &mut Transaction,
    input_index: usize,
    taproot_spend_info: &TaprootSpendInfo,
    script: &Script,
) {
    let prevout_leaf = (ScriptBuf::from(script), LeafVersion::TapScript);

    let control_block = taproot_spend_info
        .control_block(&prevout_leaf)
        .expect("Unable to create Control block");

    tx.input[input_index]
        .witness
        .push(prevout_leaf.0.to_bytes());

    tx.input[input_index]
        .witness
        .push(control_block.serialize());
}

/// Use this function to populate taproot input witness for
/// scripts containing any logic.
pub fn populate_taproot_input_witness(
    tx: &mut Transaction,
    input_index: usize,
    taproot_spend_info: &TaprootSpendInfo,
    script: &Script,
    unlock_data: Vec<Vec<u8>>,
) {
    push_taproot_leaf_unlock_data_to_witness(tx, input_index, unlock_data);
    push_taproot_leaf_script_and_control_block_to_witness(
        tx,
        input_index,
        taproot_spend_info,
        script,
    );
}

/// Use this function to populate taproot input witness for
/// scripts containing only OP_CHECKSIG verification.
pub fn populate_taproot_input_witness_default(
    context: &dyn BaseContext,
    tx: &mut Transaction,
    prevouts: &Vec<TxOut>,
    input_index: usize,
    sighash_type: TapSighashType,
    taproot_spend_info: &TaprootSpendInfo,
    script: &Script,
    keypairs: &Vec<&Keypair>,
) {
    let mut unlock_data: Vec<Vec<u8>> = Vec::new();
    for keypair in keypairs {
        let schnorr_signature = generate_taproot_leaf_schnorr_signature(
            context,
            tx,
            prevouts,
            input_index,
            sighash_type,
            script,
            &keypair,
        );
        unlock_data.push(schnorr_signature.to_vec());
    }

    push_taproot_leaf_unlock_data_to_witness(tx, input_index, unlock_data);
    push_taproot_leaf_script_and_control_block_to_witness(
        tx,
        input_index,
        taproot_spend_info,
        script,
    );
}
