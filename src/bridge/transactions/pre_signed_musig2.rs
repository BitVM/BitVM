use bitcoin::{
    key::Secp256k1, taproot::TaprootSpendInfo, PublicKey, TapSighashType, XOnlyPublicKey,
};
use musig2::{
    secp::MaybeScalar,
    secp256k1::{schnorr::Signature, Message},
    BinaryEncoding, PartialSignature, PubNonce, SecNonce,
};
use std::collections::HashMap;

use super::{
    super::contexts::{base::BaseContext, verifier::VerifierContext},
    pre_signed::PreSignedTransaction,
    signing::push_taproot_leaf_script_and_control_block_to_witness,
    signing_musig2::{
        generate_aggregated_nonce, generate_nonce, generate_taproot_aggregated_signature,
        generate_taproot_partial_signature,
    },
};

pub trait PreSignedMusig2Transaction {
    fn musig2_nonces(&self) -> &HashMap<usize, HashMap<PublicKey, PubNonce>>;
    fn musig2_nonces_mut(&mut self) -> &mut HashMap<usize, HashMap<PublicKey, PubNonce>>;
    fn musig2_nonce_signatures(&self) -> &HashMap<usize, HashMap<PublicKey, Signature>>;
    fn musig2_nonce_signatures_mut(&mut self)
        -> &mut HashMap<usize, HashMap<PublicKey, Signature>>;
    fn musig2_signatures(&self) -> &HashMap<usize, HashMap<PublicKey, PartialSignature>>;
    fn musig2_signatures_mut(
        &mut self,
    ) -> &mut HashMap<usize, HashMap<PublicKey, PartialSignature>>;
}

pub fn push_nonce<T: PreSignedTransaction + PreSignedMusig2Transaction>(
    tx: &mut T,
    context: &VerifierContext,
    input_index: usize,
) -> SecNonce {
    // Push nonce
    let musig2_nonces = tx.musig2_nonces_mut();
    if musig2_nonces.get(&input_index).is_none() {
        musig2_nonces.insert(input_index, HashMap::new());
    }

    let secret_nonce = generate_nonce();
    musig2_nonces
        .get_mut(&input_index)
        .unwrap()
        .insert(context.verifier_public_key, secret_nonce.public_nonce());

    // Sign the nonce and push the signature
    let musig2_nonce_signatures = tx.musig2_nonce_signatures_mut();
    if musig2_nonce_signatures.get(&input_index).is_none() {
        musig2_nonce_signatures.insert(input_index, HashMap::new());
    }

    let nonce_signature = context.secp.sign_schnorr(
        &get_nonce_message(&secret_nonce.public_nonce()),
        &context.verifier_keypair,
    );

    musig2_nonce_signatures
        .get_mut(&input_index)
        .unwrap()
        .insert(context.verifier_public_key, nonce_signature);

    secret_nonce
}

fn get_nonce_message(nonce: &PubNonce) -> Message {
    Message::from_hashed_data::<bitcoin::hashes::sha256::Hash>(nonce.to_bytes().as_slice())
}

fn verify_schnorr_signature(sig: &Signature, msg: &Message, pubkey: &XOnlyPublicKey) -> bool {
    match Secp256k1::new().verify_schnorr(sig, msg, pubkey) {
        Ok(()) => true,
        Err(e) => {
            eprintln!("verify_schnorr() failed with: {e}");
            false
        }
    }
}

pub fn verify_public_nonce(sig: &Signature, nonce: &PubNonce, pubkey: &XOnlyPublicKey) -> bool {
    verify_schnorr_signature(sig, &get_nonce_message(nonce), pubkey)
}

pub fn pre_sign_musig2_taproot_input<T: PreSignedTransaction + PreSignedMusig2Transaction>(
    tx: &mut T,
    context: &VerifierContext,
    input_index: usize,
    sighash_type: TapSighashType,
    secret_nonce: &SecNonce,
) {
    // TODO validate nonces first

    let prev_outs = &tx.prev_outs().clone();
    let script = &tx.prev_scripts()[input_index].clone();
    let musig2_nonces = &tx.musig2_nonces()[&input_index]
        .values()
        .map(|public_nonce| public_nonce.clone())
        .collect();

    let partial_signature = generate_taproot_partial_signature(
        context,
        tx.tx_mut(),
        secret_nonce,
        &generate_aggregated_nonce(musig2_nonces),
        input_index,
        prev_outs,
        script,
        sighash_type,
    )
    .unwrap(); // TODO: Add error handling.

    let musig2_signatures = tx.musig2_signatures_mut();
    if musig2_signatures.get(&input_index).is_none() {
        musig2_signatures.insert(input_index, HashMap::new());
    }
    musig2_signatures
        .get_mut(&input_index)
        .unwrap()
        .insert(context.verifier_public_key, partial_signature);
}

pub fn finalize_musig2_taproot_input<T: PreSignedTransaction + PreSignedMusig2Transaction>(
    tx: &mut T,
    context: &dyn BaseContext,
    input_index: usize,
    sighash_type: TapSighashType,
    taproot_spend_info: TaprootSpendInfo,
) {
    // TODO: Verify we have partial signatures from all verifiers.
    // TODO: Verify each signature against the signers public key.
    // See example here: https://github.com/conduition/musig2/blob/c39bfce58098d337a3ec38b54d93def8306d9953/src/signing.rs#L358C1-L366C65

    let prev_outs = &tx.prev_outs().clone();
    let script = &tx.prev_scripts()[input_index].clone();
    let musig2_nonces: &Vec<PubNonce> = &tx.musig2_nonces()[&input_index]
        .values()
        .map(|public_nonce| public_nonce.clone())
        .collect();
    let musig2_signatures: Vec<MaybeScalar> = tx.musig2_signatures()[&input_index]
        .values()
        .map(|&partial_signature| PartialSignature::from(partial_signature))
        .collect();
    let tx_mut = tx.tx_mut();

    // Aggregate signature
    let signature = generate_taproot_aggregated_signature(
        context,
        tx_mut,
        &generate_aggregated_nonce(musig2_nonces),
        input_index,
        prev_outs,
        script,
        sighash_type,
        musig2_signatures, // TODO: Is there a more elegant way of doing this?
    )
    .unwrap(); // TODO: Add error handling.

    let final_signature = bitcoin::taproot::Signature {
        signature: signature.into(),
        sighash_type,
    };

    // Push signature to witness
    tx_mut.input[input_index]
        .witness
        .push(final_signature.serialize());

    // Push script + control block
    push_taproot_leaf_script_and_control_block_to_witness(
        tx_mut,
        input_index,
        &taproot_spend_info,
        script,
    );
}
