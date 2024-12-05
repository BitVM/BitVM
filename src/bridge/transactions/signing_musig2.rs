use bitcoin::{
    sighash::{Prevouts, SighashCache},
    taproot::LeafVersion,
    Script, TapLeafHash, TapSighashType, Transaction, TxOut,
};
use musig2::{
    aggregate_partial_signatures,
    errors::{SigningError, VerifyError},
    secp::{MaybeScalar, Point},
    sign_partial, AggNonce, KeyAggContext, LiftedSignature, PartialSignature, PubNonce, SecNonce,
};

use super::super::contexts::{base::BaseContext, verifier::VerifierContext};

pub fn generate_nonce() -> SecNonce { SecNonce::build(&mut rand::rngs::OsRng).build() }

pub fn generate_aggregated_nonce(nonces: &Vec<PubNonce>) -> AggNonce { AggNonce::sum(nonces) }

pub fn generate_taproot_partial_signature(
    context: &VerifierContext,
    tx: &Transaction,
    secret_nonce: &SecNonce,
    aggregated_nonce: &AggNonce,
    input_index: usize,
    prevouts: &Vec<TxOut>,
    script: &Script,
    sighash_type: TapSighashType,
) -> Result<MaybeScalar, SigningError> {
    let pubkeys: Vec<Point> = Vec::from_iter(
        context
            .n_of_n_public_keys
            .iter()
            .map(|&public_key| public_key.inner.into()),
    ); // TODO: The tests will reveal whether this conversion works as expected.
    let key_agg_ctx = KeyAggContext::new(pubkeys).unwrap();

    let leaf_hash = TapLeafHash::from_script(script, LeafVersion::TapScript);
    let sighash = SighashCache::new(tx)
        .taproot_script_spend_signature_hash(
            input_index,
            &Prevouts::All(prevouts), // TODO: add Prevouts::One
            leaf_hash,
            sighash_type,
        )
        .expect("Failed to construct sighash");

    sign_partial(
        &key_agg_ctx,
        context.verifier_keypair.secret_key(),
        secret_nonce.clone(),
        aggregated_nonce,
        sighash,
    )
}

pub fn generate_taproot_aggregated_signature(
    context: &dyn BaseContext,
    tx: &Transaction,
    aggregated_nonce: &AggNonce,
    input_index: usize,
    prevouts: &Vec<TxOut>,
    script: &Script,
    sighash_type: TapSighashType,
    partial_signatures: Vec<PartialSignature>,
) -> Result<LiftedSignature, VerifyError> {
    let pubkeys: Vec<Point> = Vec::from_iter(
        context
            .n_of_n_public_keys()
            .iter()
            .map(|&public_key| public_key.inner.into()),
    );
    let key_agg_ctx = KeyAggContext::new(pubkeys).unwrap();

    let leaf_hash = TapLeafHash::from_script(script, LeafVersion::TapScript);
    let sighash_cache = SighashCache::new(tx)
        .taproot_script_spend_signature_hash(
            input_index,
            &Prevouts::All(prevouts), // TODO: add Prevouts::One
            leaf_hash,
            sighash_type,
        )
        .expect("Failed to construct sighash");

    aggregate_partial_signatures(
        &key_agg_ctx,
        aggregated_nonce,
        partial_signatures,
        sighash_cache,
    )
}

// TODO: This is currently unused and can be removed. If the conversion at the start of the above functions is incorrect, try this approach.
// pub fn to_point(public_key: PublicKey) -> Point {
//     Point::from_slice(&public_key.to_bytes()).unwrap() // TODO: Add error handling. Also, verify this method is correct (otherwise see conversion via secp256k1::PublicKey).
// }
