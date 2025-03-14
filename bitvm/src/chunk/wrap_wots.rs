use bitcoin_script::script;

use crate::chunk::helpers::pack_bytes_to_limbs;
use crate::chunk::wrap_hasher::BLAKE3_HASH_LENGTH;
use crate::pseudo::NMUL;
use crate::treepp::Script;
use crate::signatures::wots_api::{wots_hash, wots256};



pub(crate) fn checksig_verify_to_limbs(pub_key: &WOTSPubKey) -> Script {
    match pub_key {
        WOTSPubKey::PHash(pb) => {
            let sc_nib = wots_hash::compact::checksig_verify(*pb);
            const N0: usize = BLAKE3_HASH_LENGTH*2;
            script!{
                {sc_nib}
                for _ in 0..(64-N0) { // padding
                    {0}
                }
                for i in 1..64 { // sig order reversal
                    {i} OP_ROLL
                }
                // w-window to byte array
                for _ in 0..32 { OP_SWAP { NMUL(1 << 4) } OP_ADD OP_TOALTSTACK }
                for _ in 0..32 { OP_FROMALTSTACK }
                // byte array to limbs
                {pack_bytes_to_limbs()} // equivalent to CompressedStateObject::deserialize_from_byte_array
            }
        }
        WOTSPubKey::P256(pb) => {
            let sc_nib = wots256::compact::checksig_verify(*pb);
            script! {
                {sc_nib}
                for i in 1..64 {
                    {i} OP_ROLL
                }
                for _ in 0..32 { OP_SWAP { NMUL(1 << 4) } OP_ADD OP_TOALTSTACK }
                for _ in 0..32 { OP_FROMALTSTACK }
                {pack_bytes_to_limbs()}
            }
        }
    }
}

pub(crate) fn byte_array_to_wots_hash_sig(secret: &str, msg_bytes: &[u8]) -> wots_hash::Signature {
    wots_hash::get_signature(secret, msg_bytes)
} 

pub(crate) fn byte_array_to_wots256_sig(secret: &str, msg_bytes: &[u8]) -> wots256::Signature {
    wots256::get_signature(secret, msg_bytes)
}

pub(crate) fn wots256_sig_to_byte_array(sig: wots256::Signature) -> Vec<u8> {
    let nibs = sig.map(|(_, digit)| digit);
    // [MSB, LSB, MSB, LSB, ..., checksum]
    let mut nibs = nibs[0..64].to_vec(); // remove checksum
                                         // [MSB, LSB, MSB, LSB]
    nibs.reverse(); // sigs are obtained in reverse order so undo
                    // [LSB, MSB, LSB, MSB,.., LSB]
    let nibs = nibs
        .chunks(2)
        .map(|bn| (bn[1] << 4) + bn[0]) // endian assumed by wots
        .collect::<Vec<u8>>();
    nibs
}

pub(crate) fn wots_hash_sig_to_byte_array(sig: wots_hash::Signature) -> Vec<u8> {
    let nibs = sig.map(|(_, digit)| digit);
    // [MSB, LSB, MSB, LSB, ..., checksum]
    let mut nibs = nibs[0..BLAKE3_HASH_LENGTH * 2].to_vec(); // remove checksum
                                                             // [MSB, LSB, MSB, LSB]
    nibs.reverse(); // sigs are obtained in reverse order so undo
                    // [LSB, MSB, LSB, MSB,.., LSB]
    let nibs = nibs
        .chunks(2)
        .map(|bn| (bn[1] << 4) + bn[0]) // endian assumed by wots
        .collect::<Vec<u8>>();
    nibs
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WOTSPubKey {
    PHash(wots_hash::PublicKey),
    P256(wots256::PublicKey)
}

#[cfg(test)]
mod test {
    use crate::{
        bn254::{fp254impl::Fp254Impl, fq::Fq},
        chunk::{
            elements::CompressedStateObject,
            helpers::extern_hash_fps,
            wrap_wots::{
                byte_array_to_wots_hash_sig, byte_array_to_wots256_sig, checksig_verify_to_limbs,
                wots_hash_sig_to_byte_array, wots256_sig_to_byte_array, WOTSPubKey,
            },
        },
        execute_script,
        signatures::wots_api::{wots_hash, wots256, SignatureImpl},
    };
    use ark_ff::{Field, UniformRand};
    use bitcoin_script::script;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_wots256_sig_to_byte_array() {
        // wots sig to limbs
        let mut prng = ChaCha20Rng::seed_from_u64(97);
        let f = ark_bn254::Fq::rand(&mut prng);
        let a: ark_ff::BigInt<4> = f.into();
        let a = CompressedStateObject::U256(a);
        let a_bytes = a.clone().serialize_to_byte_array();

        let secret: &str = "a138982ce17ac813d505a5b40b665d404e9528e7";
        let signature = byte_array_to_wots256_sig(secret, &a_bytes);

        let msg_bytes = wots256_sig_to_byte_array(signature);
        assert_eq!(msg_bytes, a_bytes);
        let msg = CompressedStateObject::deserialize_from_byte_array(msg_bytes);
        assert_eq!(a, msg);

        let sig_witness = signature.to_compact_script();
        let pub_key = WOTSPubKey::P256(wots256::generate_public_key(secret));
        let scr = script! {
            {sig_witness}
            {checksig_verify_to_limbs(&pub_key)}
            {a.as_hint_type().push()}
            {Fq::equalverify(1, 0)}
            OP_TRUE
        };
        let tap_len = scr.len();
        let res = execute_script(scr);
        assert!(res.success && res.final_stack.len() == 1);
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }

    #[test]
    fn test_wots160_sig_to_byte_array() {
        // wots sig to limbs
        let mut prng = ChaCha20Rng::seed_from_u64(97);
        let a = ark_bn254::Fq6::rand(&mut prng);
        let a = extern_hash_fps(
            a.to_base_prime_field_elements()
                .collect::<Vec<ark_bn254::Fq>>(),
        );
        let a = CompressedStateObject::Hash(a);
        let a_bytes = a.clone().serialize_to_byte_array();

        let secret: &str = "a138982ce17ac813d505a5b40b665d404e9528e7";

        let signature = byte_array_to_wots_hash_sig(secret, &a_bytes);
        let msg_bytes = wots_hash_sig_to_byte_array(signature);
        assert_eq!(msg_bytes, a_bytes);
        let msg = CompressedStateObject::deserialize_from_byte_array(msg_bytes);
        assert_eq!(a, msg);

        let sig_witness = signature.to_compact_script();
        let pub_key = WOTSPubKey::PHash(wots_hash::generate_public_key(secret));
        let scr = script! {
            {sig_witness}
            {checksig_verify_to_limbs(&pub_key)}
            {a.as_hint_type().push()}
            {Fq::equalverify(1, 0)}
            OP_TRUE
        };
        let tap_len = scr.len();
        let res = execute_script(scr);
        assert!(res.success && res.final_stack.len() == 1);
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }

    #[test]
    fn test_witness_signature_conversions() {
        let mut prng = ChaCha20Rng::seed_from_u64(97);
        let a = ark_bn254::Fq6::rand(&mut prng);
        let a = extern_hash_fps(a.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>());
        let a = CompressedStateObject::Hash(a);
        let a_bytes = a.clone().serialize_to_byte_array();
        let secret: &str = "a138982ce17ac813d505a5b40b665d404e9528e7";
        {
         
            let signature = wots_hash::get_signature(secret, &a_bytes);
            assert!(signature == wots_hash::raw_witness_to_signature(&wots_hash::signature_to_raw_witness(&signature)));
        }
        {
            let signature = wots_hash::compact::get_signature(secret, &a_bytes);
            assert!(signature == wots_hash::compact::raw_witness_to_signature(&wots_hash::compact::signature_to_raw_witness(&signature)));
        }
        {
            let signature = wots256::get_signature(secret, &a_bytes);
            assert!(signature == wots256::raw_witness_to_signature(&wots256::signature_to_raw_witness(&signature)));
        }
        {
            let signature = wots256::compact::get_signature(secret, &a_bytes);
            assert!(signature == wots256::compact::raw_witness_to_signature(&wots256::compact::signature_to_raw_witness(&signature)));
        }
    }
}
