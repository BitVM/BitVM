use bitcoin_script::script;

use crate::chunk::helpers::pack_bytes_to_limbs;
use crate::chunk::wrap_hasher::BLAKE3_HASH_LENGTH;
use crate::pseudo::NMUL;
use crate::signatures::{CompactWots, Wots, Wots16, Wots32};
use crate::treepp::Script;

pub(crate) fn checksig_verify_to_limbs(pub_key: &WOTSPubKey) -> Script {
    match pub_key {
        WOTSPubKey::PHash(pb) => {
            let sc_nib = Wots16::compact_checksig_verify(pb);
            const N0: usize = BLAKE3_HASH_LENGTH * 2;
            script! {
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
            let sc_nib = Wots32::compact_checksig_verify(pb);
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

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum WOTSPubKey {
    PHash(<Wots16 as Wots>::PublicKey),
    P256(<Wots32 as Wots>::PublicKey),
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        bn254::{fp254impl::Fp254Impl, fq::Fq},
        chunk::{
            elements::CompressedStateObject,
            helpers::extern_hash_fps,
            wrap_wots::{checksig_verify_to_limbs, WOTSPubKey},
        },
        execute_script,
    };
    use ark_ff::{Field, UniformRand};
    use bitcoin::hex::FromHex;
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
        let a_bytes: [u8; 32] = a.clone().serialize_to_byte_array().try_into().expect("should be 32 bytes");

        let secret = Vec::from_hex("a138982ce17ac813d505a5b40b665d404e9528e7").expect("should be valid hex");
        let signature = Wots32::sign(&secret, &a_bytes);

        let msg_bytes = Wots32::signature_to_message(&signature);
        assert_eq!(msg_bytes, a_bytes);
        let msg = CompressedStateObject::deserialize_from_byte_array(msg_bytes.to_vec());
        assert_eq!(a, msg);

        let compact_signature_witness = Wots32::compact_sign_to_raw_witness(&secret, &a_bytes);
        let pub_key = WOTSPubKey::P256(Wots32::generate_public_key(&secret));
        let scr = script! {
            {compact_signature_witness}
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
    fn test_wots_hash_sig_to_byte_array() {
        // wots sig to limbs
        let mut prng = ChaCha20Rng::seed_from_u64(97);
        let a = ark_bn254::Fq6::rand(&mut prng);
        let a = extern_hash_fps(
            a.to_base_prime_field_elements()
                .collect::<Vec<ark_bn254::Fq>>(),
        );
        let a = CompressedStateObject::Hash(a);
        let a_bytes: [u8; 16] = a.clone().serialize_to_byte_array().try_into().expect("should be 16 bytes");

        let secret = Vec::from_hex("a138982ce17ac813d505a5b40b665d404e9528e7").expect("should be valid hex");

        let signature = Wots16::sign(&secret, &a_bytes);
        let msg_bytes = Wots16::signature_to_message(&signature);
        assert_eq!(msg_bytes, a_bytes);
        let msg = CompressedStateObject::deserialize_from_byte_array(msg_bytes.to_vec());
        assert_eq!(a, msg);

        let compact_signature_witness = Wots16::compact_sign_to_raw_witness(&secret, &a_bytes);
        let pub_key = WOTSPubKey::PHash(Wots16::generate_public_key(&secret));
        let scr = script! {
            {compact_signature_witness}
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
        let a = extern_hash_fps(
            a.to_base_prime_field_elements()
                .collect::<Vec<ark_bn254::Fq>>(),
        );
        let a = CompressedStateObject::Hash(a);
        let a_bytes: [u8; 16] = a.clone().serialize_to_byte_array().try_into().expect("should be 16 bytes");
        let secret = Vec::from_hex("a138982ce17ac813d505a5b40b665d404e9528e7").expect("should be valid hex");
        {
            let signature = Wots16::sign(&secret, &a_bytes);
            assert!(
                signature
                    == Wots16::raw_witness_to_signature(&Wots16::signature_to_raw_witness(
                        &signature
                    ))
            );
        }
        {
            let signature = Wots16::compact_sign(&secret, &a_bytes);
            assert!(
                signature
                    == Wots16::compact_raw_witness_to_signature(
                        &Wots16::compact_signature_to_raw_witness(&signature)
                    )
            );
        }
    }
}
