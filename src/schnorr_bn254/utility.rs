use ark_bn254::{Fr, Fq, G1Affine, G1Projective};
use ark_ec::{AffineRepr,PrimeGroup};
use ark_ff::{PrimeField, UniformRand};
use num_bigint::BigUint;
use num_traits::Num;
use std::ops::{Add, Mul, Shl, Rem, Neg};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

fn serialize_254bit_element(s : &BigUint) -> [u8; 36] {
    let mut result : [u8; 36] = [0; 36];
    let mut bits_consumed : usize = 0;
    let mut bytes_produced : usize = 0;
    while(bits_consumed < 254) {
        for _ in 0..3 {
            for i in 0..8 {
                result[bytes_produced] |= ((s.bit(bits_consumed as u64) as u8) << i);
                bits_consumed+=1;
            }
            bytes_produced+=1;
        }
        for i in 0..5 {
            result[bytes_produced] |= ((s.bit(bits_consumed as u64) as u8) << i);
            bits_consumed+=1;
        }
        bytes_produced+=1;
    }
    return result;
}

fn deserialize_254bit_element(d : &[u8]) -> BigUint {
    let mut result : BigUint = BigUint::ZERO;
    let mut bytes_consumed : usize = 0;
    let mut bits_produced : usize = 0;
    while(bits_produced < 254) {
        for _ in 0..3 {
            for i in 0..8 {
                result.set_bit(bits_produced as u64, ((d[bytes_consumed] >> i) & 0x01) == 0x01);
                bits_produced+=1;
            }
            bytes_consumed+=1;
        }
        for i in 0..5 {
            result.set_bit(bits_produced as u64, ((d[bytes_consumed] >> i) & 0x01) == 0x01);
            bits_produced+=1;
        }
        bytes_consumed+=1;
    }

    return result;
}

pub fn serialize_bn254_element(_s : &BigUint, is_Fq : bool) -> [u8; 36] {
    let mut N : BigUint = BigUint::ZERO;
    if is_Fq {
        N = BigUint::from_str_radix("30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47", 16).unwrap();
    } else {
        N = BigUint::from_str_radix("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001", 16).unwrap();
    }
    let mut R : BigUint = BigUint::ZERO;
    if is_Fq {
        R = BigUint::from_str_radix("dc83629563d44755301fa84819caa36fb90a6020ce148c34e8384eb157ccc21", 16).unwrap();
    } else {
        R = BigUint::from_str_radix("dc83629563d44755301fa84819caa8075bba827a494b01a2fd4e1568fffff57", 16).unwrap();
    }

    let s = _s.mul(&R).rem(&N);

    return serialize_254bit_element(&s);
}

pub fn deserialize_bn254_element(d : &[u8], is_Fq : bool) -> BigUint {
    let mut N : BigUint = BigUint::ZERO;
    if is_Fq {
        N = BigUint::from_str_radix("30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47", 16).unwrap();
    } else {
        N = BigUint::from_str_radix("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001", 16).unwrap();
    }
    let mut Rinv : BigUint = BigUint::ZERO;
    if is_Fq {
        Rinv = BigUint::from_str_radix("18223d71645e71455ce0bffc0a6ec602ae5dab0851091e61fb9b65ed0584ee8b", 16).unwrap();
    } else {
        Rinv = BigUint::from_str_radix("1be7cbeb2ac214c05dee57a5ce4e849f4ee5aa561380deb5f511f723626d88cb", 16).unwrap();
    }

    return deserialize_254bit_element(d).mul(&Rinv).rem(&N);
}

pub fn serialize_g1affine(p : &G1Affine) -> [u8; 72] {
    let mut result : [u8; 72] = [0; 72];
    if p.is_zero() {
        return result;
    }
    result[0..36].copy_from_slice(&serialize_bn254_element(&BigUint::from(p.y), true));
    result[36..72].copy_from_slice(&serialize_bn254_element(&BigUint::from(p.x), true));
    return result;
}

pub fn serialize_fr(s : &Fr) -> [u8; 36] {
    return serialize_bn254_element(&BigUint::from(s.clone()), false);
}

pub fn deserialize_g1affine(b : &[u8]) -> G1Affine {
    if b.into_iter().all(|&b| b == 0) {
        return G1Affine::zero();
    }
    return G1Affine::new_unchecked(
        Fq::from(deserialize_bn254_element(&b[36..72], true)),
        Fq::from(deserialize_bn254_element(&b[0..36], true))
    );
}

pub fn deserialize_fr(b : &[u8]) -> Fr {
    return Fr::from(deserialize_bn254_element(b, false));
}

pub fn generate_key_pair(random_seed : u64) -> (Fr, G1Affine) {
    let mut prng = ChaCha20Rng::seed_from_u64(random_seed);
    let private_key : Fr = Fr::rand(&mut prng);
    let public_key : G1Affine = G1Affine::from(G1Projective::generator() * private_key);
    return (private_key, public_key);
}

pub fn sign(data : &[u8], private_key : &Fr, random_seed : u64) -> (G1Affine, Fr) {
    // k = random scalar
    let mut prng = ChaCha20Rng::seed_from_u64(random_seed);
    let k : Fr = Fr::rand(&mut prng);

    // R = kG
    let R : G1Projective = G1Projective::generator() * k;

    // e = h(Rx || M)
    let mut hasher = blake3::Hasher::new();
    hasher.update(&serialize_bn254_element(&BigUint::from(G1Affine::from(R).x), true));
    hasher.update(data);
    let data_hash = hasher.finalize();
    let data_hash = data_hash.as_bytes();
    let e : Fr = Fr::from_le_bytes_mod_order(data_hash);

    // s = (k - de) mod N
    let s : Fr = k - (*private_key) * e;

    // R, s is the siganture
    return (G1Affine::from(R), s);
}

pub fn verify(data : &[u8], public_key : &G1Affine, R : &G1Affine, s : &Fr) -> bool {
    // e = h(Rx || M)
    let mut hasher = blake3::Hasher::new();
    hasher.update(&serialize_bn254_element(&BigUint::from(R.x), true));
    hasher.update(data);
    let data_hash = hasher.finalize();
    let data_hash = data_hash.as_bytes();
    let e : Fr = Fr::from_le_bytes_mod_order(data_hash);

    // Rv = s * G
    let Rv : G1Projective = G1Projective::generator() * s;

    // R - Rv == e * P
    return (G1Projective::from(*R) + Rv.neg()) == (G1Projective::from(*public_key) * e);
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_schnorr_utility() {
        #[rustfmt::skip]

        let (private_key, public_key) = generate_key_pair(0);

        // generate some deterministic data
        const data_size : usize = 128;
        let mut data : [u8; data_size] = [0; data_size];
        for i in 0..data_size {
            data[i] = ((i * 13) as u8);
        }

        let (R, s) = sign(&data, &private_key, 1);
        
        assert!(verify(&data, &public_key, &R, &s), "test failed signature logic (signing or verification) incorrect");
        println!("signature verified !!!");
    }
}