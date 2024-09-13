use crate::treepp::{script, Script};
use std::rc::Rc;

use ark_ff::BigInteger;
use num_bigint::BigUint;
use num_traits::Zero;
use std::ops::{Add, Mul, Shl, Rem, Neg};

use ark_bn254::{Fr, Fq, G1Affine, G1Projective};
use ark_ec::{AffineRepr,PrimeGroup};
use ark_ff::{PrimeField, UniformRand};

use crate::schnorr_bn254::schnorr_ps_scripts::*;
use crate::schnorr_bn254::utility::*;

/*
    schnorr_ps refers to partitioned schnorr signature verification script
    using the schnorr_pr_verify_scripts::new(),
    we create a list of scripts and their intermediate inputs and outputs,
    these scripts succeed, only if the corresponding signature verification intermediate operation is incorrect
    (realize the not equal connotation at the end of all scripts of schnorr_ps_scripts.rs)
    i.e. you only need to run one of these scripts on chain to prove that the calculation was incorrect.

    exec_context is a simple struct defined just to encapsulate the input and the script
 */
pub struct exec_context {
    pub input : Vec<u8>,
    pub script : Rc<Script>,
}

pub struct schnorr_ps_verify_scripts {
    // instances of scripts of all possible computation that we clone from
    verify_e_script : Rc<Script>,
    verify_bit_product_script : Rc<Script>,
    verify_double_script : Rc<Script>,
    verify_result_script : Rc<Script>,

    // actual exec_context-s to be executed/committed on chain
    pub exec_contexts : Vec<exec_context>,
}

impl schnorr_ps_verify_scripts {
    pub fn new(data : &[u8], public_key : &G1Affine, R : &G1Affine, s : &Fr) -> (bool, schnorr_ps_verify_scripts) {
        let mut result = schnorr_ps_verify_scripts {
            verify_e_script : Rc::new(verify_e(data.len())),
            verify_bit_product_script : Rc::new(verify_bit_product()),
            verify_double_script : Rc::new(verify_double()),
            verify_result_script : Rc::new(verify_result()),

            exec_contexts : vec![],
        };

        // construct e = h(Rx || M) -> using script verify_e
        let mut hasher = blake3::Hasher::new();
        hasher.update(&serialize_bn254_element(&BigUint::from(R.x), true));
        hasher.update(&data);
        let data_hash = hasher.finalize();
        let data_hash = data_hash.as_bytes();
        let e : Fr = Fr::from_le_bytes_mod_order(data_hash);

        // push a script for calculation of e
        {
            let mut input = vec![];
            input.extend_from_slice(&serialize_bn254_element(&BigUint::from(R.x), true));
            input.extend_from_slice(data);
            input.extend_from_slice(&serialize_fr(&e));
            result.exec_contexts.push(exec_context{
                input : input,
                script : result.verify_e_script.clone(),
            });
        }

        // construct eP = e * P
        let mut eP = G1Projective::zero();
        {
            let mut power_i = G1Projective::from(*public_key);
            for i in 0..254 {
                let mut eP_next = eP.clone();
                if(e.into_bigint().get_bit(i) == true) {
                    eP_next = eP + power_i;
                }
                let power_i_next = power_i + power_i;

                // script for eP_next
                {
                    let mut input = vec![];
                    input.extend_from_slice(&serialize_g1affine(&G1Affine::from(eP_next)));
                    input.extend_from_slice(&serialize_g1affine(&G1Affine::from(power_i)));
                    input.push(i as u8);
                    input.extend_from_slice(&serialize_fr(&e));
                    input.extend_from_slice(&serialize_g1affine(&G1Affine::from(eP)));
                    result.exec_contexts.push(exec_context{
                        input : input,
                        script : result.verify_bit_product_script.clone(),
                    });
                }

                // script for power_i_next
                {
                    let mut input = vec![];
                    input.extend_from_slice(&serialize_g1affine(&G1Affine::from(power_i_next)));
                    input.extend_from_slice(&serialize_g1affine(&G1Affine::from(power_i)));
                    result.exec_contexts.push(exec_context{
                        input : input,
                        script : result.verify_double_script.clone(),
                    });
                }

                eP = eP_next;
                power_i = power_i_next;
            }
        }
        assert!((eP == (G1Projective::from(*public_key) * e)), "wrong eP");

        // construct Rv = s * G
        let mut Rv = G1Projective::zero();
        {
            let mut power_i = G1Projective::generator();
            for i in 0..254 {
                let mut Rv_next = Rv.clone();
                if(s.into_bigint().get_bit(i) == true) {
                    Rv_next = Rv + power_i;
                }
                let power_i_next = power_i + power_i;

                // script for Rv_next
                {
                    let mut input = vec![];
                    input.extend_from_slice(&serialize_g1affine(&G1Affine::from(Rv_next)));
                    input.extend_from_slice(&serialize_g1affine(&G1Affine::from(power_i)));
                    input.push(i as u8);
                    input.extend_from_slice(&serialize_fr(s));
                    input.extend_from_slice(&serialize_g1affine(&G1Affine::from(Rv)));
                    result.exec_contexts.push(exec_context{
                        input : input,
                        script : result.verify_bit_product_script.clone(),
                    });
                }

                // script for power_i_next
                {
                    let mut input = vec![];
                    input.extend_from_slice(&serialize_g1affine(&G1Affine::from(power_i_next)));
                    input.extend_from_slice(&serialize_g1affine(&G1Affine::from(power_i)));
                    result.exec_contexts.push(exec_context{
                        input : input,
                        script : result.verify_double_script.clone(),
                    });
                }

                Rv = Rv_next;
                power_i = power_i_next;
            }
        }
        assert!((Rv == G1Projective::generator().mul(s)), "wrong Rv");

        // build script for R - Rv == eP
        {
            let mut input = vec![];
            input.extend_from_slice(&serialize_g1affine(R));
            input.extend_from_slice(&serialize_g1affine(&G1Affine::from(Rv)));
            input.extend_from_slice(&serialize_g1affine(&G1Affine::from(eP)));
            result.exec_contexts.push(exec_context{
                input : input,
                script : result.verify_result_script.clone(),
            });
        }

        return ((G1Projective::from(*R).add(Rv.neg()) == eP) , result);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{run};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_schnorr_ps() {
        #[rustfmt::skip]

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let (private_key, public_key) = generate_key_pair(&mut prng);

        // generate some deterministic data
        const data_size : usize = 64;
        let mut data : [u8; data_size] = [0; data_size];
        for i in 0..data_size {
            data[i] = ((i * 13) as u8);
        }

        // sign the data promducing (R,s)
        let (R, s) = sign(&data, &private_key, &mut prng);
        assert!(verify(&data, &public_key, &R, &s), "test failed signature logic (signing or verification) incorrect");

        let (verified, scripts) = schnorr_ps_verify_scripts::new(&data, &public_key, &R, &s);
        assert!(verified, "test failed signature could not be verified in parts");

        for (i, ec) in scripts.exec_contexts.iter().enumerate() {
            println!("script no {} of size {}", i, ec.script.len());
            run(script! {
                    for x in ec.input.iter().rev() {
                        {(*x)}
                    }
                    { (*(ec.script)).clone() }
                    OP_NOT // for the tests to pass we want all scripts to return 0
                }
            );
        }
    }
}