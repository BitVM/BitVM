use crate::{
    bn254::curves::G1Projective,
    bn254::ell_coeffs::G2Prepared,
    groth16::pairing::Groth16Pairing,
    treepp::{pushable, script, Script},
};

#[derive(Clone, Copy, Debug)]
struct Verifier {}

impl Verifier {
    pub fn verify_proof(public_input_len: u32, constants: &Vec<G2Prepared>) -> Script {
        script! {
            { Self::msm_with_public_inputs(public_input_len) }
            { Groth16Pairing::quad_miller_loop_with_c_wi(constants) }
        }
    }

    // Sum a_i * pre_computation_g1, i = 0..public_input_len
    pub fn msm_with_public_inputs(public_input_len: u32) -> Script {
        script! {

            for _ in 0..public_input_len {

                { G1Projective::scalar_mul() }
                { G1Projective::toaltstack() }

            }

            for _ in 0..public_input_len {

                { G1Projective::fromaltstack() }

            }

            for _ in 1..public_input_len {

                { G1Projective::add() }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::bigint::U254;
    use crate::bn254::curves::{G1Affine, G1Projective};
    use crate::bn254::fq::Fq;
    use crate::execute_script;
    use crate::treepp::{pushable, script, Script};

    use crate::bn254::fp254impl::Fp254Impl;
    use crate::groth16::verifier::Verifier;
    use ark_bn254::Fr;
    use ark_ec::{AffineRepr, CurveGroup, Group};
    use ark_ff::{BigInteger, PrimeField};
    use ark_std::UniformRand;
    use core::ops::{Add, Mul};
    use num_bigint::BigUint;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::ops::Neg;

    fn g1_projective_push(point: ark_bn254::G1Projective) -> Script {
        script! {
            { Fq::push_u32_le(&BigUint::from(point.x).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(point.y).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(point.z).to_u32_digits()) }
        }
    }

    fn g1_affine_push(point: ark_bn254::G1Affine) -> Script {
        script! {
            { Fq::push_u32_le(&BigUint::from(point.x).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(point.y).to_u32_digits()) }
        }
    }

    fn fr_push(scalar: Fr) -> Script {
        script! {
            { U254::push_u32_le(&BigUint::from(scalar).to_u32_digits()) }
        }
    }

    #[test]
    fn test_msm_with_public_inputs() {
        println!(
            "G1_msm_with_public_inputs: {} bytes",
            Verifier::msm_with_public_inputs(2).len()
        );

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let scalar = Fr::rand(&mut prng);

            let p = ark_bn254::G1Projective::rand(&mut prng);
            let q = p.mul(scalar);
            let q2: ark_ec::short_weierstrass::Projective<ark_bn254::g1::Config> = q.double();

            /*let script = script! {
                { g1_projective_push(p) }
                { fr_push(scalar) }
                { G1Projective::scalar_mul() }
                { g1_projective_push(q) }
                { G1Projective::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);*/

            let script = script! {
                { g1_projective_push(p) }
                { fr_push(scalar) }
                { g1_projective_push(p) }
                { fr_push(scalar) }
                { Verifier::msm_with_public_inputs(2) }
                { g1_projective_push(q2) }
                { G1Projective::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}
