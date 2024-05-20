use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_ff::{Field, One, QuadExtField};
use ark_groth16::{Proof, VerifyingKey};
use num_bigint::BigUint;

use crate::{
    bn254::{
        ell_coeffs::G2Prepared, fp254impl::Fp254Impl, fq::Fq, fq12::Fq12, msm::msm,
        pairing::Pairing as Pairing2,
    },
    groth16::checkpairing_with_c_wi_groth16::{compute_c_wi, fq12_push},
    treepp::{pushable, script, Script},
};

#[derive(Clone, Copy, Debug)]
struct Verifier {}

impl Verifier {
    pub fn verify_proof(
        public_inputs: Vec<Fr>,
        proof: &Proof<Bn254>,
        vk: &VerifyingKey<Bn254>,
    ) -> Script {
        let msm = Self::prepare_inputs(public_inputs, proof, vk);
        script! {
            { Self::verify_proof_with_prepared_inputs(proof, vk) }
        }
    }

    pub fn verify_proof_with_prepared_inputs(
        proof: &Proof<Bn254>,
        vk: &VerifyingKey<Bn254>,
    ) -> Script {
        let Q_prepared = [
            G2Prepared::from(vk.gamma_g2),
            G2Prepared::from(vk.beta_g2),
            G2Prepared::from(vk.delta_g2),
        ]
        .to_vec();
        // TODO: calculate msm
        let ai_abc_gamma = vk.alpha_g1;
        // TODO: calculate neg_a
        let neg_a = proof.a;

        let f = Bn254::multi_miller_loop(
            [ai_abc_gamma, vk.alpha_g1, proof.c, neg_a],
            [vk.gamma_g2, vk.beta_g2, vk.delta_g2, proof.b],
        )
        .0;
        let (c, wi) = compute_c_wi(f);
        let c_inv = c.inverse().unwrap();

        let hint = QuadExtField::one();

        let quad_miller_loop_with_c_wi = Pairing2::quad_miller_loop_with_c_wi(&Q_prepared);
        let p1 = ai_abc_gamma;
        let p2 = vk.alpha_g1;
        let p3 = proof.c;
        let p4 = neg_a;
        let q4 = proof.b;

        let t4 = q4.into_group();

        script! {
            { Fq::push_u32_le(&BigUint::from(p1.x).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(p1.y).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(p2.x).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(p2.y).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(p3.x).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(p3.y).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(p4.x).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(p4.y).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(q4.x.c0).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(q4.x.c1).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(q4.y.c0).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(q4.y.c1).to_u32_digits()) }
            { fq12_push(c) }
            { fq12_push(c_inv) }
            { fq12_push(wi) }

            { Fq::push_u32_le(&BigUint::from(t4.x.c0).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(t4.x.c1).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(t4.y.c0).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(t4.y.c1).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(t4.z.c0).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(t4.z.c1).to_u32_digits()) }

            { quad_miller_loop_with_c_wi.clone() }
            { fq12_push(hint) }
            { Fq12::equalverify() }
            OP_TRUE
        }
    }

    pub fn prepare_inputs(
        public_inputs: Vec<Fr>,
        proof: &Proof<Bn254>,
        vk: &VerifyingKey<Bn254>,
    ) -> Script {
        let gamma_abc_g1 = vk
            .gamma_abc_g1
            .iter()
            .map(|&g| g.into())
            .collect::<Vec<_>>();
        let msm_script = msm(&gamma_abc_g1, &public_inputs);
        msm_script
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

    // #[test]
    // fn test_msm_with_public_inputs() {
    //     println!(
    //         "G1_msm_with_public_inputs: {} bytes",
    //         Verifier::msm_with_public_inputs(2).len()
    //     );

    //     let mut prng = ChaCha20Rng::seed_from_u64(0);

    //     for _ in 0..1 {
    //         let scalar = Fr::rand(&mut prng);

    //         let p = ark_bn254::G1Projective::rand(&mut prng);
    //         let q = p.mul(scalar);
    //         let q2: ark_ec::short_weierstrass::Projective<ark_bn254::g1::Config> = q.double();

    //         /*let script = script! {
    //             { g1_projective_push(p) }
    //             { fr_push(scalar) }
    //             { G1Projective::scalar_mul() }
    //             { g1_projective_push(q) }
    //             { G1Projective::equalverify() }
    //             OP_TRUE
    //         };
    //         let exec_result = execute_script(script);
    //         assert!(exec_result.success);*/

    //         let script = script! {
    //             { g1_projective_push(p) }
    //             { fr_push(scalar) }
    //             { g1_projective_push(p) }
    //             { fr_push(scalar) }
    //             { Verifier::msm_with_public_inputs(2) }
    //             { g1_projective_push(q2) }
    //             { G1Projective::equalverify() }
    //             OP_TRUE
    //         };
    //         let exec_result = execute_script(script);
    //         assert!(exec_result.success);
    //     }
    // }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_verify_proof() {}
}
