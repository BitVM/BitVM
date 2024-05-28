use crate::bn254::ell_coeffs::{G2HomProjective, G2Prepared};
use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::fq::Fq;
use crate::bn254::fq12::Fq12;
use crate::bn254::msm::msm;
use crate::bn254::pairing::Pairing;
use crate::bn254::utils::fq12_push;
use crate::groth16::constants::{LAMBDA, P_POW3};
use crate::groth16::offchain_checker::compute_c_wi;
use crate::treepp::{pushable, script, Script};
use ark_bn254::{Bn254, G1Projective};
use ark_ec::bn::G1Prepared;
use ark_ec::pairing::Pairing as ark_Pairing;
use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::Field;
use ark_groth16::{prepare_verifying_key, Proof, VerifyingKey};
use num_bigint::BigUint;
use num_traits::One;
use std::str::FromStr;

#[derive(Clone, Copy, Debug)]
pub struct Verifier;

impl Verifier {
    pub fn verify_proof(
        public_inputs: &Vec<<Bn254 as ark_Pairing>::ScalarField>,
        proof: &Proof<Bn254>,
        vk: &VerifyingKey<Bn254>,
    ) -> Script {
        let (msm_script, msm_g1) = Self::prepare_inputs(public_inputs, vk);
        Self::verify_proof_with_prepared_inputs(proof, vk, msm_script, msm_g1)
    }

    pub fn prepare_inputs(
        public_inputs: &Vec<<Bn254 as ark_Pairing>::ScalarField>,
        vk: &VerifyingKey<Bn254>,
    ) -> (Script, Projective<ark_bn254::g1::Config>) {
        let scalars = [
            vec![<Bn254 as ark_Pairing>::ScalarField::ONE],
            public_inputs.clone(),
        ]
        .concat();
        let sum_ai_abc_gamma =
            G1Projective::msm(&vk.gamma_abc_g1, &scalars).expect("failed to calculate msm");
        (msm(&vk.gamma_abc_g1, &scalars), sum_ai_abc_gamma)
    }

    pub fn verify_proof_with_prepared_inputs(
        proof: &Proof<Bn254>,
        vk: &VerifyingKey<Bn254>,
        msm_script: Script,
        msm_g1: Projective<ark_bn254::g1::Config>,
    ) -> Script {
        let (exp, sign) = if LAMBDA.gt(&P_POW3) {
            (&*LAMBDA - &*P_POW3, true)
        } else {
            (&*P_POW3 - &*LAMBDA, false)
        };

        let pvk = prepare_verifying_key::<Bn254>(&vk);
        let beta_prepared = (-vk.beta_g2).into();
        let gamma_g2_neg_pc = pvk.gamma_g2_neg_pc.clone().into();
        let delta_g2_neg_pc = pvk.delta_g2_neg_pc.clone().into();

        let q_prepared = [gamma_g2_neg_pc, delta_g2_neg_pc, beta_prepared].to_vec();

        let sum_ai_abc_gamma = msm_g1.into_affine();

        let a: [G1Prepared<ark_bn254::Config>; 4] = [
            sum_ai_abc_gamma.into(),
            proof.c.into(),
            vk.alpha_g1.into(),
            proof.a.into(),
        ];

        let b = [
            pvk.gamma_g2_neg_pc.clone(),
            pvk.delta_g2_neg_pc.clone(),
            (-vk.beta_g2).into(),
            proof.b.into(),
        ];

        let qap = Bn254::multi_miller_loop(a, b);
        let f = qap.0;
        let (c, wi) = compute_c_wi(f);
        let c_inv = c.inverse().unwrap();

        let hint = if sign {
            f * wi * (c_inv.pow((exp).to_u64_digits()))
        } else {
            f * wi * (c_inv.pow((exp).to_u64_digits()).inverse().unwrap())
        };

        assert_eq!(hint, c.pow(P_POW3.to_u64_digits()), "hint isn't correct!");

        let p2 = proof.c;
        let p3 = vk.alpha_g1;
        let p4 = proof.a;
        let q4 = proof.b;
        let t4 = G2HomProjective {
            x: q4.x,
            y: q4.y,
            z: ark_bn254::Fq2::one(),
        };

        script! {
            // 1. push constants to stack
            { constants() }
            // 2. push params to stack

            // 2.1 compute p1 with msm
            { msm_script }

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
            // stack: [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4]

            // 3. verifier pairing
            { check_pairing(&q_prepared, hint) }
        }
    }
}

// Groth16's pairing verifier
//
// To verify e(P1,Q1)*e(P2,Q2)*e(P3,Q3)*e(P4,Q4)=1
//
// Here is only support to verify groth16's pairing, which (Q1,Q2,Q3) are fixed, Q4 is non-fixed.
//
// params:
//  @eval_points: [P1,P2,P3]. which has fixed {Q1,Q2,Q3}
//  @P4: P4
//  @Q4: Q4
//  @lines: []precompute miller lines for Qi. Only support fixed Qi.
//  @c: c^lambda = f*w^i
//  @c_inv: inverse of c
//  @hint: expect final_f
//
// verify c^lambda = f * wi, namely c_inv^lambda * f * wi = 1
pub fn check_pairing(precompute_lines: &Vec<G2Prepared>, hint: ark_bn254::Fq12) -> Script {
    script! {
        // Input stack: [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4]
        // Output stack: [final_f]
        { Pairing::quad_miller_loop_with_c_wi(precompute_lines) }

        // 2. check final_f == hint
        { fq12_push(hint) }
        { Fq12::equalverify() }
        OP_TRUE
    }
}

// Push constants to stack
// Return Stack: [beta_12, beta_13, beta_22, 1/2, B]
fn constants() -> Script {
    script! {
        // beta_12
        { Fq::push_u32_le(&BigUint::from_str("21575463638280843010398324269430826099269044274347216827212613867836435027261").unwrap().to_u32_digits()) }
        { Fq::push_u32_le(&BigUint::from_str("10307601595873709700152284273816112264069230130616436755625194854815875713954").unwrap().to_u32_digits()) }

         // beta_13
        { Fq::push_u32_le(&BigUint::from_str("2821565182194536844548159561693502659359617185244120367078079554186484126554").unwrap().to_u32_digits()) }
        { Fq::push_u32_le(&BigUint::from_str("3505843767911556378687030309984248845540243509899259641013678093033130930403").unwrap().to_u32_digits()) }

        // beta_22
        { Fq::push_u32_le(&BigUint::from_str("21888242871839275220042445260109153167277707414472061641714758635765020556616").unwrap().to_u32_digits()) }
        { Fq::push_u32_le(&BigUint::from_str("0").unwrap().to_u32_digits()) }

        // 1/2
        { Fq::push_u32_le(&BigUint::from(ark_bn254::Fq::one().double().inverse().unwrap()).to_u32_digits()) }

        // B
        { Fq::push_u32_le(&BigUint::from(ark_bn254::g2::Config::COEFF_B.c0).to_u32_digits()) }
        { Fq::push_u32_le(&BigUint::from(ark_bn254::g2::Config::COEFF_B.c1).to_u32_digits()) }
    }
}
