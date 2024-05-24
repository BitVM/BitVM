use crate::bn254::ell_coeffs::{G2HomProjective, G2Prepared};
use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::fq::Fq;
use crate::bn254::fq12::Fq12;
use crate::bn254::pairing::Pairing;
use crate::bn254::utils::fq12_push;
use crate::treepp::{pushable, script, Script};
use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ff::Field;
use num_bigint::BigUint;
use num_traits::One;
use std::str::FromStr;

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
pub fn groth16_verifier_script(
    eval_points: (
        ark_bn254::G1Affine,
        ark_bn254::G1Affine,
        ark_bn254::G1Affine,
    ),
    q4: ark_bn254::G2Affine,
    precompute_lines: &Vec<G2Prepared>,
    c: ark_bn254::Fq12,
    c_inv: ark_bn254::Fq12,
    wi: ark_bn254::Fq12,
    hint: ark_bn254::Fq12,
    // TODO: add msm scripts or inputs:
    msm_script: Script,
) -> Script {
    let (p2, p3, p4) = eval_points;

    let t4 = G2HomProjective {
        x: q4.x,
        y: q4.y,
        z: ark_bn254::Fq2::one(),
    };

    script! {
        // 1. push constant to stack
        {constant_script()}
        // stack: [beta_12, beta_13, beta_22, 1/2, B]

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
        { Pairing::quad_miller_loop_with_c_wi(
            precompute_lines
        ) }
        // stack: [final_f]

        // 4. check final_f == hint
        { fq12_push(hint) }
        { Fq12::equalverify() }
        OP_TRUE
    }
}

// Push constants to stack
// Return Stack: [beta_12, beta_13, beta_22, 1/2, B]
fn constant_script() -> Script {
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
