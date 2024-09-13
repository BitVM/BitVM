use crate::bn254::ell_coeffs::G2Prepared;
use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::fq::Fq;
use crate::bn254::fq12::Fq12;
use crate::bn254::msm::{hinted_msm_with_constant_bases, msm_with_constant_bases};
use crate::bn254::pairing::Pairing;
use crate::bn254::utils::{fq12_push, fq12_push_not_montgomery, fq2_push, fq2_push_not_montgomery, from_eval_point, hinted_from_eval_point, Hint};
use crate::groth16::constants::{LAMBDA, P_POW3};
use crate::groth16::offchain_checker::compute_c_wi;
use crate::treepp::{script, Script};
use ark_bn254::{Bn254, G1Projective};
use ark_ec::pairing::Pairing as ark_Pairing;
use ark_ec::short_weierstrass::Projective;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::Field;
use ark_groth16::{Proof, VerifyingKey};
use core::ops::Neg;

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
        (msm_with_constant_bases(&vk.gamma_abc_g1, &scalars), sum_ai_abc_gamma)
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

        // G1/G2 points for pairings
        let (p1, p2, p3, p4) = (msm_g1.into_affine(), proof.c, vk.alpha_g1, proof.a);
        let (q1, q2, q3, q4) = (
            vk.gamma_g2.into_group().neg().into_affine(),
            vk.delta_g2.into_group().neg().into_affine(),
            -vk.beta_g2,
            proof.b,
        );
        let t4 = q4;

        // hint from arkworks
        let f = Bn254::multi_miller_loop_affine([p1, p2, p3, p4], [q1, q2, q3, q4]).0;
        let (c, wi) = compute_c_wi(f);
        let c_inv = c.inverse().unwrap();
        let hint = if sign {
            f * wi * (c_inv.pow((exp).to_u64_digits()))
        } else {
            f * wi * (c_inv.pow((exp).to_u64_digits()).inverse().unwrap())
        };
        assert_eq!(hint, c.pow(P_POW3.to_u64_digits()), "hint isn't correct!");

        let q_prepared = vec![
            G2Prepared::from_affine(q1),
            G2Prepared::from_affine(q2),
            G2Prepared::from_affine(q3),
            G2Prepared::from_affine(q4),
        ];
        script! {
            // constants
            { constants() }

            // variant of p1, say -p1.x / p1.y, 1 / p1.y
            { msm_script }
            { Fq::inv() }
            { Fq::copy(0) }
            { Fq::roll(2) }
            { Fq::neg(0) }
            { Fq::mul() }
            { Fq::roll(1) }

            // variants of G1 points
            { from_eval_point(p2) }
            { from_eval_point(p3) }
            { from_eval_point(p4) }

            // the only non-fixed G2 point, say q4
            { fq2_push(q4.x) }
            { fq2_push(q4.y) }

            // proofs for verifying final exp
            { fq12_push(c) }
            { fq12_push(c_inv) }
            { fq12_push(wi) }

            // accumulator of q4, say t4
            { fq2_push(t4.x) }
            { fq2_push(t4.y) }
            // stack: [beta_12, beta_13, beta_22, P1, P2, P3, P4, Q4, c, c_inv, wi, T4]

            // 3. verify pairing
            { check_pairing(&q_prepared, hint) }
        }
    }

    pub fn hinted_verify(
        public_inputs: &Vec<<Bn254 as ark_Pairing>::ScalarField>,
        proof: &Proof<Bn254>,
        vk: &VerifyingKey<Bn254>,
    ) -> (Script, Vec<Hint>) {
        let mut hints = Vec::new();

        let scalars = [
            vec![<Bn254 as ark_Pairing>::ScalarField::ONE],
            public_inputs.clone(),
        ]
        .concat();
        let msm_g1 = G1Projective::msm(&vk.gamma_abc_g1, &scalars).expect("failed to calculate msm");
        let (hinted_msm, hint_msm) = hinted_msm_with_constant_bases(&vk.gamma_abc_g1, &scalars);
        hints.extend(hint_msm);

        let (exp, sign) = if LAMBDA.gt(&P_POW3) {
            (&*LAMBDA - &*P_POW3, true)
        } else {
            (&*P_POW3 - &*LAMBDA, false)
        };

        // G1/G2 points for pairings
        let (p1, p2, p3, p4) = (msm_g1.into_affine(), proof.c, vk.alpha_g1, proof.a);
        let (q1, q2, q3, q4) = (
            vk.gamma_g2.into_group().neg().into_affine(),
            vk.delta_g2.into_group().neg().into_affine(),
            -vk.beta_g2,
            proof.b,
        );
        let t4 = q4;

        // hint from arkworks
        let f = Bn254::multi_miller_loop_affine([p1, p2, p3, p4], [q1, q2, q3, q4]).0;
        let (c, wi) = compute_c_wi(f);
        let c_inv = c.inverse().unwrap();
        let hint = if sign {
            f * wi * (c_inv.pow((exp).to_u64_digits()))
        } else {
            f * wi * (c_inv.pow((exp).to_u64_digits()).inverse().unwrap())
        };
        assert_eq!(hint, c.pow(P_POW3.to_u64_digits()), "hint isn't correct!");

        let q_prepared = vec![
            G2Prepared::from_affine(q1),
            G2Prepared::from_affine(q2),
            G2Prepared::from_affine(q3),
            G2Prepared::from_affine(q4),
        ];

        let p_lst = vec![p1, p2, p3, p4];

        let (hinted_script1, hint1) = Fq::hinted_inv(p1.y);
        let (hinted_script2, hint2) = Fq::hinted_mul(1, p1.x.neg(), 0, p1.y.inverse().unwrap());
        let (hinted_script3, hint3) = hinted_from_eval_point(p2);
        let (hinted_script4, hint4) = hinted_from_eval_point(p3);
        let (hinted_script5, hint5) = hinted_from_eval_point(p4);
        let (hinted_script6, hint6) = Pairing::hinted_quad_miller_loop_with_c_wi(q_prepared.to_vec(), c, c_inv, wi, p_lst, q4);

        let script_lines = [
            // constants
            constants_not_montgomery(),

            // variant of p1, say -p1.x / p1.y, 1 / p1.y
            hinted_msm,
            hinted_script1, // Fq::inv(),
            Fq::copy(0),
            Fq::roll(2),
            Fq::neg(0),
            hinted_script2, // Fq::mul()
            Fq::roll(1),

            // variants of G1 points
            hinted_script3, // utils::from_eval_point(p2),
            hinted_script4, // utils::from_eval_point(p3),
            hinted_script5, // utils::from_eval_point(p4),

            // the only non-fixed G2 point, say q4
            fq2_push_not_montgomery(q4.x),
            fq2_push_not_montgomery(q4.y),

            // proofs for verifying final exp
            fq12_push_not_montgomery(c),
            fq12_push_not_montgomery(c_inv),
            fq12_push_not_montgomery(wi),

            // accumulator of q4, say t4
            fq2_push_not_montgomery(t4.x),
            fq2_push_not_montgomery(t4.y),
            // stack: [beta_12, beta_13, beta_22, P1, P2, P3, P4, Q4, c, c_inv, wi, T4]

            // 3. verify pairing
            // Input stack: [beta_12, beta_13, beta_22, P1, P2, P3, P4, Q4, c, c_inv, wi, T4]
            // Output stack: [final_f]
            hinted_script6, // Pairing::quad_miller_loop_with_c_wi(q_prepared.to_vec()),

            // check final_f == hint
            fq12_push_not_montgomery(hint),
            Fq12::equalverify(),
            script! {OP_TRUE},
        ];
        let mut script = script! {};
        for script_line in script_lines {
            script = script.push_script(script_line.compile());
        }

        hints.extend(hint1);
        hints.extend(hint2);
        hints.extend(hint3);
        hints.extend(hint4);
        hints.extend(hint5);
        hints.extend(hint6);

        (script, hints)
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
        // Input stack: [beta_12, beta_13, beta_22, P1, P2, P3, P4, Q4, c, c_inv, wi, T4]
        // Output stack: [final_f]
        { Pairing::quad_miller_loop_with_c_wi(precompute_lines.to_vec()) }

        // check final_f == hint
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
        { Fq::push_dec("21575463638280843010398324269430826099269044274347216827212613867836435027261") }
        { Fq::push_dec("10307601595873709700152284273816112264069230130616436755625194854815875713954") }

         // beta_13
        { Fq::push_dec("2821565182194536844548159561693502659359617185244120367078079554186484126554") }
        { Fq::push_dec("3505843767911556378687030309984248845540243509899259641013678093033130930403") }

        // beta_22
        { Fq::push_dec("21888242871839275220042445260109153167277707414472061641714758635765020556616") }
        { Fq::push_zero() }
    }
}

// Push constants to stack
// Return Stack: [beta_12, beta_13, beta_22, 1/2, B]
fn constants_not_montgomery() -> Script {
    script! {
        // beta_12
        { Fq::push_dec_not_montgomery("21575463638280843010398324269430826099269044274347216827212613867836435027261") }
        { Fq::push_dec_not_montgomery("10307601595873709700152284273816112264069230130616436755625194854815875713954") }

         // beta_13
        { Fq::push_dec_not_montgomery("2821565182194536844548159561693502659359617185244120367078079554186484126554") }
        { Fq::push_dec_not_montgomery("3505843767911556378687030309984248845540243509899259641013678093033130930403") }

        // beta_22
        { Fq::push_dec_not_montgomery("21888242871839275220042445260109153167277707414472061641714758635765020556616") }
        { Fq::push_zero() }
    }
}
