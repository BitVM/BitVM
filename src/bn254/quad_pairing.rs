use crate::bn254::ell_coeffs::G2Prepared;
use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::fq12::Fq12;
use crate::bn254::pairing::Pairing;
use crate::bn254::utils;
use crate::bn254::{fq::Fq, fq2::Fq2};
use crate::treepp::*;
use ark_ec::bn::BnConfig;
pub struct QuadPairing;

impl QuadPairing {
    /// input on stack:
    ///     [P1, P2, P3, P4, Q4, T4]
    ///     [2,  2,  2,  2,  4,  4] (16 stack elements in total)
    ///     P1, P2, P3, P4 are in affine form, such as P1: (-p1.x / p1.y, 1 / p1.y)
    ///     2 means 2 Fq elements, 4 means 4 fp elements
    ///     Q1, Q2 and Q3 are fixed, Q4 is provided by prover
    ///     T4 is accumulator for Q4, initial T4 = Q4, will do double and add operations for T4

    /// input of parameters:
    ///     [L(Q1), L(Q2), L(Q3), L(Q4)] (line coefficients)
    pub fn quad_miller_loop_affine(constants: Vec<G2Prepared>) -> Script {
        assert_eq!(constants.len(), 4);
        let num_line_groups = constants.len();
        let num_constant = 3;

        let line_coeffs = utils::collect_line_coeffs(constants);
        let num_lines = line_coeffs.len();

        let script = script! {
            { Fq12::push_one() }
            // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]

            for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
                // square f
                if i != ark_bn254::Config::ATE_LOOP_COUNT.len() - 1 {
                    { Fq12::square() }
                }
                // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]

                // double line
                for j in 0..num_line_groups {
                    // update f with double line evaluation
                    { Fq2::copy((26 - j * 2) as u32) }
                    { Pairing::ell_by_constant_affine(&line_coeffs[num_lines - (i + 2)][j][0]) }
                    // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]

                    // non-constant part
                    if j == num_constant {
                        // check line coeff is satisfied with T4
                        { Fq12::toaltstack() }
                        { Fq2::copy(2) }
                        { Fq2::copy(2) }
                        { utils::check_tangent_line(line_coeffs[num_lines - (i + 2)][j][0].1, line_coeffs[num_lines - (i + 2)][j][0].2) }
                        // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4) | f(12)]

                        // update T4
                        { Fq2::drop() }
                        { utils::affine_double_line(line_coeffs[num_lines - (i + 2)][j][0].1, line_coeffs[num_lines - (i + 2)][j][0].2) }
                        { Fq12::fromaltstack() }
                        // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]
                    }
                }

                // add line
                if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == 1 || ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == -1 {
                    for j in 0..num_line_groups {
                        // update f with add line evaluation
                        { Fq2::copy((26 - j * 2) as u32) }
                        { Pairing::ell_by_constant_affine(&line_coeffs[num_lines - (i + 2)][j][1]) }
                        // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]

                        // non-constant part
                        if j == num_constant {
                            { Fq12::toaltstack() }
                            { Fq2::copy(2) }
                            { Fq2::copy(2) }
                            { Fq2::copy(10) }
                            { Fq2::copy(10) }
                            // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), T4(4), Q4(4) | f(12)]
                            if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == -1 {
                                { Fq2::neg(0) }
                            }
                            { utils::check_chord_line(line_coeffs[num_lines - (i + 2)][j][1].1, line_coeffs[num_lines - (i + 2)][j][1].2) }
                            // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]

                            // update T4
                            { Fq2::drop() }
                            { Fq2::copy(4) }
                            // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4.x(2), Q4.x(2) | f(12)]
                            { utils::affine_add_line(line_coeffs[num_lines - (i + 2)][j][1].1, line_coeffs[num_lines - (i + 2)][j][1].2) }
                            { Fq12::fromaltstack() }
                            // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]
                        }
                    }
                }
            }

            // one-time of frobenius map
            for j in 0..num_line_groups {
                // update f with add line evaluation
                { Fq2::copy((26 - j * 2) as u32) }
                { Pairing::ell_by_constant_affine(&line_coeffs[num_lines - 2][j][0]) }
                // [beta_12(2), beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]

                // non-constant part
                if j == num_constant {
                    { Fq12::toaltstack() }

                    ////////// phi(Q) = (Qx', Qy')
                    // Qx' = Qx.conjugate * beta^{2 * (p - 1) / 6}
                    { Fq2::copy(6) }
                    { Fq::neg(0) }
                    { Fq2::roll(22) }
                    { Fq2::mul(2, 0) }
                    // [beta_13(2), beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), Q4.x' * beta_12 (2) | f(12)]

                    // Qy' = Qy.conjugate * beta^{3 * (p - 1) / 6}
                    { Fq2::copy(6) }
                    { Fq::neg(0) }
                    { Fq2::roll(22) }
                    { Fq2::mul(2, 0) }
                    // [beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), Q4.x' * beta_12 (2), Q4.y' * beta_13 (2) | f(12)]
                    // [beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), phi(Q)(4) | f(12)]

                    /////////// check chord line
                    { Fq2::copy(6) }
                    { Fq2::copy(6) }
                    { Fq2::copy(6) }
                    { Fq2::copy(6) }
                    { utils::check_chord_line(line_coeffs[num_lines - 2][j][0].1, line_coeffs[num_lines - 2][j][0].2) }
                    // [beta_22(2), P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), phi(Q)(4) | f(12)]

                    // update T4
                    { Fq2::drop() }
                    { Fq2::toaltstack() }
                    { Fq2::drop() }
                    { Fq2::fromaltstack() }
                    // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4.x(2), phi(Q4).x(2) | f(12)]
                    { utils::affine_add_line(line_coeffs[num_lines - 2][j][0].1, line_coeffs[num_lines - 2][j][0].2) }
                    { Fq12::fromaltstack() }
                    // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]
                }
            }

            // two-times of frobenius map
            for j in 0..num_line_groups {
                //////////// update f with add line evaluation
                { Fq2::roll((26 - j * 2) as u32) }
                { Pairing::ell_by_constant_affine(&line_coeffs[num_lines - 1][j][0]) }
                // [beta_22(2), Q4(4), T4(4), f(12)]

                // non-constant part
                if j == num_constant {
                    { Fq12::toaltstack() }

                    ////////// phi(Q)^2 = (Qx', Qy)
                    // Qx' = Qx * beta^{2 * (p^2 - 1) / 6}
                    { Fq2::roll(8) }
                    { Fq2::roll(8) }
                    { Fq2::mul(2, 0) }
                    { Fq2::roll(6) }
                    // [T4(4), phi(Q4)^2 | f(12)]

                    /////////// check whether the chord line through T4 and phi(Q4)^2
                    { utils::check_chord_line(line_coeffs[num_lines - 1][j][0].1, line_coeffs[num_lines - 1][j][0].2) }
                    { Fq12::fromaltstack() }
                    // [f(12)]
                }
            }
        };
        script
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;
    use crate::{
        bn254::{
            ell_coeffs::G2Prepared,
            fq12::Fq12,
            quad_pairing::QuadPairing,
            utils::{self, fq12_push, fq2_push},
        },
        execute_script_without_stack_limit,
    };
    use ark_bn254::Bn254;
    use ark_ec::pairing::Pairing as _;
    use ark_ff::UniformRand;
    use num_bigint::BigUint;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_quad_miller_loop_affine() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let p1 = ark_bn254::G1Affine::rand(&mut prng);
        let p2 = ark_bn254::G1Affine::rand(&mut prng);
        let p3 = ark_bn254::G1Affine::rand(&mut prng);
        let p4 = ark_bn254::G1Affine::rand(&mut prng);

        let q1 = ark_bn254::g2::G2Affine::rand(&mut prng);
        let q2 = ark_bn254::g2::G2Affine::rand(&mut prng);
        let q3 = ark_bn254::g2::G2Affine::rand(&mut prng);
        let q4 = ark_bn254::g2::G2Affine::rand(&mut prng);
        let q1_prepared = G2Prepared::from_affine(q1);
        let q2_prepared = G2Prepared::from_affine(q2);
        let q3_prepared = G2Prepared::from_affine(q3);
        let q4_prepared = G2Prepared::from_affine(q4);

        let t4 = q4;

        let quad_miller_loop_affine_script = QuadPairing::quad_miller_loop_affine(
            [q1_prepared, q2_prepared, q3_prepared, q4_prepared].to_vec(),
        );
        println!(
            "Pairing.quad_miller_loop: {} bytes",
            quad_miller_loop_affine_script.len()
        );

        let hint = Bn254::multi_miller_loop_affine([p1, p2, p3, p4], [q1, q2, q3, q4]).0;
        println!("Bn254::multi_miller_loop_affine done!");

        // [beta_12, beta_13, beta_22, p1, p2, p3, p4, q4, t4]: p1-p4: (-p.x / p.y, 1 / p.y)
        let script = script! {
            { Fq::push_u32_le(&BigUint::from_str("21575463638280843010398324269430826099269044274347216827212613867836435027261").unwrap().to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from_str("10307601595873709700152284273816112264069230130616436755625194854815875713954").unwrap().to_u32_digits()) }

            { Fq::push_u32_le(&BigUint::from_str("2821565182194536844548159561693502659359617185244120367078079554186484126554").unwrap().to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from_str("3505843767911556378687030309984248845540243509899259641013678093033130930403").unwrap().to_u32_digits()) }

            { Fq::push_u32_le(&BigUint::from_str("21888242871839275220042445260109153167277707414472061641714758635765020556616").unwrap().to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from_str("0").unwrap().to_u32_digits()) }

            { utils::from_eval_point(p1) }
            { utils::from_eval_point(p2) }
            { utils::from_eval_point(p3) }
            { utils::from_eval_point(p4) }

            { fq2_push(q4.x) }
            { fq2_push(q4.y) }

            { fq2_push(t4.x) }
            { fq2_push(t4.y) }

            { quad_miller_loop_affine_script.clone() }

            { fq12_push(hint) }
            { Fq12::equalverify() }

            OP_TRUE
        };
        let exec_result = execute_script_without_stack_limit(script);
        if !exec_result.success {
            println!(
                "Remaining script size: {}, last opcode: {}",
                exec_result.remaining_script.len(),
                exec_result.last_opcode.unwrap().to_string()
            );
        }
        assert!(exec_result.success);
    }
}
