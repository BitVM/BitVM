use crate::bn254::ell_coeffs::{EllCoeff, G2Prepared};
use crate::bn254::fq::Fq;
use crate::bn254::fq12::Fq12;
use crate::bn254::fq2::Fq2;
use crate::bn254::fq6::Fq6;
use crate::bn254::pairing::Pairing;
use crate::bn254::utils;
use crate::treepp::*;
use ark_ec::bn::BnConfig;
pub struct QuadPairing;

impl QuadPairing {
    /// input on stack:
    ///     [P1, P2, P3, P4, Q4, T4(affine)]
    ///     [2,  2,  2,  2,  4,  4]
    ///
    /// input of parameters:
    ///     [L(P1), L(P2), L(P3), L(P4)]
    pub fn quad_miller_loop(constants: &Vec<G2Prepared>) -> Script {
        assert_eq!(constants.len(), 4);
        let mut script_bytes = vec![];
        let num_constant = 3;

        script_bytes.extend(Fq12::push_one().as_bytes());
        // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]

        let fq12_square = Fq12::square();

        let mut constant_iters = constants
            .iter()
            .map(|item| item.ell_coeffs.iter())
            .collect::<Vec<_>>();

        for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
            if i != ark_bn254::Config::ATE_LOOP_COUNT.len() - 1 {
                script_bytes.extend(fq12_square.as_bytes());
            }
            // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]

            ////////////////////////////////////////////////////// double line
            for j in 0..constants.len() {
                ////////////////////////////// constant part
                // copy P_i
                let offset = (26 - j * 2) as u32;
                script_bytes.extend(Fq2::copy(offset).as_bytes());
                // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12), P_i(2)]
                let line_coeff = constant_iters[j].next().unwrap();
                script_bytes
                    .extend(Pairing::ell_by_constant_affine(&line_coeff.clone()).as_bytes());
                // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]

                ///////////////////////////// non-constant part
                if j == num_constant {
                    // check line coeff is satisfied with T4
                    script_bytes.extend(Fq2::copy(14).as_bytes());
                    script_bytes.extend(Fq2::copy(14).as_bytes());
                    script_bytes
                        .extend(utils::check_tangent_line(line_coeff.1, line_coeff.2).as_bytes());
                    // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]

                    // update T4
                    script_bytes.extend(Fq12::toaltstack().as_bytes());
                    script_bytes.extend(Fq2::drop().as_bytes());
                    // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4.x | f(12)]
                    script_bytes
                        .extend(utils::affine_double_line(line_coeff.1, line_coeff.2).as_bytes());
                    script_bytes.extend(Fq12::fromaltstack().as_bytes());
                    // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]
                }
            }

            //////////////////////////////////////////////////////// add line
            let bit = ark_bn254::Config::ATE_LOOP_COUNT[i - 1];
            if bit == 1 || bit == -1 {
                for j in 0..constants.len() {
                    ///////////////////////////////////// constant part
                    let offset = (26 - j * 2) as u32;
                    script_bytes.extend(Fq2::copy(offset).as_bytes());
                    let line_coeff = constant_iters[j].next().unwrap();
                    script_bytes
                        .extend(Pairing::ell_by_constant_affine(&line_coeff.clone()).as_bytes());
                    // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]

                    ///////////////////////////////////// non-constant part
                    if j == num_constant {
                        // copy Q4
                        script_bytes.extend(Fq2::copy(18).as_bytes());
                        script_bytes.extend(Fq2::copy(18).as_bytes());
                        // copy T4
                        script_bytes.extend(Fq2::copy(18).as_bytes());
                        script_bytes.extend(Fq2::copy(18).as_bytes());
                        script_bytes
                            .extend(utils::check_chord_line(line_coeff.1, line_coeff.2).as_bytes());
                        // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]

                        // update T4
                        script_bytes.extend(Fq12::toaltstack().as_bytes());
                        script_bytes.extend(Fq2::drop().as_bytes());
                        script_bytes.extend(Fq2::copy(4).as_bytes());
                        // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4.x(2), Q4.x(2) | f(12)]
                        script_bytes
                            .extend(utils::affine_add_line(line_coeff.1, line_coeff.2).as_bytes());
                        script_bytes.extend(Fq12::fromaltstack().as_bytes());
                        // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]
                    }
                }
            }
        }

        // one-time of frobenius map
        for j in 0..constants.len() {
            ///////////////////////////////////// constant part
            let offset = (26 - j * 2) as u32;
            script_bytes.extend(Fq2::copy(offset).as_bytes());
            let line_coeff = constant_iters[j].next().unwrap();
            script_bytes.extend(Pairing::ell_by_constant_affine(&line_coeff.clone()).as_bytes());
            // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]

            ///////////////////////////////////// non-constant part
            if j == num_constant {
                // copy Q4
                script_bytes.extend(Fq2::copy(18).as_bytes());
                script_bytes.extend(Fq2::copy(18).as_bytes());
                // copy T4
                script_bytes.extend(Fq2::copy(18).as_bytes());
                script_bytes.extend(Fq2::copy(18).as_bytes());
                script_bytes.extend(utils::check_chord_line(line_coeff.1, line_coeff.2).as_bytes());
                // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]

                // update T4
                script_bytes.extend(Fq12::toaltstack().as_bytes());
                script_bytes.extend(Fq2::drop().as_bytes());
                script_bytes.extend(Fq2::copy(4).as_bytes());
                // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4.x(2), Q4.x(2) | f(12)]
                script_bytes.extend(utils::affine_add_line(line_coeff.1, line_coeff.2).as_bytes());
                script_bytes.extend(Fq12::fromaltstack().as_bytes());
                // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]
            }
        }

        // two-times of frobenius map
        for j in 0..constants.len() {
            ///////////////////////////////////// constant part
            let offset = (26 - j * 2) as u32;
            script_bytes.extend(Fq2::roll(offset).as_bytes());
            let line_coeff = constant_iters[j].next().unwrap();
            script_bytes.extend(Pairing::ell_by_constant_affine(&line_coeff.clone()).as_bytes());
            // [Q4(4), T4(4), f(12)]

            ///////////////////////////////////// non-constant part
            if j == num_constant {
                // roll Q4
                script_bytes.extend(Fq2::roll(18).as_bytes());
                script_bytes.extend(Fq2::roll(18).as_bytes());
                // roll T4
                script_bytes.extend(Fq2::roll(18).as_bytes());
                script_bytes.extend(Fq2::roll(18).as_bytes());
                script_bytes.extend(utils::check_chord_line(line_coeff.1, line_coeff.2).as_bytes());
                // [f(12)]

                // script_bytes.extend(Fq12::toaltstack().as_bytes());
                // script_bytes.extend(Fq2::drop().as_bytes());
                // script_bytes.extend(Fq2::copy(4).as_bytes());
                // // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4.x(2), Q4.x(2) | f(12)]
                // script_bytes.extend(utils::affine_add_line(line_coeff.1, line_coeff.2).as_bytes());
                // script_bytes.extend(Fq12::fromaltstack().as_bytes());
            }
        }

        for i in 0..num_constant {
            assert_eq!(constant_iters[i].next(), None);
        }

        Script::from(script_bytes)
    }
}
