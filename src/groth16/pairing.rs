use crate::bn254::ell_coeffs::{EllCoeff, G2HomProjective, G2Prepared};
use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::fq::Fq;
use crate::bn254::fq12::Fq12;
use crate::bn254::fq2::Fq2;
use crate::bn254::fq6::Fq6;
use crate::bn254::pairing::Pairing;
use crate::treepp::*;
use ark_ec::bn::BnConfig;

#[derive(Clone, Copy, Debug)]
pub struct Groth16Pairing {}

impl Groth16Pairing {
    // input on stack (non-fixed) : [1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4]
    // [Fp, Fp2, 2 * Fp, 2 * Fp, 2 * Fp, 2 * Fp, 2 * Fp2, Fp12, Fp12, Fp12, 3 * Fp2]
    // input outside stack (fixed): [L1, L2, L3]
    pub fn quad_miller_loop_with_c_wi(constants: &Vec<G2Prepared>) -> Script {
        /*let num_constant = constants.len();
        assert_eq!(num_constant, 3);
        let num_non_constant = 1;
        let num_pairs = 4;
        let mut script_bytes: Vec<u8> = vec![];

        // f = c_inv
        script_bytes.extend(
            script! {
                { Fq12::copy(12) }
            }
            .as_bytes(),
        );

        let fq12_square = Fq12::square();

        let mut constant_iters = constants
            .iter()
            .map(|item| item.ell_coeffs.iter())
            .collect::<Vec<_>>();

        // miller loop part, 6x + 2
        for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
            let bit = ark_bn254::Config::ATE_LOOP_COUNT[i - 1];

            // update f (double), f = f * f
            script_bytes.extend(fq12_square.as_bytes());

            // update c_inv
            // f = f * c_inv, if digit == 1
            // f = f * c, if digit == -1
            if bit == 1 {
                script_bytes.extend(
                    script! {
                        { Fq12::copy(30) }
                        { Fq12::mul(12, 0) }
                    }
                    .as_bytes(),
                );
            } else if bit == -1 {
                script_bytes.extend(
                    script! {
                        { Fq12::copy(42) }
                        { Fq12::mul(12, 0) }
                    }
                    .as_bytes(),
                );
            }

            ////////////////////////// accumulate double lines (fixed and non-fixed)
            // f = f^2 * double_line_Q(P)
            // fixed (constant part)
            for j in 0..num_constant {
                let offset = (4 * 12) as u32
                    + (num_non_constant * 3 * 2) as u32
                    + (num_non_constant * 2 * 2) as u32
                    + (num_pairs - 1 - j) as u32 * 2;
                script_bytes.extend(Fq2::copy(offset).as_bytes());
                script_bytes.extend(
                    Pairing::ell_by_constant(&constant_iters[j].next().unwrap()).as_bytes(),
                );
            }

            // non-fixed (non-constant part)
            let offset_P = (4 * 12) as u32
                + (num_non_constant * 3 * 2) as u32
                + (num_non_constant * 2 * 2) as u32;
            script_bytes.extend(Fq2::copy(offset_P).as_bytes());
            // roll T, and double line with T (projective coordinates)
            // ..., f, P, T
            let offset_T = 14 as u32;
            script_bytes.extend(Fq2::roll(offset_T).as_bytes());
            // ..., f, P, (,,) | T
            script_bytes.extend(G2HomProjective::double_line().as_bytes());
            script_bytes.extend(Fq6::toaltstack().as_bytes());
            // line evaluation and update f
            // ..., f | T
            script_bytes.extend(Pairing::ell_by_non_constant().as_bytes());
            // rollback T
            // ..., T, f
            script_bytes.extend(Fq6::fromaltstack().as_bytes());
            script_bytes.extend(Fq12::roll(6).as_bytes());

            // update f (add), f = f * add_line_eval
            if bit == 1 || bit == -1 {
                // f = f * add_line_Q(P)
                // fixed (constant part)
                for j in 0..num_constant {
                    let offset = (4 * 12) as u32
                        + (num_non_constant * 3 * 2) as u32
                        + (num_non_constant * 2 * 2) as u32
                        + (num_pairs - 1 - j) as u32 * 2;
                    script_bytes.extend(Fq2::copy(offset).as_bytes());
                    script_bytes.extend(
                        Pairing::ell_by_constant(&constant_iters[j].next().unwrap()).as_bytes(),
                    );
                }

                // non-fixed (non-constant part)
                let offset_P = (4 * 12) as u32
                    + (num_non_constant * 3 * 2) as u32
                    + (num_non_constant * 2 * 2) as u32;
                script_bytes.extend(Fq2::copy(offset_P).as_bytes());
                // roll T and copy Q, and add line with T and Q(projective coordinates)
                // ..., f, P, T
                let offset_T = 14 as u32;
                script_bytes.extend(Fq2::roll(offset_T).as_bytes());
                let offset_Q = (4 * 12 + num_non_constant * 3 * 2) as u32;
                script_bytes.extend(Fq2::copy(offset_Q).as_bytes());
                // ..., f, P, (,,) | T
                script_bytes.extend(G2HomProjective::add_line().as_bytes());
                script_bytes.extend(Fq6::toaltstack().as_bytes());
                // line evaluation and update f
                // ..., f | T
                script_bytes.extend(Pairing::ell_by_non_constant().as_bytes());
                // rollback T
                // ..., T, f
                script_bytes.extend(Fq6::fromaltstack().as_bytes());
                script_bytes.extend(Fq12::roll(6).as_bytes());
            }

            println!("Miller loop [{}]", i - 1);
        }

        // update c_inv
        // f = f * c_inv^p * c^{p^2}
        script_bytes.extend(
            script! {
                { Fq12::roll(30) }
                { Fq12::frobenius_map(1) }
                { Fq12::mul(12, 0) }
                { Fq12::roll(30) }
                { Fq12::frobenius_map(2) }
                { Fq12::mul(12, 0) }
            }
            .as_bytes(),
        );

        // scale f
        // f = f * wi
        script_bytes.extend(
            script! {
                { Fq12::roll(18) }
                { Fq12::mul(12, 0) }
            }
            .as_bytes(),
        );

        // frobenius map on fixed and non-fixed lines

        // update f (frobenius map): f = f * add_line_eval([p])
        for i in 0..num_constant {
            let offset = (12
                + num_non_constant * 3 * 2
                + num_non_constant * 2 * 2
                + (num_pairs - 1 - i) * 2) as u32;
            script_bytes.extend(Fq2::copy(offset).as_bytes());
            script_bytes
                .extend(Pairing::ell_by_constant(&constant_iters[i].next().unwrap()).as_bytes());
        }

        // non-fixed
        // copy P, and T
        script_bytes.extend(Fq2::copy(22).as_bytes());
        script_bytes.extend(Fq6::copy(12).as_bytes());

        // phi(Q)
        // Qx.conjugate * beta^{2 * (p - 1) / 6}
        script_bytes.extend(Fq2::copy(20).as_bytes());
        script_bytes.extend(Fq::neg(0).as_bytes());
        script_bytes.extend(Fq2::copy(39).as_bytes());
        script_bytes.extend(Fq2::mul(2, 0).as_bytes());
        // Qy.conjugate * beta^{3 * (p - 1) / 6}
        script_bytes.extend(Fq2::copy(20).as_bytes());
        script_bytes.extend(Fq::neg(0).as_bytes());
        script_bytes.extend(Fq2::copy(39).as_bytes());
        script_bytes.extend(Fq2::mul(2, 0).as_bytes());

        // add line with T and phi(Q)
        script_bytes.extend(G2HomProjective::add_line().as_bytes());
        script_bytes.extend(Fq6::toaltstack().as_bytes());

        // line evaluation and update f
        script_bytes.extend(Pairing::ell_by_non_constant().as_bytes());
        script_bytes.extend(Fq6::fromaltstack().as_bytes());
        script_bytes.extend(Fq12::roll(6).as_bytes());

        for i in 0..num_constant {
            let offset = (12
                + num_non_constant * 3 * 2
                + num_non_constant * 2 * 2
                + (num_pairs - 1 - i) * 2) as u32;
            script_bytes.extend(Fq2::roll(offset).as_bytes());
            script_bytes
                .extend(Pairing::ell_by_constant(&constant_iters[i].next().unwrap()).as_bytes());
        }

        // non-fixed
        // copy P, and T
        script_bytes.extend(Fq2::roll(22).as_bytes());
        script_bytes.extend(Fq6::roll(12).as_bytes());

        // phi(Q)
        // Qx * beta^{2 * (p^2 - 1) / 6}
        script_bytes.extend(Fq2::roll(20).as_bytes());
        script_bytes.extend(Fq2::roll(33).as_bytes());
        script_bytes.extend(Fq2::mul(2, 0).as_bytes());
        // - Qy
        script_bytes.extend(Fq2::copy(20).as_bytes());
        script_bytes.extend(Fq2::neg(0).as_bytes());

        // add line with T and phi(Q)
        script_bytes.extend(G2HomProjective::add_line().as_bytes());
        script_bytes.extend(Fq6::drop().as_bytes());
        // line evaluation and update f
        script_bytes.extend(Pairing::ell_by_non_constant().as_bytes());

        for i in 0..num_constant {
            assert_eq!(constant_iters[i].next(), None);
        }

        Script::from(script_bytes)*/
        script!(OP_TRUE)
    }
}
