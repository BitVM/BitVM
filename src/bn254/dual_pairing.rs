use crate::bn254::ell_coeffs::{EllCoeff, G2Prepared};
use crate::bn254::fq::Fq;
use crate::bn254::fq12::Fq12;
use crate::bn254::fq2::Fq2;
use crate::bn254::fq6::Fq6;
use crate::bn254::pairing::Pairing;
use crate::treepp::*;
use ark_ec::bn::BnConfig;
pub struct DualPairing;

impl DualPairing {
    // input:
    //   p.x
    //   p.y
    pub fn miller_loop(constant: &G2Prepared, affine: bool) -> Script {

        println!(
            "miller loop length: {}",
            ark_bn254::Config::ATE_LOOP_COUNT.len() - 1
        );
        let mut constant_iter = constant.ell_coeffs.iter();
        let script = script! {
            { Fq12::push_one() }

            for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
                if i != ark_bn254::Config::ATE_LOOP_COUNT.len() - 1 {
                    { Fq12::square() }
                }

                { Fq2::copy(12) }
                if affine {
                    { Pairing::ell_by_constant_affine(constant_iter.next().unwrap()) }
                } else {
                    { Pairing::ell_by_constant(constant_iter.next().unwrap()) }
                }

                if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == 1 || ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == -1 {
                    { Fq2::copy(12) }
                    if affine {
                        { Pairing::ell_by_constant_affine(constant_iter.next().unwrap()) }
                    } else {
                        { Pairing::ell_by_constant(constant_iter.next().unwrap()) }
                    }
                }
            }

            { Fq2::copy(12) }
            if affine {
                { Pairing::ell_by_constant_affine(constant_iter.next().unwrap()) }
            } else {
                { Pairing::ell_by_constant(constant_iter.next().unwrap()) }
            }

            { Fq2::roll(12) }
            if affine {
                { Pairing::ell_by_constant_affine(constant_iter.next().unwrap()) }
            } else {
                { Pairing::ell_by_constant(constant_iter.next().unwrap()) }
            }

        };
        assert_eq!(constant_iter.next(), None);
        script
    }

    // input on stack (non-fixed) : [P1, P2, c, c_inv, wi]
    // input outside (fixed): L1(Q1), L2(Q2)
    pub fn dual_miller_loop_with_c_wi(
        constant_1: &G2Prepared,
        constant_2: &G2Prepared,
        affine: bool,
    ) -> Script {
        println!(
            "miller loop length: {}",
            ark_bn254::Config::ATE_LOOP_COUNT.len() - 1
        );

        let mut constant_1_iter = constant_1.ell_coeffs.iter();
        let mut constant_2_iter = constant_2.ell_coeffs.iter();
        let script = script! {
            // f = c_inv
            { Fq12::copy(12) }

            // miller loop part, 6x + 2
            for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
                // update f (double), f = f * f
                { Fq12::square() }

                // update c_inv
                // f = f * c_inv, if bit == 1
                // f = f * c, if bit == -1
                if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == 1 {
                    { Fq12::copy(24) }
                    { Fq12::mul(12, 0) }
                } else if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == -1 {
                    { Fq12::copy(36) }
                    { Fq12::mul(12, 0) }
                }

                // update f, f = f * double_line_eval
                { Fq2::copy(50) }
                if affine {
                    { Pairing::ell_by_constant_affine(constant_1_iter.next().unwrap()) }
                } else {
                    { Pairing::ell_by_constant(constant_1_iter.next().unwrap()) }
                }

                { Fq2::copy(48) }
                if affine {
                    { Pairing::ell_by_constant_affine(constant_2_iter.next().unwrap()) }
                } else {
                    { Pairing::ell_by_constant(constant_2_iter.next().unwrap()) }
                }

                // update f (add), f = f * add_line_eval
                if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == 1 || ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == -1 {
                    { Fq2::copy(50) }
                    if affine {
                        { Pairing::ell_by_constant_affine(constant_1_iter.next().unwrap()) }
                    } else {
                        { Pairing::ell_by_constant(constant_1_iter.next().unwrap()) }
                    }

                    { Fq2::copy(48) }
                    if affine {
                        { Pairing::ell_by_constant_affine(constant_2_iter.next().unwrap()) }
                    } else {
                        { Pairing::ell_by_constant(constant_2_iter.next().unwrap()) }
                    }
                }
            }

            // update c_inv
            // f = f * c_inv^p * c^{p^2}
            { Fq12::roll(24) }
            { Fq12::frobenius_map(1) }
            { Fq12::mul(12, 0) }
            { Fq12::roll(24) }
            { Fq12::frobenius_map(2) }
            { Fq12::mul(12, 0) }

            // scale f
            // f = f * wi
            { Fq12::mul(12, 0) }

            // update f (frobenius map): f = f * add_line_eval([p])
            { Fq2::copy(14) }
            if affine {
                { Pairing::ell_by_constant_affine(constant_1_iter.next().unwrap()) }
            } else {
                { Pairing::ell_by_constant(constant_1_iter.next().unwrap()) }
            }

            { Fq2::copy(12) }
            if affine {
                { Pairing::ell_by_constant_affine(constant_2_iter.next().unwrap()) }
            } else {
                { Pairing::ell_by_constant(constant_2_iter.next().unwrap()) }
            }

            // update f (frobenius map): f = f * add_line_eval([-p^2])
            { Fq2::roll(14) }
            if affine {
                { Pairing::ell_by_constant_affine(constant_1_iter.next().unwrap()) }
            } else {
                { Pairing::ell_by_constant(constant_1_iter.next().unwrap()) }
            }

            { Fq2::roll(12) }
            if affine {
                { Pairing::ell_by_constant_affine(constant_2_iter.next().unwrap()) }
            } else {
                { Pairing::ell_by_constant(constant_2_iter.next().unwrap()) }
            }

        };
        assert_eq!(constant_1_iter.next(), None);
        assert_eq!(constant_2_iter.next(), None);
        script
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::bn254::ell_coeffs::{mul_by_char, G2Prepared};
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::bn254::fq::Fq;
    use crate::bn254::fq12::Fq12;
    use crate::bn254::utils::{fq12_push, fq2_push};
    use ark_bn254::Bn254;
    use rand_chacha::ChaCha20Rng;

    use ark_ec::pairing::Pairing as _;

    use crate::bn254::utils;
    use ark_ff::Field;
    use ark_std::{test_rng, UniformRand};
    use num_bigint::BigUint;
    use num_traits::Num;
    use rand::{RngCore, SeedableRng};
    use std::str::FromStr;

    #[test]
    fn test_miller_loop_projective() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let p = ark_bn254::G1Affine::rand(&mut prng);

            let a = ark_bn254::g2::G2Affine::rand(&mut prng);

            // projective mode
            let a_prepared = G2Prepared::from(a);
            let a_proj = ark_bn254::G2Projective::from(a);

            let miller_loop = DualPairing::miller_loop(&a_prepared, false);
            println!("Pairing.miller_loop: {} bytes", miller_loop.len());

            let hint = Bn254::multi_miller_loop([p], [a_proj]).0;

            let script = script! {
                { Fq::push_u32_le(&BigUint::from(p.x).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(p.y).to_u32_digits()) }
                { miller_loop.clone() }
                { fq12_push(hint) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            println!("{}", exec_result);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_miller_loop_affine() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let p = ark_bn254::G1Affine::rand(&mut prng);

            let a = ark_bn254::g2::G2Affine::rand(&mut prng);

            // affine mode
            let a_prepared = G2Prepared::from_affine(a);
            let a_affine = a;

            let miller_loop = DualPairing::miller_loop(&a_prepared, true);
            println!("Pairing.miller_loop: {} bytes", miller_loop.len());

            let c = Bn254::multi_miller_loop_affine([p], [a_affine]).0;

            let script = script! {
                { utils::from_eval_point(p) }
                { miller_loop.clone() }
                { fq12_push(c) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            println!("{}", exec_result);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_dual_millerloop_with_c_wi_projective() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        // exp = 6x + 2 + p - p^2 = lambda - p^3
        let p_pow3 = BigUint::from_str_radix(Fq::MODULUS, 16).unwrap().pow(3_u32);
        let lambda = BigUint::from_str(
                "10486551571378427818905133077457505975146652579011797175399169355881771981095211883813744499745558409789005132135496770941292989421431235276221147148858384772096778432243207188878598198850276842458913349817007302752534892127325269"
            ).unwrap();
        let (exp, sign) = if lambda > p_pow3 {
            (lambda - p_pow3, true)
        } else {
            (p_pow3 - lambda, false)
        };

        // random c and wi for test
        let c = ark_bn254::Fq12::rand(&mut prng);
        let c_inv = c.inverse().unwrap();
        let wi = ark_bn254::Fq12::rand(&mut prng);

        // random input points for following two pairings
        let p = ark_bn254::G1Affine::rand(&mut prng);
        let q = ark_bn254::G1Affine::rand(&mut prng);
        let a = ark_bn254::g2::G2Affine::rand(&mut prng);
        let b = ark_bn254::g2::G2Affine::rand(&mut prng);

        // projective mode
        let a_proj = ark_bn254::G2Projective::from(a);
        let b_proj = ark_bn254::G2Projective::from(b);

        // benchmark(arkworks): multi miller loop with projective cooordinates of line functions
        let f = Bn254::multi_miller_loop([p, q], [a_proj, b_proj]).0;
        println!("Bn254::multi_miller_loop done!");
        let hint = if sign {
            f * wi * (c_inv.pow(exp.to_u64_digits()))
        } else {
            f * wi * (c_inv.pow(exp.to_u64_digits()).inverse().unwrap())
        };
        println!("Accumulated f done!");

        // (projective) coefficients of line functions
        let a_prepared = G2Prepared::from(a);
        let b_prepared = G2Prepared::from(b);
        // test(script): of multi miller loop with projective coordinates of line functions
        let dual_miller_loop_with_c_wi =
            DualPairing::dual_miller_loop_with_c_wi(&a_prepared, &b_prepared, false);
        println!(
            "Pairing.dual_miller_loop_with_c_wi(projective): {} bytes",
            dual_miller_loop_with_c_wi.len()
        );

        // input on stack :
        //      p, q, c, c_inv, wi
        // input of script func (parameters):
        //      a_prepared, Vec[(c0, c3, c4)]
        //      b_prepared, Vec[(c0, c3, c4)]
        let script = script! {
            { Fq::push_u32_le(&BigUint::from(p.x).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(p.y).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(q.x).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(q.y).to_u32_digits()) }
            { fq12_push(c) }
            { fq12_push(c_inv) }
            { fq12_push(wi) }
            { dual_miller_loop_with_c_wi.clone() }
            { fq12_push(hint) }
            { Fq12::equalverify() }
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_dual_millerloop_with_c_wi_affine() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        // exp = 6x + 2 + p - p^2 = lambda - p^3
        let p_pow3 = &BigUint::from_str_radix(Fq::MODULUS, 16).unwrap().pow(3_u32);
        let lambda = BigUint::from_str(
                        "10486551571378427818905133077457505975146652579011797175399169355881771981095211883813744499745558409789005132135496770941292989421431235276221147148858384772096778432243207188878598198850276842458913349817007302752534892127325269"
                    ).unwrap();
        let (exp, sign) = if lambda > *p_pow3 {
            (lambda - p_pow3, true)
        } else {
            (p_pow3 - lambda, false)
        };

        // random c and wi just for unit test
        let c = ark_bn254::Fq12::rand(&mut prng);
        let c_inv = c.inverse().unwrap();
        let wi = ark_bn254::Fq12::rand(&mut prng);

        // random input points for following two pairings
        let p = ark_bn254::G1Affine::rand(&mut prng);
        let q = ark_bn254::G1Affine::rand(&mut prng);
        let a = ark_bn254::g2::G2Affine::rand(&mut prng);
        let b = ark_bn254::g2::G2Affine::rand(&mut prng);

        // affine mode
        let a_affine = a;
        let b_affine = b;

        // benchmark: multi miller loop with affine cooordinates of line functions
        let f = Bn254::multi_miller_loop_affine([p, q], [a_affine, b_affine]).0;
        println!("Bn254::multi_miller_loop done!");
        let hint = if sign {
            f * wi * (c_inv.pow(exp.to_u64_digits()))
        } else {
            f * wi * (c_inv.pow(exp.to_u64_digits()).inverse().unwrap())
        };
        println!("Accumulated f done!");

        // (affine) coefficients of line functions
        let a_prepared = G2Prepared::from_affine(a);
        let b_prepared = G2Prepared::from_affine(b);
        // test(script): of multi miller loop with affine coordinates of line functions
        let dual_miller_loop_with_c_wi_affine =
            DualPairing::dual_miller_loop_with_c_wi(&a_prepared, &b_prepared, true);
        println!(
            "Pairing.dual_miller_loop_with_c_wi(affine): {} bytes",
            dual_miller_loop_with_c_wi_affine.len()
        );

        // input on stack :
        //      [-p.x / p.y, 1 / p.y, -q.x / q.y, 1 / q.y, c, c_inv, wi]
        // input of script func (parameters):
        //      a_prepared, Vec[(c0, c3, c4)]
        //      b_prepared, Vec[(c0, c3, c4)]
        let script = script! {
            { utils::from_eval_point(p) }
            // [-p.x / p.y, 1 / p.y]
            { utils::from_eval_point(q) }
            // [-p.x / p.y, 1 / p.y, -q.x / q.y, 1 / q.y]
            { fq12_push(c) }
            { fq12_push(c_inv) }
            { fq12_push(wi) }
            // [-p.x / p.y, 1 / p.y, -q.x / q.y, 1 / q.y, c, c_inv, wi]
            { dual_miller_loop_with_c_wi_affine.clone() }
            { fq12_push(hint) }
            { Fq12::equalverify() }
            OP_TRUE
        };
        let exec_result = execute_script(script);
        println!("{}", exec_result);
        assert!(exec_result.success);
    }
}
