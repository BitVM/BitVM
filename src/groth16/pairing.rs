use crate::bn254::ell_coeffs::G2Prepared;
use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::fq::Fq;
use crate::bn254::fq12::Fq12;
use crate::bn254::fq2::Fq2;
use crate::bn254::fq6::Fq6;
use crate::bn254::pairing::Pairing;
use crate::treepp::{pushable, script, Script};
use ark_ec::bn::BnConfig;

impl Pairing {
    // input on stack (non-fixed): [beta^{2*(p-1)/6}, beta^{3*(p-1)/6}, beta^{2*(p^2-1)/6}, 1/2, B,   P1,   P2,   P3,   P4,   Q4,    c,    c_inv, wi,   T4]
    //                             [Fp2,              Fp2,              Fp2,                Fp,  Fp2, 2*Fp, 2*Fp, 2*Fp, 2*Fp, 2*Fp2, Fp12, Fp12,  Fp12, 3*Fp2]
    // Stack Index(Bottom,Top)     [61                59,               57,                 56,  54,  52,   50,   48,   46,   42,    30,   18,    6,    0]
    //
    // ind_beta_12 = 61,
    // ind_beta_13 = 59,
    // ind_beta_22 = 57,
    // ind_2_div_1 = 56,
    // ind_B = 54,
    // ind_P1 = 52,
    // ind_P2 = 50,
    // ind_P3 = 48,
    // ind_P4 = 46,
    // ind_Q4 = 42,
    // ind_c = 30,
    // ind_c_inv = 18,
    // ind_wi = 6
    // ind_T4 = 0
    //
    // params:
    //      input outside stack (fixed): [L1, L2, L3]
    pub fn quad_miller_loop_with_c_wi(constants: &Vec<G2Prepared>) -> Script {
        let num_constant = constants.len();
        assert_eq!(num_constant, 3);
        let mut script_bytes: Vec<u8> = vec![];

        // 1. f = c_inv
        // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4]
        script_bytes.extend(
            script! {
                { Fq12::copy(18) }
            }
            .as_bytes(),
        );
        // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f]

        let fq12_square = Fq12::square();

        let mut constant_iters = constants
            .iter()
            .map(|item| item.ell_coeffs.iter())
            .collect::<Vec<_>>();

        // 2. miller loop part, 6x + 2
        // ATE_LOOP_COUNT len: 65
        for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
            println!("miller loop i = {}", i);
            let bit = ark_bn254::Config::ATE_LOOP_COUNT[i - 1];

            // 2.1 update f (double), f = f * f
            // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f^2]
            script_bytes.extend(fq12_square.as_bytes());

            // 2.2 update c_inv
            // f = f * c_inv, if digit == 1
            // f = f * c, if digit == -1
            if bit == 1 {
                // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f^2 * c_inv]
                script_bytes.extend(
                    script! {
                        { Fq12::copy(30) }
                        { Fq12::mul(12, 0) }
                    }
                    .as_bytes(),
                );
            } else if bit == -1 {
                // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f^2 * c]
                script_bytes.extend(
                    script! {
                        { Fq12::copy(42) }
                        { Fq12::mul(12, 0) }
                    }
                    .as_bytes(),
                );
            }
            // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f]

            //////////////////////////////////////////////////////////////////// 2.3 accumulate double lines (fixed and non-fixed)
            // f = f^2 * double_line_Q(P)
            // fixed (constant part) P1, P2, P3
            // [beta_12, beta_13, beta_22, 1/2, B, P1(64), P2(62), P3(60), P4(58), Q4(54), c(42), c_inv(30), wi(18), T4(12), f]
            for j in 0..num_constant {
                let offset = (64 - j * 2) as u32;
                // [beta_12, beta_13, beta_22, 1/2, B, P1(64), P2(62), P3(60), P4(58), Q4(54), c(42), c_inv(30), wi(18), T4(12), f, P1]
                script_bytes.extend(Fq2::copy(offset).as_bytes());
                script_bytes.extend(
                    Pairing::ell_by_constant(&constant_iters[j].next().unwrap()).as_bytes(),
                );
            }
            // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f]

            // non-fixed (non-constant part) P4
            let offset_P = (46 + 12) as u32;
            script_bytes.extend(Fq2::copy(offset_P).as_bytes());
            // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f, P4]
            // roll T, and double line with T (projective coordinates)
            let offset_T = (12 + 2) as u32;
            script_bytes.extend(Fq6::roll(offset_T).as_bytes());
            // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f, P4, T4]
            script_bytes.extend(Pairing::double_line().as_bytes());
            // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f, P4, T4, (,,)]
            script_bytes.extend(Fq6::roll(6).as_bytes());
            // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f, P4, (,,), T4]
            script_bytes.extend(Fq6::toaltstack().as_bytes());
            // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f, P4, (,,) | T4]
            // line evaluation and update f
            script_bytes.extend(Fq2::roll(6).as_bytes());
            // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f, (,,), P4 | T4]
            script_bytes.extend(Pairing::ell().as_bytes());
            // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f | T4]
            script_bytes.extend(Fq6::fromaltstack().as_bytes());
            // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f, T4]
            script_bytes.extend(Fq12::roll(6).as_bytes());
            // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f]

            //////////////////////////////////////////////////////////////////// 2.4 accumulate add lines (fixed and non-fixed)
            // update f (add), f = f * add_line_eval
            if bit == 1 || bit == -1 {
                // f = f * add_line_Q(P)
                // fixed (constant part), P1, P2, P3
                for j in 0..num_constant {
                    let offset = (64 - j * 2) as u32;
                    script_bytes.extend(Fq2::copy(offset).as_bytes());
                    script_bytes.extend(
                        Pairing::ell_by_constant(&constant_iters[j].next().unwrap()).as_bytes(),
                    );
                }
                // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f]

                // non-fixed (non-constant part), P4
                let offset_P = (46 + 12) as u32;
                script_bytes.extend(Fq2::copy(offset_P).as_bytes());
                // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f, P4]
                // roll T and copy Q, and add line with Q and T(projective coordinates)
                let offset_T = (12 + 2) as u32;
                script_bytes.extend(Fq6::roll(offset_T).as_bytes());
                // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f, P4, T4]
                let offset_Q = (48 + 2 + 6) as u32;
                script_bytes.extend(Fq2::copy(offset_Q + 2).as_bytes());
                script_bytes.extend(Fq2::copy(offset_Q + 2).as_bytes());
                // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f, P4, T4, Q4]
                script_bytes.extend(Pairing::add_line_with_flag(bit == 1).as_bytes());
                // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f, P4, T4, (,,)]
                script_bytes.extend(Fq6::roll(6).as_bytes());
                // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f, P4, (,,), T4]
                script_bytes.extend(Fq6::toaltstack().as_bytes());
                // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f, P4, (,,) | T4]
                // line evaluation and update f
                script_bytes.extend(Fq2::roll(6).as_bytes());
                // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f, (,,), P4 | T4]
                // script_bytes.extend(Pairing::ell_by_non_constant().as_bytes());
                script_bytes.extend(Pairing::ell().as_bytes());
                // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f | T4]
                // rollback T
                script_bytes.extend(Fq6::fromaltstack().as_bytes());
                // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, f, T4]
                script_bytes.extend(Fq12::roll(6).as_bytes());
                // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f]
            }
        }

        // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f]
        // clean 1/2 and B in stack
        script_bytes.extend(Fq::roll(68).as_bytes());
        script_bytes.extend(Fq::drop().as_bytes());
        // [beta_12, beta_13, beta_22, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f]
        script_bytes.extend(Fq2::roll(66).as_bytes());
        script_bytes.extend(Fq2::drop().as_bytes());
        // [beta_12, beta_13, beta_22, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f]

        /////////////////////////////////////////  update c_inv
        // 3. f = f * c_inv^p * c^{p^2}
        script_bytes.extend(
            script! {
                { Fq12::roll(30) }
                // [beta_12, beta_13, beta_22, P1, P2, P3, P4, Q4, c, wi, T4, f, c_inv]
                { Fq12::frobenius_map(1) }
                // [beta_12, beta_13, beta_22, P1, P2, P3, P4, Q4, c, wi, T4, f, c_inv^p]
                { Fq12::mul(12, 0) }
                // [beta_12, beta_13, beta_22, P1, P2, P3, P4, Q4, c, wi, T4, f]
                { Fq12::roll(30) }
                // [beta_12, beta_13, beta_22, P1, P2, P3, P4, Q4, c, wi, T4, f, c]
                { Fq12::frobenius_map(2) }
                // [beta_12, beta_13, beta_22, P1, P2, P3, P4, Q4, wi, T4, f,]
                { Fq12::mul(12, 0) }
                // [beta_12, beta_13, beta_22, P1, P2, P3, P4, Q4, wi, T4, f]
            }
            .as_bytes(),
        );
        // [beta_12, beta_13, beta_22, P1, P2, P3, P4, Q4, wi, T4, f]
        //////////////////////////////////////// scale f
        // 4. f = f * wi
        script_bytes.extend(
            script! {
                { Fq12::roll(12 + 6) }
                // [beta_12, beta_13, beta_22, P1, P2, P3, P4, Q4, T4, f, wi]
                { Fq12::mul(12, 0) }
                // [beta_12, beta_13, beta_22, P1, P2, P3, P4, Q4, T4, f]
            }
            .as_bytes(),
        );
        // [beta_12, beta_13, beta_22, P1, P2, P3, P4, Q4, T4, f]

        /////////////////////////////////////// 5. one-time frobenius map on fixed and non-fixed lines
        // fixed part, P1, P2, P3
        // 5.1 update f (frobenius map): f = f * add_line_eval([p])
        for j in 0..num_constant {
            let offset = (28 - j * 2) as u32;
            script_bytes.extend(Fq2::copy(offset).as_bytes());
            script_bytes
                .extend(Pairing::ell_by_constant(&constant_iters[j].next().unwrap()).as_bytes());
        }
        // [beta_12, beta_13, beta_22, P1, P2, P3, P4, Q4, T4, f]

        // 5.2 non-fixed part, P4
        // copy P4
        script_bytes.extend(Fq2::copy(22).as_bytes());
        // [beta_12, beta_13, beta_22, P1, P2, P3, P4, Q4, T4, f, P4]
        script_bytes.extend(Fq6::roll(14).as_bytes());
        // [beta_12, beta_13, beta_22, P1, P2, P3, P4, Q4, f, P4, T4]

        // 5.2.1 Qx.conjugate * beta^{2 * (p - 1) / 6}
        let offset_Q = (6 + 2 + 12) as u32;
        script_bytes.extend(Fq2::copy(offset_Q + 2).as_bytes());
        // [beta_12, beta_13, beta_22, P1, P2, P3, P4, Q4, f, P4, T4, Qx]
        script_bytes.extend(Fq::neg(0).as_bytes());
        // [beta_12, beta_13, beta_22, P1(32), P2, P3, P4, Q4(22), f(10), P4(8), T4, Qx']
        let offset_beta_12 = 38 as u32;
        script_bytes.extend(Fq2::roll(offset_beta_12).as_bytes());
        // [beta_13, beta_22, P1, P2, P3, P4, Q4, f, P4, T4, Qx', beta_12]
        script_bytes.extend(Fq2::mul(2, 0).as_bytes());
        // [beta_13, beta_22, P1, P2, P3, P4, Q4, f, P4, T4, Qx' * beta_12]
        // [beta_13, beta_22, P1, P2, P3, P4, Q4(22), f, P4, T4, Qx]

        // 5.2.2 Qy.conjugate * beta^{3 * (p - 1) / 6}
        script_bytes.extend(Fq2::copy(offset_Q + 2).as_bytes());
        script_bytes.extend(Fq::neg(0).as_bytes());
        // [beta_13(38), beta_22, P1, P2, P3, P4(28), Q4(24), f(12), P4(10), T4(4), Qx, Qy']
        let offset_beta_13 = 38 as u32;
        script_bytes.extend(Fq2::roll(offset_beta_13).as_bytes());
        // [beta_22, P1, P2, P3, P4, Q4, f, P4, T4, Qx, Qy', beta_13]
        script_bytes.extend(Fq2::mul(2, 0).as_bytes());
        // [beta_22, P1, P2, P3, P4, Q4, f, P4, T4, Qx, Qy' * beta_13]
        // [beta_22, P1, P2, P3, P4, Q4, f, P4, T4, Qx, Qy]

        // add line with T and phi(Q)
        script_bytes.extend(Pairing::add_line().as_bytes());
        // [beta_22, P1, P2, P3, P4, Q4, f, P4, T4, (,,)]
        script_bytes.extend(Fq6::roll(6).as_bytes());
        // [beta_22, P1, P2, P3, P4, Q4, f, P4, (,,), T4]
        script_bytes.extend(Fq6::toaltstack().as_bytes());
        // [beta_22, P1, P2, P3, P4, Q4, f, P4, (,,) | T4]

        // line evaluation and update f
        script_bytes.extend(Fq2::roll(6).as_bytes());
        // [beta_22, P1, P2, P3, P4, Q4, f, (,,), P4 | T4]
        script_bytes.extend(Pairing::ell().as_bytes());
        // [beta_22, P1, P2, P3, P4, Q4, f | T4]
        script_bytes.extend(Fq6::fromaltstack().as_bytes());
        script_bytes.extend(Fq12::roll(6).as_bytes());
        // [beta_22, P1, P2, P3, P4, Q4, T4, f]

        /////////////////////////////////////// 6. two-times frobenius map on fixed and non-fixed lines
        /// 6.1 fixed part, P1, P2, P3
        for j in 0..num_constant {
            let offset = (28 - j * 2) as u32;
            script_bytes.extend(Fq2::roll(offset).as_bytes());
            script_bytes
                .extend(Pairing::ell_by_constant(&constant_iters[j].next().unwrap()).as_bytes());
        }
        // [beta_22, P4, Q4, T4, f]

        // non-fixed part, P4
        let offset_P = 22 as u32;
        script_bytes.extend(Fq2::roll(offset_P).as_bytes());
        // [beta_22, Q4, T4, f, P4]
        script_bytes.extend(Fq6::roll(14).as_bytes());
        // [beta_22, Q4, f, P4, T4]

        // 6.2 phi(Q)
        // Qx * beta^{2 * (p^2 - 1) / 6}
        let offset_Q = 20;
        script_bytes.extend(Fq2::roll(offset_Q + 2).as_bytes());
        // [beta_22, Qy, f, P4, T4, Qx]
        let offset_beta_22 = 24 as u32;
        script_bytes.extend(Fq2::roll(offset_beta_22).as_bytes());
        // [Qy, f, P4, T4, Qx, beta_22]
        script_bytes.extend(Fq2::mul(2, 0).as_bytes());
        // [Qy, f, P4, T4, Qx * beta_22]
        // - Qy
        script_bytes.extend(Fq2::roll(22).as_bytes());
        // [f, P4, T4, Qx * beta_22, Qy]
        // [f, P4, T4, Qx, Qy]

        // 6.3 add line with T and phi(Q)
        script_bytes.extend(Pairing::add_line().as_bytes());
        // [f, P4, T4, (,,)]
        script_bytes.extend(Fq6::roll(6).as_bytes());
        // [f, P4, (,,), T4]
        script_bytes.extend(Fq6::drop().as_bytes());
        // [f, P4, (,,)]
        // line evaluation and update f
        script_bytes.extend(Fq2::roll(6).as_bytes());
        // [f, (,,), P4]
        script_bytes.extend(Pairing::ell().as_bytes());
        // [f]

        for i in 0..num_constant {
            assert_eq!(constant_iters[i].next(), None);
        }

        Script::from(script_bytes)
    }
}

#[cfg(test)]
mod test {
    use crate::bn254::ell_coeffs::G2Prepared;
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::bn254::fq::Fq;
    use crate::bn254::fq12::Fq12;
    use crate::bn254::fq2::Fq2;
    use crate::bn254::fq6::Fq6;
    use crate::bn254::pairing::Pairing;
    use crate::bn254::utils::{fq12_push, fq2_push};
    use crate::treepp::*;
    use ark_bn254::Bn254;

    use ark_ec::pairing::Pairing as _;
    use ark_ec::short_weierstrass::SWCurveConfig;
    use ark_ec::AffineRepr;

    use ark_ff::Field;
    use ark_std::UniformRand;
    use num_bigint::BigUint;
    use num_traits::Num;
    use num_traits::One;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::str::FromStr;

    #[test]
    fn test_quad_miller_loop_with_c_wi() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
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
            // random c and wi
            let c = ark_bn254::Fq12::rand(&mut prng);
            let c_inv = c.inverse().unwrap();
            let wi = ark_bn254::Fq12::rand(&mut prng);

            let P1 = ark_bn254::G1Affine::rand(&mut prng);
            let P2 = ark_bn254::G1Affine::rand(&mut prng);
            let P3 = ark_bn254::G1Affine::rand(&mut prng);
            let P4 = ark_bn254::G1Affine::rand(&mut prng);

            let Q1 = ark_bn254::g2::G2Affine::rand(&mut prng);
            let Q2 = ark_bn254::g2::G2Affine::rand(&mut prng);
            let Q3 = ark_bn254::g2::G2Affine::rand(&mut prng);
            let Q4 = ark_bn254::g2::G2Affine::rand(&mut prng);
            let Q1_prepared = G2Prepared::from(Q1);
            let Q2_prepared = G2Prepared::from(Q2);
            let Q3_prepared = G2Prepared::from(Q3);

            let T4 = Q4.into_group();

            let quad_miller_loop_with_c_wi = Pairing::quad_miller_loop_with_c_wi(
                &[Q1_prepared, Q2_prepared, Q3_prepared].to_vec(),
            );
            println!(
                "Pairing.quad_miller_loop_with_c_wi: {} bytes",
                quad_miller_loop_with_c_wi.len()
            );

            let f = Bn254::multi_miller_loop([P1, P2, P3, P4], [Q1, Q2, Q3, Q4]).0;
            println!("Bn254::multi_miller_loop done!");
            let hint = if sign {
                f * wi * (c_inv.pow(exp.to_u64_digits()))
            } else {
                f * wi * (c_inv.pow(exp.to_u64_digits()).inverse().unwrap())
            };
            println!("Accumulated f done!");

            // beta^{2 * (p - 1) / 6}, beta^{3 * (p - 1) / 6}, beta^{2 * (p^2 - 1) / 6}, 1/2, B / beta,
            // P1, P2, P3, P4, Q4, c, c_inv, wi, T4
            let script = script! {
                { Fq::push_u32_le(&BigUint::from_str("21575463638280843010398324269430826099269044274347216827212613867836435027261").unwrap().to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from_str("10307601595873709700152284273816112264069230130616436755625194854815875713954").unwrap().to_u32_digits()) }

                { Fq::push_u32_le(&BigUint::from_str("2821565182194536844548159561693502659359617185244120367078079554186484126554").unwrap().to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from_str("3505843767911556378687030309984248845540243509899259641013678093033130930403").unwrap().to_u32_digits()) }

                { Fq::push_u32_le(&BigUint::from_str("21888242871839275220042445260109153167277707414472061641714758635765020556616").unwrap().to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from_str("0").unwrap().to_u32_digits()) }

                { Fq::push_u32_le(&BigUint::from(ark_bn254::Fq::one().double().inverse().unwrap()).to_u32_digits()) }

                { Fq::push_u32_le(&BigUint::from(ark_bn254::g2::Config::COEFF_B.c0).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(ark_bn254::g2::Config::COEFF_B.c1).to_u32_digits()) }

                { Fq::push_u32_le(&BigUint::from(P1.x).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(P1.y).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(P2.x).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(P2.y).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(P3.x).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(P3.y).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(P4.x).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(P4.y).to_u32_digits()) }

                { fq2_push(Q4.x) }
                { fq2_push(Q4.y) }

                { fq12_push(c) }
                { fq12_push(c_inv) }
                { fq12_push(wi) }

                { fq2_push(T4.x) }
                { fq2_push(T4.y) }
                { fq2_push(T4.z) }

                { quad_miller_loop_with_c_wi.clone() }

                { fq12_push(hint) }
                { Fq12::equalverify() }

                // [beta_12, beta_13, beta_22, 1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4, f]
                // { Fq12::drop() }
                // { Fq6::drop() }
                // { Fq12::drop() }
                // { Fq12::drop() }
                // { Fq12::drop() }

                // { Fq2::drop() }
                // { Fq2::drop() }

                // { Fq2::drop() }
                // { Fq2::drop() }
                // { Fq2::drop() }
                // { Fq2::drop() }

                // { Fq2::drop() }
                // { Fq::drop() }

                // { Fq2::drop() }
                // { Fq2::drop() }
                // { Fq2::drop() }

                OP_TRUE
            };
            let exec_result = execute_script(script);
            println!("{}", exec_result);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_demo() {
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
        // random c and wi
        let c = ark_bn254::Fq12::rand(&mut prng);
        let c_inv = c.inverse().unwrap();
        let wi = ark_bn254::Fq12::rand(&mut prng);

        let P1 = ark_bn254::G1Affine::rand(&mut prng);
        let P2 = ark_bn254::G1Affine::rand(&mut prng);
        let P3 = ark_bn254::G1Affine::rand(&mut prng);
        let P4 = ark_bn254::G1Affine::rand(&mut prng);

        let Q1 = ark_bn254::g2::G2Affine::rand(&mut prng);
        let Q2 = ark_bn254::g2::G2Affine::rand(&mut prng);
        let Q3 = ark_bn254::g2::G2Affine::rand(&mut prng);
        let Q4 = ark_bn254::g2::G2Affine::rand(&mut prng);
        let Q1_prepared = G2Prepared::from(Q1);
        let Q2_prepared = G2Prepared::from(Q2);
        let Q3_prepared = G2Prepared::from(Q3);

        let T4 = Q4.into_group();

        let quad_miller_loop_with_c_wi =
            Pairing::quad_miller_loop_with_c_wi(&[Q1_prepared, Q2_prepared, Q3_prepared].to_vec());
        println!(
            "Pairing.quad_miller_loop_with_c_wi: {} bytes",
            quad_miller_loop_with_c_wi.len()
        );

        let script = script! {
            // { Fq::push_u32_le(&BigUint::from(ark_bn254::Fq::one().double().inverse().unwrap()).to_u32_digits()) }

            // { Fq::push_u32_le(&BigUint::from(ark_bn254::g2::Config::COEFF_B.c0).to_u32_digits()) }
            // { Fq::push_u32_le(&BigUint::from(ark_bn254::g2::Config::COEFF_B.c1).to_u32_digits()) }

            { Fq::push_u32_le(&BigUint::from(P1.x).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(P1.y).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(P2.x).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(P2.y).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(P3.x).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(P3.y).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(P4.x).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(P4.y).to_u32_digits()) }

            { fq2_push(Q4.x) }
            { fq2_push(Q4.y) }

            { fq12_push(c) }
            { fq12_push(c_inv) }
            { fq12_push(wi) }

            { fq2_push(T4.x) }
            { fq2_push(T4.y) }
            { fq2_push(T4.z) }

            // { quad_miller_loop_with_c_wi.clone() }
            { Fq12::copy(18) }
            { Fq12::square() }
            { Fq12::copy(30) }
            { Fq12::mul(12, 0) }

            { Fq12::drop() }
            { Fq12::drop() }
            { Fq6::drop() }
            { Fq12::drop() }
            { Fq12::drop() }
            { Fq12::drop() }
            { Fq2::drop() }
            { Fq2::drop() }

            { Fq2::drop() }
            { Fq2::drop() }
            { Fq2::drop() }
            { Fq2::drop() }

            // { Fq2::drop() }
            // { Fq::drop() }

            OP_TRUE
        };
        let exec_result = execute_script(script);
        println!("{}", exec_result);
        assert!(exec_result.success);
    }
}
