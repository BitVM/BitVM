#[allow(non_snake_case)]
#[cfg(test)]
mod test {
    use crate::bn254::curves::G1Affine;
    use crate::bn254::curves::G1Projective;
    use crate::bn254::ell_coeffs::G2Prepared;
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::bn254::fq::Fq;
    use crate::bn254::fq12::Fq12;
    use crate::bn254::fr::Fr;
    use crate::bn254::pairing::Pairing;

    use crate::bn254::utils;
    use crate::execute_script_as_chunks;
    use crate::hash::blake3::blake3_var_length;
    use crate::treepp::*;
    use ark_bn254::Bn254;
    use ark_ec::pairing::Pairing as ArkPairing;
    use ark_ec::CurveGroup;
    use ark_ff::{Field, One};
    use ark_std::UniformRand;
    use num_bigint::BigUint;
    use num_traits::{Num, ToPrimitive};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::str::FromStr;

    fn fq12_push(element: ark_bn254::Fq12) -> Script {
        script! {
            for elem in element.to_base_prime_field_elements() {
                { Fq::push_u32_le(&BigUint::from(elem).to_u32_digits()) }
           }
        }
    }

    /// compute challenges
    fn compute_challenges_beta(
        hash: &Script,
        c0_x: &str,
        c0_y: &str,
        c1_x: &str,
        c1_y: &str,
        inp_1: &str,
        inp_2: &str,
    ) -> Script {
        script! {
            // push C0
            {
                Fq::push_dec(
                    c0_x
                )
            }
            {
                Fq::push_dec(
                    c0_y
                )
            }
            // push the public input
            {
                Fq::push_dec(inp_1)
            }
            {
                Fq::push_dec(inp_2)
            }
            // push C1
            {
                Fq::push_dec(
                    c1_x
                )
            }
            {
                Fq::push_dec(
                    c1_y
                )
            }

            // send C0 to altstack
            {
                Fq::roll(4)
            }
            {
                Fq::toaltstack()
            }
            {
                Fq::roll(4)
            }
            {
                Fq::toaltstack()
            }

            // send the public input to altstack
            {
                Fq::roll(3)
            }
            {
                Fq::toaltstack()
            }
            {
                Fq::roll(2)
            }
            {
                Fq::toaltstack()
            }

            // convert C1 into bytes
            {
                G1Affine::convert_to_compressed()
            }

            // convert the public input into bytes
            {
                Fq::fromaltstack()
            }
            {
                Fq::convert_to_be_bytes()
            }
            {
                Fq::fromaltstack()
            }
            {
                Fq::convert_to_be_bytes()
            }

            // convert C0 into bytes
            {
                Fq::fromaltstack()
            }
            {
                Fq::fromaltstack()
            }
            {
                G1Affine::convert_to_compressed()
            }

            // compute the hash
            {
                hash.clone()
            }
            {
                Fr::from_hash()
            }
        }
    }

    fn compute_challenges_gamma(hash: &Script) -> Script {
        script! {
         { Fr::copy(0) }
         { Fr::convert_to_be_bytes() }
         { hash.clone() }
         { Fr::from_hash() }
        }
    }

    fn compute_challenges_alpha(
        hash: &Script,
        xi: &str,
        ql: &str,
        qr: &str,
        qm: &str,
        qo: &str,
        qc: &str,
        s1: &str,
        s2: &str,
        s3: &str,
        a: &str,
        b: &str,
        c: &str,
        z: &str,
        zw: &str,
        t1w: &str,
        t2w: &str,
    ) -> Script {
        script! {
            // push xi seed
            { Fr::push_dec(xi) }

            // push the polynomial evaluations

            // ql
            { Fr::push_dec(ql) }

            // qr
            { Fr::push_dec(qr) }

            // qm
            { Fr::push_dec(qm) }

            // qo
            { Fr::push_dec(qo) }

            // qc
            { Fr::push_dec(qc) }

            // s1
            { Fr::push_dec(s1) }

            // s2
            { Fr::push_dec(s2) }

            // s3
            { Fr::push_dec(s3) }

            // a
            { Fr::push_dec(a) }

            // b
            { Fr::push_dec(b) }

            // c
            { Fr::push_dec(c) }

            // z
            { Fr::push_dec(z) }

            // zw
            { Fr::push_dec(zw) }

            // t1w
            { Fr::push_dec(t1w) }

            // t2w
            { Fr::push_dec(t2w) }

            for i in 1..16 {
                { Fr::roll(16 - i) } { Fr::toaltstack() }
            }

            { Fr::convert_to_be_bytes() }

            for _ in 0..15 {
                { Fr::fromaltstack() } { Fr::convert_to_be_bytes() }
            }

            {hash.clone()}
            { Fr::from_hash() }
        }
    }

    // [beta, gamma, alpha]
    fn compute_challenges_y(hash: &Script, w1_x: &str, w1_y: &str) -> Script {
        script! {
            // alpha
            { Fr::copy(0) }
            // W1
            { Fq::push_dec(w1_x) }
            { Fq::push_dec(w1_y) }

            { Fr::roll(2) }
            { Fr::toaltstack() }

            { G1Affine::convert_to_compressed() }
            { Fr::fromaltstack() }
            { Fr::convert_to_be_bytes() }

            {hash.clone()}
            { Fr::from_hash() }
        }
    }

    // [beta, gamma, alpha, y]
    fn compute_challenges_xiseed(hash: &Script, c2_x: &str, c2_y: &str) -> Script {
        script! {
            { Fr::copy(2) }
            // C2
            { Fq::push_dec(c2_x) }
            { Fq::push_dec(c2_y) }

            { Fr::roll(2) }
            { Fr::toaltstack() }

            { G1Affine::convert_to_compressed() }
            { Fr::fromaltstack() }
            { Fr::convert_to_be_bytes() }

            {hash.clone()}
            { Fr::from_hash() }
        }
    }

    // [beta, gamma, alpha, y, xiseed]
    fn compute_challenges_xin(
        w8_1: &str,
        w8_2: &str,
        w8_3: &str,
        w8_4: &str,
        w8_5: &str,
        w8_6: &str,
        w8_7: &str,
        w3: &str,
        w3_2: &str,
        w4: &str,
        w4_2: &str,
        w4_3: &str,
        wr: &str,
    ) -> Script {
        script! {
            // push xiseed
            // { Fr::copy(0) }
            // compute xiseed^2
            { Fr::copy(0) }
            { Fr::square() }
            { Fr::copy(0) }
            { Fr::toaltstack() }

            // pH0w8_0 = xiseed^3
            { Fr::mul() }
            // [beta, gamma, alpha, y, pH0w8_0]

            // pH0w8_1
            { Fr::copy(0) }
            // push constant w8_1
            { Fr::push_dec(w8_1) }
            { Fr::mul() }
            // [beta, gamma, alpha, y, pH0w8_0, pH0w8_1]

            // pH0w8_2
            // { Fr::copy(0) }
            { Fr::copy(1) }
            // push constant w8_2
            { Fr::push_dec(w8_2) }
            { Fr::mul() }
            // [beta, gamma, alpha, y, pH0w8_0, pH0w8_1, pH0w8_2]

            // pH0w8_3
            // { Fr::copy(0) }
            { Fr::copy(2) }
            // push constant w8_3
            { Fr::push_dec(w8_3) }
            { Fr::mul() }
            // [beta, gamma, alpha, y, pH0w8_0, pH0w8_1, pH0w8_2, pH0w8_3]

            // pH0w8_4
            { Fr::copy(3) }
            // push constant w8_4
            { Fr::push_dec(w8_4) }
            { Fr::mul() }
            // [beta, gamma, alpha, y, pH0w8_0, pH0w8_1, pH0w8_2, pH0w8_3, pH0w8_4]

            // pH0w8_5
            { Fr::copy(4) }
            // push constant w8_5
            { Fr::push_dec(w8_5) }
            { Fr::mul() }
            // [beta, gamma, alpha, y, pH0w8_0, pH0w8_1, pH0w8_2, pH0w8_3, pH0w8_4, pH0w8_5]

            // pH0w8_6
            { Fr::copy(5) }
            // push constant w8_6
            { Fr::push_dec(w8_6) }
            { Fr::mul() }
            // [beta, gamma, alpha, y, pH0w8_0, pH0w8_1, pH0w8_2, pH0w8_3, pH0w8_4, pH0w8_5, pH0w8_6]

            // pH0w8_7
            { Fr::copy(6) }
            // push constant w8_7
            { Fr::push_dec(w8_7) }
            { Fr::mul() }
            // [beta, gamma, alpha, y, pH0w8_0, pH0w8_1, pH0w8_2, pH0w8_3, pH0w8_4, pH0w8_5, pH0w8_6, pH0w8_7]

            // pH1w4_0 = xiseed^6
            { Fr::copy(7) }
            { Fr::square() }
            // [beta, gamma, alpha, y, pH0w8_0, pH0w8_1, pH0w8_2, pH0w8_3, pH0w8_4, pH0w8_5, pH0w8_6, pH0w8_7,
            // pH1w4_0, ]

            // pH1w4_1
            { Fr::copy(0) }
            // push constant w4
            { Fr::push_dec(w4) }
            { Fr::mul() }
            // [beta, gamma, alpha, y, pH0w8_0, pH0w8_1, pH0w8_2, pH0w8_3, pH0w8_4, pH0w8_5, pH0w8_6, pH0w8_7,
            // pH1w4_0, pH1w4_1]

            // pH1w4_2
            { Fr::copy(1) }
            // push constant w4_1
            { Fr::push_dec(w4_2) }
            { Fr::mul() }
            // [beta, gamma, alpha, y, pH0w8_0, pH0w8_1, pH0w8_2, pH0w8_3, pH0w8_4, pH0w8_5, pH0w8_6, pH0w8_7,
            // pH1w4_0, pH1w4_1, pH1w4_2]

            // pH1w4_3
            { Fr::copy(2) }
            // push constant w4_2
            { Fr::push_dec(w4_3) }
            { Fr::mul() }
            // [beta, gamma, alpha, y, pH0w8_0, pH0w8_1, pH0w8_2, pH0w8_3, pH0w8_4, pH0w8_5, pH0w8_6, pH0w8_7,
            // pH1w4_0, pH1w4_1, pH1w4_2, pH1w4_3]

            // pH2w3_0 = xiseed^8
            { Fr::copy(3) }
            { Fr::fromaltstack() }
            { Fr::mul() }
            // { Fr::copy(0) }
            // { Fr::toaltstack() }
            // [beta, gamma, alpha, y, pH0w8_0, pH0w8_1, pH0w8_2, pH0w8_3, pH0w8_4, pH0w8_5, pH0w8_6, pH0w8_7,
            // pH1w4_0, pH1w4_1, pH1w4_2, pH1w4_3, pH2w3_0]

            // pH2w3_1
            { Fr::copy(0) }
            // push constant w3
            { Fr::push_dec(w3) }
            { Fr::mul() }
            // [beta, gamma, alpha, y, pH0w8_0, pH0w8_1, pH0w8_2, pH0w8_3, pH0w8_4, pH0w8_5, pH0w8_6, pH0w8_7,
            // pH1w4_0, pH1w4_1, pH1w4_2, pH1w4_3, pH2w3_0, pH2w3_1]

            // pH2w3_2
            { Fr::copy(1) }
            // push constant w3_2
            { Fr::push_dec(w3_2) }
            { Fr::mul() }
            // [beta, gamma, alpha, y, pH0w8_0, pH0w8_1, pH0w8_2, pH0w8_3, pH0w8_4, pH0w8_5, pH0w8_6, pH0w8_7,
            // pH1w4_0, pH1w4_1, pH1w4_2, pH1w4_3, pH2w3_0, pH2w3_1, pH2w3_2]

            // pH3w3_0 = xiseed^8 * ω^{1/3}
            { Fr::copy(2) }
            { Fr::push_dec(wr) }
            { Fr::mul() }
            // [beta, gamma, alpha, y, pH0w8_0, pH0w8_1, pH0w8_2, pH0w8_3, pH0w8_4, pH0w8_5, pH0w8_6, pH0w8_7,
            // pH1w4_0, pH1w4_1, pH1w4_2, pH1w4_3, pH2w3_0, pH2w3_1, pH2w3_2, pH3w3_0]

            // pH3w3_1
            { Fr::copy(0) }
            // push constant w3
            { Fr::push_dec(w3) }
            { Fr::mul() }
            // [beta, gamma, alpha, y, pH0w8_0, pH0w8_1, pH0w8_2, pH0w8_3, pH0w8_4, pH0w8_5, pH0w8_6, pH0w8_7,
            // pH1w4_0, pH1w4_1, pH1w4_2, pH1w4_3, pH2w3_0, pH2w3_1, pH2w3_2, pH3w3_0, pH3w3_1]

            // pH2w3_2
            // push constant w3_2
            { Fr::copy(1) }
            { Fr::push_dec(w3_2) }
            { Fr::mul() }
            // [beta, gamma, alpha, y, pH0w8_0, pH0w8_1, pH0w8_2, pH0w8_3, pH0w8_4, pH0w8_5, pH0w8_6, pH0w8_7,
            // pH1w4_0, pH1w4_1, pH1w4_2, pH1w4_3, pH2w3_0, pH2w3_1, pH2w3_2, pH3w3_0, pH3w3_1, pH2w3_2]

            // { Fr::fromaltstack() }
            { Fr::copy(5) }

            // xi = xi_seeder^24
            { Fr::copy(0) }
            { Fr::square() }
            { Fr::mul() }
            // [beta, gamma, alpha, y, pH0w8_0, pH0w8_1, pH0w8_2, pH0w8_3, pH0w8_4, pH0w8_5, pH0w8_6, pH0w8_7,
            // pH1w4_0, pH1w4_1, pH1w4_2, pH1w4_3, pH2w3_0, pH2w3_1, pH2w3_2, pH3w3_0, pH3w3_1, pH2w3_2, xi]

            // xiN
            { Fr::copy(0) }
            { Fr::square() }
            { Fr::square() }
            { Fr::square() }
            { Fr::square() }
            { Fr::square() }
            { Fr::square() }
            { Fr::square() }
            { Fr::square() }
            { Fr::square() }

            { Fr::square() }
            { Fr::square() }
            { Fr::square() }
            { Fr::square() }
            { Fr::square() }
            { Fr::square() }
            { Fr::square() }
            { Fr::square() }
            { Fr::square() }
            // [beta, gamma, alpha, y, pH0w8_0, pH0w8_1, pH0w8_2, pH0w8_3, pH0w8_4, pH0w8_5, pH0w8_6, pH0w8_7,
            // pH1w4_0, pH1w4_1, pH1w4_2, pH1w4_3, pH2w3_0, pH2w3_1, pH2w3_2, pH3w3_0, pH3w3_1, pH2w3_2, xi, xiN]

            // zh
            { Fr::push_one() }
            { Fr::sub(1, 0) }
            // [beta, gamma, alpha, y, pH0w8_0, pH0w8_1, pH0w8_2, pH0w8_3, pH0w8_4, pH0w8_5, pH0w8_6, pH0w8_7,
            // pH1w4_0, pH1w4_1, pH1w4_2, pH1w4_3, pH2w3_0, pH2w3_1, pH2w3_2, pH3w3_0, pH3w3_1, pH2w3_2, xi, zh]
        }
    }
    // [beta, gamma, alpha, y, pH0w8_0, pH0w8_1, pH0w8_2, pH0w8_3, pH0w8_4, pH0w8_5, pH0w8_6, pH0w8_7,
    // pH1w4_0, pH1w4_1, pH1w4_2, pH1w4_3, pH2w3_0, pH2w3_1, pH2w3_2, pH3w3_0, pH3w3_1, pH2w3_2, xi, zh]
    // pH3w3_0(3), pH2w3_0(6), pH1w4_0(10), pH0w8_0(18)

    /// compute inversions
    fn compute_inversions(w: &str, inv: &str) -> Script {
        script! {
            // push Z_H
            { Fr::copy(0) }
            { Fr::toaltstack() }

            // push y
            { Fr::copy(20) }
            // push H1w4_0, H1w4_1, H1w4_2, H1w4_3
            { Fr::copy(12) }
            { Fr::copy(12) }
            { Fr::copy(12) }
            { Fr::copy(12) }
            // [..., xi, zh, y, pH1w4_0, pH1w4_1, pH1w4_2, pH1w4_3 | Z_H]

            { Fr::copy(4) }
            { Fr::sub(0, 1) }
            // [xi, zh, y, pH1w4_0, pH1w4_1, pH1w4_2, y - pH1w4_3 | Z_H]
            { Fr::copy(4) }
            { Fr::sub(0, 2) }
            // [xi, zh, y, pH1w4_0, pH1w4_1, y - pH1w4_3, y - pH1w4_2 | Z_H]
            { Fr::copy(4) }
            { Fr::sub(0, 3) }
            // [xi, zh, y, pH1w4_0, y - pH1w4_3, y - pH1w4_2, y - pH1w4_1 | Z_H]
            { Fr::copy(4) }
            { Fr::sub(0, 4) }
            // [xi, zh, y, y - pH1w4_3, y - pH1w4_2, y - pH1w4_1, y - pH1w4_0 | Z_H]

            { Fr::mul() }
            { Fr::mul() }
            { Fr::mul() }
            // [y, (y - pH1w4_3) * (y - pH1w4_2) * (y - pH1w4_1) * (y - pH1w4_0)]
            { Fr::toaltstack() }
            // [y | Z_H, (y - pH1w4_3) * (y - pH1w4_2) * (y - pH1w4_1) * (y - pH1w4_0)]

            // push H2w3_0, H2w3_1, H2w3_2, H3w3_0, H3w3_1, H3w3_2
            { Fr::copy(8) }
            { Fr::copy(8) }
            { Fr::copy(8) }
            { Fr::copy(8) }
            { Fr::copy(8) }
            { Fr::copy(8) }
            // [y, H2w3_0, H2w3_1, H2w3_2, H3w3_0, H3w3_1, H3w3_2 | Z_H, prod_1]

            { Fr::copy(6) }
            { Fr::sub(0, 1) }
            // [y, H2w3_0, H2w3_1, H2w3_2, H3w3_0, H3w3_1, y -  H3w3_2]
            { Fr::copy(6) }
            { Fr::sub(0, 2) }
            // [y, H2w3_0, H2w3_1, H2w3_2, H3w3_0, y -  H3w3_2, y - H3w3_1]
            { Fr::copy(6) }
            { Fr::sub(0, 3) }
            // [y, H2w3_0, H2w3_1, H2w3_2, y -  H3w3_2, y - H3w3_1, y - H3w3_0]
            { Fr::copy(6) }
            { Fr::sub(0, 4) }
            // [y, H2w3_0, H2w3_1, y -  H3w3_2, y - H3w3_1, y - H3w3_0, y - H2w3_2]
            { Fr::copy(6) }
            { Fr::sub(0, 5) }
            // [y, H2w3_0, y -  H3w3_2, y - H3w3_1, y - H3w3_0, y - H2w3_2, y - H2w3_1]
            { Fr::copy(6) }
            { Fr::sub(0, 6) }
            // [y, y -  H3w3_2, y - H3w3_1, y - H3w3_0, y - H2w3_2, y - H2w3_1, y - H2w3_0]

            { Fr::mul() }
            { Fr::mul() }
            { Fr::mul() }
            { Fr::mul() }
            { Fr::mul() }
            // [y, (y -  H3w3_2) * (y - H3w3_1) * (y - H3w3_0) * (y - H2w3_2) * (y - H2w3_1) * (y - H2w3_0)]
            { Fr::toaltstack() }
            // [y | Z_H, prod_1, prod_2]

            // push H0w8_0, H0w8_1, H0w8_2, H0w8_3, H0w8_4, H0w8_5, H0w8_6, H0w8_7
            { Fr::copy(20) }
            { Fr::copy(20) }
            { Fr::copy(20) }
            { Fr::copy(20) }
            { Fr::copy(20) }
            { Fr::copy(20) }
            { Fr::copy(20) }
            { Fr::copy(20) }
            // [y, H0w8_0, H0w8_1, H0w8_2, H0w8_3, H0w8_4, H0w8_5, H0w8_6, H0w8_7 | Z_H, prod_1, prod_2]

            // den1 = Fr.mul(Fr.e(len), Fr.exp(roots[0], len - 2)) = = 8 * H0w8_0 ^ 6
            { Fr::copy(7) }
            { Fr::square() }
            { Fr::copy(0) }
            { Fr::square() }
            { Fr::mul() }
            { Fr::double(0) }
            { Fr::double(0) }
            { Fr::double(0) }
            { Fr::toaltstack() }
            // [y, H0w8_0, H0w8_1, H0w8_2, H0w8_3, H0w8_4, H0w8_5, H0w8_6, H0w8_7 | Z_H, prod_1, prod_2, den1]

            // den2 = roots[7 * 0 % 8] = roots[0]
            { Fr::copy(7) }
            { Fr::toaltstack() }
            // [y, H0w8_0, H0w8_1, H0w8_2, H0w8_3, H0w8_4, H0w8_5, H0w8_6, H0w8_7 | prod_1, prod_2, den1, den2]

            // den3 = x - roots[0]
            { Fr::copy(8) }
            { Fr::toaltstack() }
            { Fr::copy(7) }
            { Fr::fromaltstack() }
            { Fr::sub(0, 1) }
            // [y, H0w8_0, H0w8_1, H0w8_2, H0w8_3, H0w8_4, H0w8_5, H0w8_6, H0w8_7, y - H0w8_0 | Z_H, prod_1, prod_2, den1, den2]

            // LiS0_1 = den1 * den2 * den3, keep den1 in the altstack
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::fromaltstack() }
            { Fr::copy(0) }
            { Fr::roll(2) }
            { Fr::mul() }
            { Fr::toaltstack() }
            { Fr::toaltstack() }
            // [y, H0w8_0, H0w8_1, H0w8_2, H0w8_3, H0w8_4, H0w8_5, H0w8_6, H0w8_7 | Z_H, prod_1, prod_2, LiS0_1, den1]

            // den2 = roots[7 * 1 % 8] = roots[7]
            { Fr::copy(0) }
            { Fr::toaltstack() }
            // [y, H0w8_0, H0w8_1, H0w8_2, H0w8_3, H0w8_4, H0w8_5, H0w8_6, H0w8_7 | Z_H, prod_1, prod_2, LiS0_1, den1, H0w8_7]

            // den3 = x - roots[1]
            { Fr::copy(8) }
            { Fr::toaltstack() }
            { Fr::copy(6) }
            { Fr::fromaltstack() }
            { Fr::sub(0, 1) }
            // [y, H0w8_0, H0w8_1, H0w8_2, H0w8_3, H0w8_4, H0w8_5, H0w8_6, H0w8_7, y - H0w8_1 | Z_H, prod_1, prod_2, LiS0_1, den1, den2]

            // LiS0_2 = den1 * den2 * den3, keep den1 in the altstack
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::fromaltstack() }
            { Fr::copy(0) }
            { Fr::roll(2) }
            { Fr::mul() }
            { Fr::toaltstack() }
            { Fr::toaltstack() }
            // [y, H0w8_0, H0w8_1, H0w8_2, H0w8_3, H0w8_4, H0w8_5, H0w8_6, H0w8_7 | Z_H, prod_1, prod_2, LiS0_1, LiS0_2, den1]

            // den2 = roots[7 * 2 % 8] = roots[6]
            { Fr::copy(1) }
            { Fr::toaltstack() }

            // den3 = x - roots[2]
            { Fr::copy(8) }
            { Fr::toaltstack() }
            { Fr::copy(5) }
            { Fr::fromaltstack() }
            { Fr::sub(0, 1) }

            // LiS0_3 = den1 * den2 * den3, keep den1 in the altstack
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::fromaltstack() }
            { Fr::copy(0) }
            { Fr::roll(2) }
            { Fr::mul() }
            { Fr::toaltstack() }
            { Fr::toaltstack() }
            // [y, H0w8_0, H0w8_1, H0w8_2, H0w8_3, H0w8_4, H0w8_5, H0w8_6, H0w8_7 | Z_H, prod_1, prod_2, LiS0_1, LiS0_2, LiS0_3, den1]

            // den2 = roots[7 * 3 % 8] = roots[5]
            { Fr::copy(2) }
            { Fr::toaltstack() }

            // den3 = x - roots[3]
            { Fr::copy(8) }
            { Fr::toaltstack() }
            { Fr::copy(4) }
            { Fr::fromaltstack() }
            { Fr::sub(0, 1) }

            // LiS0_4 = den1 * den2 * den3, keep den1 in the altstack
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::fromaltstack() }
            { Fr::copy(0) }
            { Fr::roll(2) }
            { Fr::mul() }
            { Fr::toaltstack() }
            { Fr::toaltstack() }
            // [y, H0w8_0, H0w8_1, H0w8_2, H0w8_3, H0w8_4, H0w8_5, H0w8_6, H0w8_7 | Z_H, prod_1, prod_2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, den1]

            // den2 = roots[7 * 4 % 8] = roots[4]
            { Fr::copy(3) }
            { Fr::toaltstack() }

            // den3 = x - roots[4]
            { Fr::copy(8) }
            { Fr::toaltstack() }
            { Fr::copy(3) }
            { Fr::fromaltstack() }
            { Fr::sub(0, 1) }

            // LiS0_5 = den1 * den2 * den3, keep den1 in the altstack
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::fromaltstack() }
            { Fr::copy(0) }
            { Fr::roll(2) }
            { Fr::mul() }
            { Fr::toaltstack() }
            { Fr::toaltstack() }
            // [y, H0w8_0, H0w8_1, H0w8_2, H0w8_3, H0w8_4, H0w8_5, H0w8_6, H0w8_7 | Z_H, prod_1, prod_2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, den1]

            // den2 = roots[7 * 5 % 8] = roots[3]
            { Fr::copy(4) }
            { Fr::toaltstack() }

            // den3 = x - roots[5]
            { Fr::copy(8) }
            { Fr::toaltstack() }
            { Fr::copy(2) }
            { Fr::fromaltstack() }
            { Fr::sub(0, 1) }

            // LiS0_6 = den1 * den2 * den3, keep den1 in the altstack
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::fromaltstack() }
            { Fr::copy(0) }
            { Fr::roll(2) }
            { Fr::mul() }
            { Fr::toaltstack() }
            { Fr::toaltstack() }
            // [y, H0w8_0, H0w8_1, H0w8_2, H0w8_3, H0w8_4, H0w8_5, H0w8_6, H0w8_7 | Z_H, prod_1, prod_2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, den1]

            // den2 = roots[7 * 6 % 8] = roots[2]
            { Fr::copy(5) }
            { Fr::toaltstack() }

            // den3 = x - roots[6]
            { Fr::copy(8) }
            { Fr::toaltstack() }
            { Fr::copy(1) }
            { Fr::fromaltstack() }
            { Fr::sub(0, 1) }

            // LiS0_7 = den1 * den2 * den3, keep den1 in the altstack
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::fromaltstack() }
            { Fr::copy(0) }
            { Fr::roll(2) }
            { Fr::mul() }
            { Fr::toaltstack() }
            { Fr::toaltstack() }
           // [y, H0w8_0, H0w8_1, H0w8_2, H0w8_3, H0w8_4, H0w8_5, H0w8_6, H0w8_7 | Z_H, prod_1, prod_2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, den1]

            // den2 = roots[7 * 7 % 8] = roots[1]
            { Fr::copy(6) }
            { Fr::toaltstack() }

            // den3 = x - roots[7]
            { Fr::copy(8) }
            { Fr::toaltstack() }
            { Fr::copy(0) }
            { Fr::fromaltstack() }
            { Fr::sub(0, 1) }

            // LiS0_8 = den1 * den2 * den3, remove den1 in the altstack
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::toaltstack() }
           // [y, H0w8_0, H0w8_1, H0w8_2, H0w8_3, H0w8_4, H0w8_5, H0w8_6, H0w8_7 | Z_H, prod_1, prod_2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8]

            // drop H0w8_0, H0w8_1, H0w8_2, H0w8_3, H0w8_4, H0w8_5, H0w8_6, H0w8_7
            { Fr::drop() }
            { Fr::drop() }
            { Fr::drop() }
            { Fr::drop() }
            { Fr::drop() }
            { Fr::drop() }
            { Fr::drop() }
            { Fr::drop() }
           // [y | Z_H, prod_1, prod_2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8]

            // push H1w4_0, H1w4_1, H1w4_2, H1w4_3
            { Fr::copy(12) }
            { Fr::copy(12) }
            { Fr::copy(12) }
            { Fr::copy(12) }

            // den1 = Fr.mul(Fr.e(len), Fr.exp(roots[0], len - 2)) = = 4 * H0w8_0 ^ 2
            { Fr::copy(3) }
            { Fr::square() }
            { Fr::double(0) }
            { Fr::double(0) }
            { Fr::toaltstack() }
           // [y, H1w4_0, H1w4_1, H1w4_2, H1w4_3 | Z_H, prod_1, prod_2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8, den1]

            // den2 = roots[3 * 0 % 4] = roots[0]
            { Fr::copy(3) }
            { Fr::toaltstack() }
           // [y, H1w4_0, H1w4_1, H1w4_2, H1w4_3 | Z_H, prod_1, prod_2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8, den1, den2]

            // den3 = x - roots[0]
            { Fr::copy(4) }
            { Fr::toaltstack() }
            { Fr::copy(3) }
            { Fr::fromaltstack() }
            { Fr::sub(0, 1) }
           // [y, H1w4_0, H1w4_1, H1w4_2, H1w4_3, den3 | Z_H, prod_1, prod_2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8, den1, den2]

            // LiS1_1 = den1 * den2 * den3, keep den1 in the altstack
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::fromaltstack() }
            { Fr::copy(0) }
            { Fr::roll(2) }
            { Fr::mul() }
            { Fr::toaltstack() }
            { Fr::toaltstack() }
           // [y, H1w4_0, H1w4_1, H1w4_2, H1w4_3 | Z_H, prod_1, prod_2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8, LiS1_1, den1]

            // den2 = roots[3 * 1 % 4] = roots[3]
            { Fr::copy(0) }
            { Fr::toaltstack() }

            // den3 = x - roots[1]
            { Fr::copy(4) }
            { Fr::toaltstack() }
            { Fr::copy(2) }
            { Fr::fromaltstack() }
            { Fr::sub(0, 1) }

            // LiS1_2 = den1 * den2 * den3, keep den1 in the altstack
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::fromaltstack() }
            { Fr::copy(0) }
            { Fr::roll(2) }
            { Fr::mul() }
            { Fr::toaltstack() }
            { Fr::toaltstack() }
           // [y, H1w4_0, H1w4_1, H1w4_2, H1w4_3 | Z_H, prod_1, prod_2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8, LiS1_1, LiS1_2, den1]

            // den2 = roots[3 * 2 % 4] = roots[2]
            { Fr::copy(1) }
            { Fr::toaltstack() }

            // den3 = x - roots[2]
            { Fr::copy(4) }
            { Fr::toaltstack() }
            { Fr::copy(1) }
            { Fr::fromaltstack() }
            { Fr::sub(0, 1) }

            // LiS1_3 = den1 * den2 * den3, keep den1 in the altstack
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::fromaltstack() }
            { Fr::copy(0) }
            { Fr::roll(2) }
            { Fr::mul() }
            { Fr::toaltstack() }
            { Fr::toaltstack() }
           // [y, H1w4_0, H1w4_1, H1w4_2, H1w4_3 | Z_H, prod_1, prod_2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8, LiS1_1, LiS1_2, LiS1_3, den1]

            // den2 = roots[3 * 3 % 4] = roots[1]
            { Fr::copy(2) }
            { Fr::toaltstack() }

            // den3 = x - roots[3]
            { Fr::copy(4) }
            { Fr::toaltstack() }
            { Fr::copy(0) }
            { Fr::fromaltstack() }
            { Fr::sub(0, 1) }

            // LiS1_4 = den1 * den2 * den3, remove den1 in the altstack
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::toaltstack() }
           // [y, H1w4_0, H1w4_1, H1w4_2, H1w4_3 | Z_H, prod_1, prod_2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8, LiS1_1, LiS1_2, LiS1_3, LiS1_4]

            // drop H1w4_0, H1w4_1, H1w4_2, H1w4_3
            { Fr::drop() }
            { Fr::drop() }
            { Fr::drop() }
            { Fr::drop() }
           // [y | prod_1, prod_2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8, LiS1_1, LiS1_2, LiS1_3, LiS1_4]

            // push H2w3_0, H2w3_1, H2w3_2
            { Fr::copy(8) }
            { Fr::copy(8) }
            { Fr::copy(8) }
            // [y, H2w3_0, H2w3_1, H2w3_2 | Z_H, prod_1, prod_2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8, LiS1_1, LiS1_2, LiS1_3, LiS1_4]

            // push xi
            // { Fr::push_dec("14814634099415170872937750660683266261347419959225231219985478027287965492246") }
            { Fr::copy(5) }
            // [y, H2w3_0, H2w3_1, H2w3_2, xi | Z_H, prod_1, prod_2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8, LiS1_1, LiS1_2, LiS1_3, LiS1_4]

            // compute xiw
            { Fr::copy(0) }
            { Fr::push_dec(w) }
            { Fr::mul() }
            // [y, H2w3_0, H2w3_1, H2w3_2, xi, xiw | Z_H, prod_1, prod_2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8, LiS1_1, LiS1_2, LiS1_3, LiS1_4]

            // compute xi - xiw
            { Fr::sub(1, 0) }
            { Fr::copy(0) }
            { Fr::toaltstack() }
            // [y, H2w3_0, H2w3_1, H2w3_2, xi - xiw | Z_H, prod_1, prod_2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8, LiS1_1, LiS1_2, LiS1_3, LiS1_4, xi - xiw]

            // move xi - xiw to before y
            { Fr::roll(4) }
            { Fr::roll(4) }
            { Fr::roll(4) }
            { Fr::roll(4) }
            // [xi - xiw, y, H2w3_0, H2w3_1, H2w3_2 | Z_H, prod_1, prod_2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8, LiS1_1, LiS1_2, LiS1_3, LiS1_4, xi - xiw]

            // _3h2 = Fr.mul(Fr.e(len), Fr.exp(roots[0], len - 2)) = = 3 * H2w3_0
            { Fr::copy(2) }
            { Fr::copy(0) }
            { Fr::double(0) }
            { Fr::add(1, 0) }

            // compute den1 = _3h2 * (xi - xiw)
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::toaltstack() }
            // [xi - xiw, y, H2w3_0, H2w3_1, H2w3_2 |
            // Z_H, prod_1, prod_2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8, LiS1_1, LiS1_2, LiS1_3, LiS1_4, den1]

            // den2 = roots[2 * 0 % 3] = roots[0]
            { Fr::copy(2) }
            { Fr::toaltstack() }
            // [xi - xiw, y, H2w3_0, H2w3_1, H2w3_2 |
            // Z_H, prod_1, prod_2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8, LiS1_1, LiS1_2, LiS1_3, LiS1_4, den1, den2]

            // den3 = x - roots[0]
            { Fr::copy(3) }
            { Fr::toaltstack() }
            { Fr::copy(2) }
            { Fr::fromaltstack() }
            { Fr::sub(0, 1) }
            // [xi - xiw, y, H2w3_0, H2w3_1, H2w3_2, y - H2w3_0 |
            // Z_H, prod_1, prod_2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8, LiS1_1, LiS1_2, LiS1_3, LiS1_4, den1, den2]

            // LiS2_1 = den1 * den2 * den3, keep den1 in the altstack
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::fromaltstack() }
            { Fr::copy(0) }
            { Fr::roll(2) }
            { Fr::mul() }
            { Fr::toaltstack() }
            { Fr::toaltstack() }
            // [xi - xiw, y, H2w3_0, H2w3_1, H2w3_2 |
            // Z_H, prod_1, prod_2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8, LiS1_1, LiS1_2, LiS1_3, LiS1_4, LiS2_1, den1]

            // den2 = roots[2 * 1 % 3] = roots[2]
            { Fr::copy(0) }
            { Fr::toaltstack() }
            // [xi - xiw, y, H2w3_0, H2w3_1, H2w3_2 |
            // Z_H, prod_1, prod_2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8, LiS1_1, LiS1_2, LiS1_3, LiS1_4, LiS2_1, den1, den2]

            // den3 = x - roots[1]
            { Fr::copy(3) }
            { Fr::toaltstack() }
            { Fr::copy(1) }
            { Fr::fromaltstack() }
            { Fr::sub(0, 1) }

            // LiS2_2 = den1 * den2 * den3, keep den1 in the altstack
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::fromaltstack() }
            { Fr::copy(0) }
            { Fr::roll(2) }
            { Fr::mul() }
            { Fr::toaltstack() }
            { Fr::toaltstack() }
            // [xi - xiw, y, H2w3_0, H2w3_1, H2w3_2 |
            // Z_H, prod_1, prod_2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8, LiS1_1, LiS1_2, LiS1_3, LiS1_4, LiS2_1, LiS2_2, den1]

            // den2 = roots[2 * 2 % 3] = roots[1]
            { Fr::copy(1) }
            { Fr::toaltstack() }

            // den3 = x - roots[2]
            { Fr::copy(3) }
            { Fr::toaltstack() }
            { Fr::copy(0) }
            { Fr::fromaltstack() }
            { Fr::sub(0, 1) }

            // LiS2_3 = den1 * den2 * den3, keep den1 in the altstack
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::toaltstack() }
            // [xi - xiw, y, H2w3_0, H2w3_1, H2w3_2 |
            // Z_H, prod_1, prod_2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8, LiS1_1, LiS1_2, LiS1_3, LiS1_4, LiS2_1, LiS2_2, LiS2_3]

            // drop H2w3_0, H2w3_1, H2w3_2
            { Fr::drop() }
            { Fr::drop() }
            { Fr::drop() }
            // [xi - xiw, y |
            // Z_H, prod_1, prod_2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8, LiS1_1, LiS1_2, LiS1_3, LiS1_4, LiS2_1, LiS2_2, LiS2_3]

            // push H3w3_0, H3w3_1, H3w3_2
            { Fr::copy(6) }
            { Fr::copy(6) }
            { Fr::copy(6) }
            // [xi - xiw, y, H3w3_0, H3w3_1, H3w3_2 |
            // Z_H, prod_1, prod_2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8, LiS1_1, LiS1_2, LiS1_3, LiS1_4, LiS2_1, LiS2_2, LiS2_3]

            // obtain xiw - xi
            { Fr::neg(4) }
            { Fr::toaltstack() }
            // [y, H3w3_0, H3w3_1, H3w3_2 |
            // Z_H, prod_1, prod_2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8, LiS1_1, LiS1_2, LiS1_3, LiS1_4, LiS2_1, LiS2_2, LiS2_3, xiw - xi]

            // _3h2 = Fr.mul(Fr.e(len), Fr.exp(roots[0], len - 2)) = = 3 * H3w3_0
            { Fr::copy(2) }
            { Fr::copy(0) }
            { Fr::double(0) }
            { Fr::add(1, 0) }

            // compute den1 = _3h2 * (xiw - xi)
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::toaltstack() }
            // [y, H3w3_0, H3w3_1, H3w3_2 |
            // Z_H, prod_1, prod_2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8, LiS1_1, LiS1_2, LiS1_3, LiS1_4, LiS2_1, LiS2_2, LiS2_3, den1]

            // den2 = roots[2 * 0 % 3] = roots[0]
            { Fr::copy(2) }
            { Fr::toaltstack() }
            // [y, H3w3_0, H3w3_1, H3w3_2 |
            // Z_H, prod_1, prod_2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8, LiS1_1, LiS1_2, LiS1_3, LiS1_4, LiS2_1, LiS2_2, LiS2_3, den1, den2]

            // den3 = x - roots[0]
            { Fr::copy(3) }
            { Fr::toaltstack() }
            { Fr::copy(2) }
            { Fr::fromaltstack() }
            { Fr::sub(0, 1) }
            // [y, H3w3_0, H3w3_1, H3w3_2, den3 |
            // Z_H, prod_1, prod_2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8, LiS1_1, LiS1_2, LiS1_3, LiS1_4, LiS2_1, LiS2_2, LiS2_3, den1, den2]

            // LiS3_1 = den1 * den2 * den3, keep den1 in the altstack
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::fromaltstack() }
            { Fr::copy(0) }
            { Fr::roll(2) }
            { Fr::mul() }
            { Fr::toaltstack() }
            { Fr::toaltstack() }
            // [y, H3w3_0, H3w3_1, H3w3_2 |
            // Z_H, prod_1, prod_2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8, LiS1_1, LiS1_2, LiS1_3, LiS1_4, LiS2_1, LiS2_2, LiS2_3, LiS3_1, den1]

            // den2 = roots[2 * 1 % 3] = roots[2]
            { Fr::copy(0) }
            { Fr::toaltstack() }

            // den3 = x - roots[1]
            { Fr::copy(3) }
            { Fr::toaltstack() }
            { Fr::copy(1) }
            { Fr::fromaltstack() }
            { Fr::sub(0, 1) }

            // LiS3_2 = den1 * den2 * den3, keep den1 in the altstack
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::fromaltstack() }
            { Fr::copy(0) }
            { Fr::roll(2) }
            { Fr::mul() }
            { Fr::toaltstack() }
            { Fr::toaltstack() }
            // [y, H3w3_0, H3w3_1, H3w3_2 |
            // Z_H, prod_1, prod_2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8, LiS1_1, LiS1_2, LiS1_3, LiS1_4, LiS2_1, LiS2_2, LiS2_3, LiS3_1, LiS3_2, den1]

            // den2 = roots[2 * 2 % 3] = roots[1]
            { Fr::copy(1) }
            { Fr::toaltstack() }

            // den3 = x - roots[2]
            { Fr::copy(3) }
            { Fr::toaltstack() }
            { Fr::copy(0) }
            { Fr::fromaltstack() }
            { Fr::sub(0, 1) }

            // LiS3_3 = den1 * den2 * den3, keep den1 in the altstack
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::toaltstack() }
            // [y, H3w3_0, H3w3_1, H3w3_2 |
            // Z_H, prod_1, prod_2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8, LiS1_1, LiS1_2, LiS1_3, LiS1_4, LiS2_1, LiS2_2, LiS2_3, LiS3_1, LiS3_2, LiS3_3]

            // drop H3w3_0, H3w3_1, H3w3_2
            { Fr::drop() }
            { Fr::drop() }
            { Fr::drop() }

            // drop y
            { Fr::drop() }
            // [ xi, zh | Z_H, prod_1, prod_2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8, LiS1_1, LiS1_2, LiS1_3, LiS1_4, LiS2_1, LiS2_2, LiS2_3, LiS3_1, LiS3_2, LiS3_3]

            // push xi again
            // { Fr::push_dec("14814634099415170872937750660683266261347419959225231219985478027287965492246") }
            { Fr::copy(1) }
            // [ xi | Z_H, prod_1, prod_2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8, LiS1_1, LiS1_2, LiS1_3, LiS1_4, LiS2_1, LiS2_2, LiS2_3, LiS3_1, LiS3_2, LiS3_3]

            // Li_1 = 262144 * (xi - 1)
            { Fr::copy(0) }
            { Fr::push_one() }
            { Fr::sub(1, 0) }
            { Fr::push_dec("262144") }
            { Fr::mul() }
            { Fr::toaltstack() }
            // [ xi | Z_H, prod_1, prod_2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8, LiS1_1, LiS1_2, LiS1_3, LiS1_4, LiS2_1, LiS2_2, LiS2_3, LiS3_1, LiS3_2, LiS3_3, Li_1]

            // Li_2 = 262144 * (xi - w1)
            { Fr::copy(0) }
            { Fr::push_dec(w) }
            { Fr::sub(1, 0) }
            { Fr::push_dec("262144") }
            { Fr::mul() }
            { Fr::toaltstack() }
            // [ xi | Z_H, prod_1, prod_2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8, LiS1_1, LiS1_2, LiS1_3, LiS1_4, LiS2_1, LiS2_2, LiS2_3, LiS3_1, LiS3_2, LiS3_3, Li_1, Li_2]


            // Get all the elements back to the stack
            for _ in 0..23 {
                { Fr::fromaltstack() }
            }
            // [ xi , Z_H, prod_1, prod_2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8, LiS1_1, LiS1_2, LiS1_3, LiS1_4, LiS2_1, LiS2_2, LiS2_3, LiS3_1, LiS3_2, LiS3_3, Li_1, Li_2]

            // build up the accumulator
            { Fr::copy(0) }
            for i in 1..23 {
                { Fr::copy(0) }
                // [ xi, Z_H, prod_1, prod_2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8,
                // LiS1_1, LiS1_2, LiS1_3, LiS1_4, LiS2_1, LiS2_2, LiS2_3, LiS3_1, LiS3_2, LiS3_3, Li_1, Li_2, Li_2, Li_2]
                { Fr::copy(i + 1 + i) }
                { Fr::mul() }
                // [ xi, Z_H, prod_1, prod_2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8,
                // LiS1_1, LiS1_2, LiS1_3, LiS1_4, LiS2_1, LiS2_2, LiS2_3, LiS3_1, LiS3_2, LiS3_3, Li_1, Li_2, Li_2, Li_2 * Li_1]
            }

            // push the inv from the proof and verify the inv
            { Fr::copy(0) }
            { Fr::push_dec(inv) }
            { Fr::copy(0) } { Fr::toaltstack() }
            { Fr::mul() }
            { Fr::is_one_keep_element(0) }
            OP_VERIFY
            { Fr::drop() } // is_one does not consume the input

            // current stack:
            //   inputs (Li_2 down to ZH)
            //   accumulators (ZH down to prod of all)
            // altstack:
            //   inv

            // compute the inverses now
            { Fr::drop() }
            { Fr::fromaltstack() }
            // [ Z_H, prod_1, prod_2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8,
            // LiS1_1, LiS1_2, LiS1_3, LiS1_4, LiS2_1, LiS2_2, LiS2_3, LiS3_1, LiS3_2, LiS3_3, Li_1, Li_2, Li_2, Li_2 * Li_1, Li_2 * Li_1 * LiS3_3, ...
            // inv ]

            for i in 0..22 {
                { Fr::copy(0) }
                { Fr::roll(2) }
                { Fr::mul() }
                { Fr::toaltstack() }
                { Fr::roll(23 - 1 - i + 23 - 1 - i) }
                { Fr::mul() }
            }
            { Fr::roll(1) }
            { Fr::drop() }
            { Fr::roll(1) }
            { Fr::drop() }
            // [ZH | ..., LiS0_3, LiS0_2, LiS0_1, DenH2, DenH1]

            for _ in 0..22 {
                { Fr::fromaltstack() }
            }
            // [..., xi, ZH, DenH1, DenH2, LiS0_1, LiS0_2, LiS0_3, ...]
        }
    }

    /// compute lagranges
    // [beta, gamma, alpha, y, pH0w8_0, pH0w8_1, pH0w8_2, pH0w8_3, pH0w8_4, pH0w8_5, pH0w8_6, pH0w8_7,
    // pH1w4_0, pH1w4_1, pH1w4_2, pH1w4_3, pH2w3_0, pH2w3_1, pH2w3_2, pH3w3_0, pH3w3_1, pH2w3_2, xi, zh,
    // ZH, DenH1, DenH2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8,
    // LiS1_1, LiS1_2, LiS1_3, LiS1_4, LiS2_1, LiS2_2, LiS2_3, LiS3_1, LiS3_2, LiS3_3, Li_1, Li_2]
    fn compute_lagranges(w1: &str) -> Script {
        script! {
            // push zh
            { Fr::copy(23) }
            { Fr::copy(0) }
            { Fr::toaltstack() }

            // push the inverse of Li_1
            { Fr::copy(2) }
            { Fr::mul() }

            // push the inverse of Li_2
            { Fr::copy(1)}
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::push_dec(w1) }
            { Fr::mul() }
        }
    }

    /// compute pi {48 elements}
    // [beta, gamma, alpha, y, pH0w8_0, pH0w8_1, pH0w8_2, pH0w8_3, pH0w8_4, pH0w8_5, pH0w8_6, pH0w8_7,
    // pH1w4_0, pH1w4_1, pH1w4_2, pH1w4_3, pH2w3_0, pH2w3_1, pH2w3_2, pH3w3_0, pH3w3_1, pH2w3_2, xi,
    // ZH, DenH1, DenH2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8,
    // LiS1_1, LiS1_2, LiS1_3, LiS1_4, LiS2_1, LiS2_2, LiS2_3, LiS3_1, LiS3_2, LiS3_3, Li_1, Li_2, L1, L2]
    fn compute_pi(input1: &str, input2: &str) -> Script {
        script! {

            { Fr::copy(1)}
            { Fr::copy(1)}
            { Fr::push_dec(input1) }
            { Fr::push_dec(input2) }
            { Fr::roll(2) }
            { Fr::mul() }
            { Fr::toaltstack() }

            { Fr::mul() }
            { Fr::fromaltstack() }
            { Fr::add(1, 0) }
            { Fr::neg(0) }
        }
    }

    /// compute R0 {50 elements} ql, qr, qo, qm, qc, s1, s2, s3
    // [beta, gamma, alpha, y, pH0w8_0, pH0w8_1, pH0w8_2, pH0w8_3, pH0w8_4, pH0w8_5, pH0w8_6, pH0w8_7,
    // pH1w4_0(37), pH1w4_1, pH1w4_2, pH1w4_3, pH2w3_0, pH2w3_1, pH2w3_2, pH3w3_0, pH3w3_1, pH2w3_2, xi, zh,
    // ZH(25), DenH1, DenH2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8,
    // LiS1_1, LiS1_2, LiS1_3, LiS1_4, LiS2_1, LiS2_2, LiS2_3, LiS3_1, LiS3_2, LiS3_3, Li_1, Li_2, L1, L2, PI]
    fn compute_r0(
        ql: &str,
        qr: &str,
        qo: &str,
        qm: &str,
        qc: &str,
        s1: &str,
        s2: &str,
        s3: &str,
    ) -> Script {
        script! {
            // push ql, qr, qo, qm, qc, s1, s2, s3
            { Fr::push_dec(ql) }
            { Fr::push_dec(qr) }
            { Fr::push_dec(qo) }
            { Fr::push_dec(qm) }
            { Fr::push_dec(qc) }
            { Fr::push_dec(s1) }
            { Fr::push_dec(s2) }
            { Fr::push_dec(s3) }

            // push H0w8_0, H0w8_1, H0w8_2, H0w8_3, H0w8_4, H0w8_5, H0w8_6, H0w8_7
            { Fr::copy(53) }
            { Fr::copy(53) }
            { Fr::copy(53) }
            { Fr::copy(53) }
            { Fr::copy(53) }
            { Fr::copy(53) }
            { Fr::copy(53) }
            { Fr::copy(53) }

            // push lis0_1_inv, ...
            { Fr::copy(38) }
            { Fr::copy(38) }
            { Fr::copy(38) }
            { Fr::copy(38) }
            { Fr::copy(38) }
            { Fr::copy(38) }
            { Fr::copy(38) }
            { Fr::copy(38) }

            // push y, xi
            { Fr::copy(70) }
            { Fr::copy(52) }

            // compute num = y^8 - xi, push to altstack
            { Fr::roll(1) }
            { Fr::square() }
            { Fr::square() }
            { Fr::square() }
            { Fr::sub(0, 1) }
            { Fr::toaltstack() }
            // [ql, qr, ...., H0w8_0, H0w8_1, ..., lis0_1_inv, lis0_2_inv, ... | num]

            // pick H0w8_0, ..., H0w8_7 and compute the corresponding c0Value
            for i in 0..8 {
                { Fr::copy(8 + 7 - i) }

                { Fr::copy(0) } { Fr::copy(1) } { Fr::mul() }
                { Fr::copy(0) } { Fr::copy(2) } { Fr::mul() }
                { Fr::copy(0) } { Fr::copy(3) } { Fr::mul() }
                { Fr::copy(0) } { Fr::copy(4) } { Fr::mul() }
                { Fr::copy(0) } { Fr::copy(5) } { Fr::mul() }
                { Fr::copy(0) } { Fr::copy(6) } { Fr::mul() }
                // H0w8_0, H0w8_0^2, H0w8_0^3, ...

                for _ in 0..7 {
                    { Fr::toaltstack() }
                }

                // c0Value starts with ql
                { Fr::copy(16 + 7) }
                { Fr::copy(16 + 6 + 1) } { Fr::fromaltstack() } { Fr::mul() } { Fr::add(1, 0) }
                { Fr::copy(16 + 5 + 1) } { Fr::fromaltstack() } { Fr::mul() } { Fr::add(1, 0) }
                { Fr::copy(16 + 4 + 1) } { Fr::fromaltstack() } { Fr::mul() } { Fr::add(1, 0) }
                { Fr::copy(16 + 3 + 1) } { Fr::fromaltstack() } { Fr::mul() } { Fr::add(1, 0) }
                { Fr::copy(16 + 2 + 1) } { Fr::fromaltstack() } { Fr::mul() } { Fr::add(1, 0) }
                { Fr::copy(16 + 1 + 1) } { Fr::fromaltstack() } { Fr::mul() } { Fr::add(1, 0) }
                { Fr::copy(16 + 1) } { Fr::fromaltstack() } { Fr::mul() } { Fr::add(1, 0) }

                // push this c0Value to the altstack
                { Fr::toaltstack() }
            }

            // get all the c0Values out
            for _ in 0..8 {
                { Fr::fromaltstack() }
            }

            // multiply the corresponding LiS0Inv
            for i in 0..8 {
                { Fr::roll(8 - i + 7 - i) }
                { Fr::mul() }
                { Fr::toaltstack() }
            }

            // drop all the intermediate values
            for _ in 0..16 {
                { Fr::drop() }
            }

            // add all the c0Values together
            { Fr::fromaltstack() }
            for _ in 1..8 {
                { Fr::fromaltstack() }
                { Fr::add(1, 0) }
            }

            // multiply by the num
            { Fr::fromaltstack() }
            { Fr::mul() }
        }
    }

    /// compute R1 {51 elements} ql, qr, qo, qm, qc, a, b, c
    // [beta, gamma, alpha, y, pH0w8_0, pH0w8_1, pH0w8_2, pH0w8_3, pH0w8_4, pH0w8_5, pH0w8_6, pH0w8_7,
    // pH1w4_0(38), pH1w4_1, pH1w4_2, pH1w4_3, pH2w3_0, pH2w3_1, pH2w3_2, pH3w3_0, pH3w3_1, pH2w3_2, xi, zh,
    // ZH(26), DenH1, DenH2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8,
    // LiS1_1(15), LiS1_2, LiS1_3, LiS1_4, LiS2_1, LiS2_2, LiS2_3, LiS3_1, LiS3_2, LiS3_3, Li_1, Li_2, L1, L2, PI, r0]
    fn compute_r1(
        ql: &str,
        qr: &str,
        qm: &str,
        qo: &str,
        qc: &str,
        a: &str,
        b: &str,
        c: &str,
    ) -> Script {
        script! {

            { Fr::push_dec(ql) }
            { Fr::push_dec(qr) }
            { Fr::push_dec(qm) }
            { Fr::push_dec(qo) }
            { Fr::push_dec(qc) }
            { Fr::push_dec(a) }
            { Fr::push_dec(b) }
            { Fr::push_dec(c) }
            // pi, zh
            { Fr::copy(9)}
            { Fr::copy(35)}
            // pH1w4_0->3
            { Fr::copy(48)}
            { Fr::copy(48)}
            { Fr::copy(48)}
            { Fr::copy(48)}
            // LiS1_1 -> 4
            { Fr::copy(29)}
            { Fr::copy(29)}
            { Fr::copy(29)}
            { Fr::copy(29)}
            // y, xi
            { Fr::copy(65)}
            { Fr::copy(47)}
            // compute num = y^4 - xi, push to altstack
            { Fr::roll(1) }
            { Fr::square() }
            { Fr::square() }
            { Fr::sub(0, 1) }
            { Fr::toaltstack() }

            // compute t0

            // ql * evalA
            { Fr::copy(10 + 7) }
            { Fr::copy(10 + 2 + 1) }
            { Fr::mul() }
            { Fr::toaltstack() }

            // qr * evalB
            { Fr::copy(10 + 6) }
            { Fr::copy(10 + 1 + 1) }
            { Fr::mul() }
            { Fr::toaltstack() }

            // qm * evalA * evalB
            { Fr::copy(10 + 5) }
            { Fr::copy(10 + 2 + 1) }
            { Fr::mul() }
            { Fr::copy(10 + 1 + 1) }
            { Fr::mul() }
            { Fr::toaltstack() }

            // qo * evalC
            { Fr::copy(10 + 4) }
            { Fr::copy(10 + 1) }
            { Fr::mul() }

            // t0 := ql * evalA + qr * evalB + qm * evalA * evalB + qo * evalC + qc + pi
            { Fr::fromaltstack() }
            { Fr::add(1, 0) }
            { Fr::fromaltstack() }
            { Fr::add(1, 0) }
            { Fr::fromaltstack() }
            { Fr::add(1, 0) }
            { Fr::copy(10 + 3 + 1) }
            { Fr::add(1, 0) }
            { Fr::copy(8 + 1 + 1) }
            { Fr::add(1, 0) }

            // t0 := t0 * zhInv
            { Fr::copy(8 + 1) }
            { Fr::mul() }

            // the stack should look like:
            //    ql, qr, qm, qo, qc, a, b, c
            //    pi, zhInv
            //    H1w4_0, H1w4_1, H1w4_2, H1w4_3
            //    LiS1Inv 1-4
            //    t0
            //
            // altstack: num

            // pick H1w4_0, ..., H1w4_3 and compute the corresponding c1Value
            for i in 0..4 {
                { Fr::copy(1 + 4 + 3 - i) }

                { Fr::copy(0) } { Fr::copy(1) } { Fr::mul() }
                { Fr::copy(0) } { Fr::copy(2) } { Fr::mul() }

                for _ in 0..3 {
                    { Fr::toaltstack() }
                }

                // c1Value starts with a
                { Fr::copy(1 + 4 + 4 + 2 + 2) }
                { Fr::copy(1 + 4 + 4 + 2 + 1 + 1) } { Fr::fromaltstack() } { Fr::mul() } { Fr::add(1, 0) }
                { Fr::copy(1 + 4 + 4 + 2 + 1) } { Fr::fromaltstack() } { Fr::mul() } { Fr::add(1, 0) }
                { Fr::copy(1) } { Fr::fromaltstack() } { Fr::mul() } { Fr::add(1, 0) }

                // push this c1Value to the altstack
                { Fr::toaltstack() }
            }

            // get all the c1Values out
            for _ in 0..4 {
                { Fr::fromaltstack() }
            }

            // multiply the corresponding LiS1Inv
            for i in 0..4 {
                { Fr::roll(4 - i + 1 + 3 - i) }
                { Fr::mul() }
                { Fr::toaltstack() }
            }

            // drop all the intermediate values
            for _ in 0..(1 + 4 + 2 + 8) {
                { Fr::drop() }
            }

            // add all the c0Values together
            { Fr::fromaltstack() }
            for _ in 1..4 {
                { Fr::fromaltstack() }
                { Fr::add(1, 0) }
            }

            // multiply by the num
            { Fr::fromaltstack() }
            { Fr::mul() }
        }
    }

    /// compute R2 {52 elements} a, b, c, z, zw, s1, s2, s3, t1w, t2w
    // [beta(51), gamma, alpha, y, pH0w8_0, pH0w8_1, pH0w8_2, pH0w8_3, pH0w8_4, pH0w8_5, pH0w8_6, pH0w8_7,
    // pH1w4_0(39), pH1w4_1, pH1w4_2, pH1w4_3, pH2w3_0, pH2w3_1, pH2w3_2, pH3w3_0, pH3w3_1, pH2w3_2, xi, zh,
    // ZH(27), DenH1, DenH2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8,
    // LiS1_1(16), LiS1_2, LiS1_3, LiS1_4, LiS2_1, LiS2_2, LiS2_3, LiS3_1, LiS3_2, LiS3_3, Li_1, Li_2, L1, L2, PI, r0, r1]
    fn compute_r2(
        a: &str,
        b: &str,
        c: &str,
        z: &str,
        zw: &str,
        s1: &str,
        s2: &str,
        s3: &str,
        t1w: &str,
        t2w: &str,
        w1: &str,
    ) -> Script {
        script! {

            { Fr::push_dec(a) }
            { Fr::push_dec(b) }
            { Fr::push_dec(c) }
            { Fr::push_dec(z) }
            { Fr::push_dec(zw) }
            { Fr::push_dec(s1) }
            { Fr::push_dec(s2) }
            { Fr::push_dec(s3) }
            { Fr::push_dec(t1w) }
            { Fr::push_dec(t2w) }
            // beta, y, xi, gamma, zhinv, L[1]
            { Fr::copy(61)}
            { Fr::copy(59)}
            { Fr::copy(41)}
            { Fr::copy(63)}
            { Fr::copy(41)}
            { Fr::copy(19)}
            // todo push from stack
            //{ Fr::push_dec("19264250262515049392118907974032894668050943806280011767302681470321758079402") }
            //  H2w3_0, H2w3_1, H2w3_2, H3w3_0, H3w3_1, H3w3_2 (6 elements)
            { Fr::copy(51)}
            { Fr::copy(51)}
            { Fr::copy(51)}
            { Fr::copy(51)}
            { Fr::copy(51)}
            { Fr::copy(51)}
            // LiS2Inv 1-6 (6 elements)
            { Fr::copy(34)}
            { Fr::copy(34)}
            { Fr::copy(34)}
            { Fr::copy(34)}
            { Fr::copy(34)}
            { Fr::copy(34)}

            // compute num2 := y^3
            { Fr::copy(6 + 6 + 4) }
            { Fr::copy(0) }
            { Fr::square() }
            { Fr::mul() }

            // compute num := num2^2 = y^6
            { Fr::copy(0) }
            { Fr::square() }

            // compute xi * w1 + xi = xi * (w1 + 1)
            { Fr::copy(6 + 6 + 3 + 2) }
            // { Fr::push_dec("11699596668367776675346610687704220591435078791727316319397053191800576917728") }
            { Fr::push_dec(w1) }
            { Fr::push_one() }
            { Fr::add(1, 0) }
            { Fr::mul() }

            // compute num2 := num2 * (xi * (w1 + 1))
            { Fr::roll(2) }
            { Fr::mul() }

            // compute num := num - num2
            { Fr::sub(1, 0) }

            // compute xi^2 * w1
            { Fr::copy(6 + 6 + 3 + 1) }
            { Fr::square() }
            // { Fr::push_dec("11699596668367776675346610687704220591435078791727316319397053191800576917728") }
            { Fr::push_dec(w1) }
            { Fr::mul() }

            // compute num := num +  xi^2 * w1 and move to altstack
            { Fr::add(1, 0) }
            { Fr::toaltstack() }

            // compute betaxi
            { Fr::copy(6 + 6 + 5) }
            { Fr::copy(6 + 6 + 3 + 1) }
            { Fr::mul() }

            // compute betaxi + gamma
            { Fr::copy(0) }
            { Fr::copy(6 + 6 + 2 + 2) }
            { Fr::add(1, 0) }

            // compute a + betaxi + gamma and send to altstack
            { Fr::copy(6 + 6 + 6 + 9 + 2) }
            { Fr::add(1, 0) }
            { Fr::toaltstack() }

            // compute betaxi * k1 + gamma for k1 = 2
            { Fr::copy(0) }
            { Fr::double(0) }
            { Fr::copy(6 + 6 + 2 + 2) }
            { Fr::add(1, 0) }

            // compute b + betaxi * k1 + gamma and send to altstack
            { Fr::copy(6 + 6 + 6 + 8 + 2) }
            { Fr::add(1, 0) }
            { Fr::toaltstack() }

            // compute betaxi * k2 + gamma for k2 = 3
            { Fr::copy(0) }
            { Fr::double(0) }
            { Fr::add(1, 0) }
            { Fr::copy(6 + 6 + 2 + 1) }
            { Fr::add(1, 0) }

            // compute c + betaxi * k2 + gamma and send to altstack
            { Fr::copy(6 + 6 + 6 + 7 + 1) }
            { Fr::add(1, 0) }

            // compute t2 = (a + betaxi + gamma) * (b + betaxi * k1 + gamma) * (c + betaxi * k2 + gamma) * z
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::copy(6 + 6 + 6 + 6 + 1) }
            { Fr::mul() }

            // send t2 to the altstack
            { Fr::toaltstack() }

            // compute beta * s1 + gamma + a
            { Fr::copy(6 + 6 + 5) }
            { Fr::copy(6 + 6 + 6 + 4 + 1) }
            { Fr::mul() }
            { Fr::copy(6 + 6 + 2 + 1) }
            { Fr::add(1, 0) }
            { Fr::copy(6 + 6 + 6 + 9 + 1) }
            { Fr::add(1, 0) }
            { Fr::toaltstack() }

            // compute beta * s2 + gamma + b
            { Fr::copy(6 + 6 + 5) }
            { Fr::copy(6 + 6 + 6 + 3 + 1) }
            { Fr::mul() }
            { Fr::copy(6 + 6 + 2 + 1) }
            { Fr::add(1, 0) }
            { Fr::copy(6 + 6 + 6 + 8 + 1) }
            { Fr::add(1, 0) }
            { Fr::toaltstack() }

            // compute beta * s3 + gamma + c
            { Fr::copy(6 + 6 + 5) }
            { Fr::copy(6 + 6 + 6 + 2 + 1) }
            { Fr::mul() }
            { Fr::copy(6 + 6 + 2 + 1) }
            { Fr::add(1, 0) }
            { Fr::copy(6 + 6 + 6 + 7 + 1) }
            { Fr::add(1, 0) }

            // compute t2' = (beta * s1 + gamma + a) * (beta * s2 + gamma + b) * (beta * s3 + gamma + c) * zw
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::copy(6 + 6 + 6 + 5 + 1) }
            { Fr::mul() }

            // compute t2 := t2 - t2'
            { Fr::fromaltstack() }
            { Fr::sub(0, 1) }

            // compute t2 := t2 * zhinv
            { Fr::copy(6 + 6 + 1 + 1) }
            { Fr::mul() }

            // send the updated t2 to the altstack
            { Fr::toaltstack() }

            // compute t1 = (z - 1) * L[1] * zhinv
            { Fr::copy(6 + 6 + 6 + 6) }
            { Fr::push_one() }
            { Fr::sub(1, 0) }
            { Fr::copy(6 + 6 + 1) }
            { Fr::mul() }
            { Fr::copy(6 + 6 + 1 + 1) }
            { Fr::mul() }

            // pull t2 from the altstack
            { Fr::fromaltstack() }

            // the stack now looks:
            //   10 + 6 + 6 + 6 Fr elements
            //   t1
            //   t2
            // altstack: num

            // pick H2w3_0, ..., H2w3_2 and compute the corresponding c2Value
            for i in 0..3 {
                { Fr::copy(2 + 6 + 5 - i) }

                { Fr::copy(0) } { Fr::square() }
                { Fr::toaltstack() } { Fr::toaltstack() }

                // c2Value starts with z
                { Fr::copy(2 + 6 + 6 + 6 + 6) }
                { Fr::copy(1 + 1) } { Fr::fromaltstack() } { Fr::mul() } { Fr::add(1, 0) }
                { Fr::copy(1) } { Fr::fromaltstack() } { Fr::mul() } { Fr::add(1, 0) }

                // push this c2Value to the altstack
                { Fr::toaltstack() }
            }

            // pick H3w3_0, ..., H3w3_2 and compute the corresponding c2Value
            for i in 0..3 {
                { Fr::copy(2 + 6 + 2 - i) }

                { Fr::copy(0) } { Fr::square() }
                { Fr::toaltstack() } { Fr::toaltstack() }

                // c2Value starts with zw
                { Fr::copy(2 + 6 + 6 + 6 + 5) }
                { Fr::copy(2 + 6 + 6 + 6 + 1 + 1) } { Fr::fromaltstack() } { Fr::mul() } { Fr::add(1, 0) }
                { Fr::copy(2 + 6 + 6 + 6 + 1) } { Fr::fromaltstack() } { Fr::mul() } { Fr::add(1, 0) }

                // push this c2Value to the altstack
                { Fr::toaltstack() }
            }

            // get all the c1Values out
            for _ in 0..6 {
                { Fr::fromaltstack() }
            }

            // multiply the corresponding LiS1Inv
            for i in 0..6 {
                { Fr::roll(6 - i + 2 + 5 - i) }
                { Fr::mul() }
                { Fr::toaltstack() }
            }

            // drop all the intermediate values
            for _ in 0..(2 + 6 + 6 + 10) {
                { Fr::drop() }
            }

            // add all the c0Values together
            { Fr::fromaltstack() }
            for _ in 1..6 {
                { Fr::fromaltstack() }
                { Fr::add(1, 0) }
            }

            // multiply by the num
            { Fr::fromaltstack() }
            { Fr::mul() }
        }
    }

    /// compute fej {53 elements}
    // [beta(52), gamma, alpha, y, pH0w8_0, pH0w8_1, pH0w8_2, pH0w8_3, pH0w8_4, pH0w8_5, pH0w8_6, pH0w8_7,
    // pH1w4_0(40), pH1w4_1, pH1w4_2, pH1w4_3, pH2w3_0, pH2w3_1, pH2w3_2, pH3w3_0, pH3w3_1, pH2w3_2, xi, zh,
    // ZH(28), DenH1, DenH2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8,
    // LiS1_1(17), LiS1_2, LiS1_3, LiS1_4, LiS2_1, LiS2_2, LiS2_3, LiS3_1, LiS3_2, LiS3_3, Li_1, Li_2, L1, L2, PI, r0, r1, r2]
    fn compute_fej() -> Script {
        script! {

            // push alpha, denh1, denh2, y (4 elements)
            { Fr::copy(50)}
            { Fr::copy(28)}
            { Fr::copy(28)}
            { Fr::copy(52)}

            // push R0, R1, R2 (3 elements)
            { Fr::copy(6)}
            { Fr::copy(6)}
            { Fr::copy(6)}

            // push H0w8_0, H0w8_1, H0w8_2, H0w8_3, H0w8_4, H0w8_5, H0w8_6, H0w8_7 (8 elements)
            { Fr::copy(55)}
            { Fr::copy(55)}
            { Fr::copy(55)}
            { Fr::copy(55)}
            { Fr::copy(55)}
            { Fr::copy(55)}
            { Fr::copy(55)}
            { Fr::copy(55)}

            // roll y
            { Fr::roll(8 + 3) }

            // compute numerator entries
            for i in 0..8 {
                { Fr::copy(0) }
                { Fr::roll(7 - i + 2) }
                { Fr::sub(1, 0) }
                { Fr::toaltstack() }
            }

            // drop y
            { Fr::drop() }

            // compute numerator
            { Fr::fromaltstack() }
            for _ in 0..7 {
                { Fr::fromaltstack() }
                { Fr::mul() }
            }

            // copy the numerator in the altstack
            { Fr::copy(0) }
            { Fr::toaltstack() }

            // compute quotient1 = alpha * numerator * denh1
            { Fr::copy(0) }
            { Fr::copy(3 + 2 + 2) }
            { Fr::mul() }
            { Fr::roll(3 + 1 + 2) }
            { Fr::mul() }

            // compute quotient2 = alpha * alpha * numerator * denh2
            { Fr::roll(1) }
            { Fr::roll(3 + 2) }
            { Fr::mul() }
            { Fr::roll(3 + 2) }
            { Fr::square() }
            { Fr::mul() }

            // the stack now looks:
            //    R0, R1, R2
            //    quotient1, quotient2
            // altstack: numerator

            // compute the scalar = R0 + quotient1 * R1 + quotient2 * R2
            { Fr::copy(1) }
            { Fr::roll(2 + 1 + 1) }
            { Fr::mul() }
            { Fr::copy(1) }
            { Fr::roll(2 + 2) }
            { Fr::mul() }
            { Fr::add(1, 0) }
            { Fr::roll(2 + 1) }
            { Fr::add(1, 0) }

            { Fr::fromaltstack() }

            // Drop useless elements, only reserve y
            // ... ] } [scalar_j, scalar_e, scalar_f2, scalar_f1]
            { Fr::toaltstack() }
            { Fr::toaltstack() }
            { Fr::toaltstack() }
            { Fr::toaltstack() }
            // ... y ] } [scalar_j, scalar_e, scalar_f2, scalar_f1]
            { Fr::copy(49) }

            // ... ] } [scalar_j, scalar_e, scalar_f2, scalar_f1, y]
            { Fr::toaltstack() }

            for _ in 0..53 {

                {Fr::drop()}
            }

            // [ y, scalar_f1, scalar_f2, scalar_e, scalar_j ] }
            { Fr::fromaltstack() }
            { Fr::fromaltstack() }
            { Fr::fromaltstack() }
            { Fr::fromaltstack() }
            { Fr::fromaltstack() }
        }
    }

    /// compute f (5)
    //[ y scalar_f1, scalar_f2, scalar_e, scalar_j]
    fn compute_f(
        c0x: &str,
        c0y: &str,
        c0z: &str,
        c1x: &str,
        c1y: &str,
        c1z: &str,
        c2x: &str,
        c2y: &str,
        c2z: &str,
    ) -> Script {
        script! {

            // push quotient1, quotient2 (2 elements)
            { Fr::copy(3)}
            { Fr::copy(3)}

            { Fr::toaltstack() }
            { Fr::toaltstack() }

            // push (C0x, C0y), C1, C2 (9 elements)
            { Fq::push_dec(c0x)}
            { Fq::push_dec(c0y)}
            { Fq::push_dec(c0z)}
            { Fq::push_dec(c1x)}
            { Fq::push_dec(c1y)}
            { Fq::push_dec(c1z)}
            { Fq::push_dec(c2x)}
            { Fq::push_dec(c2y)}
            { Fq::push_dec(c2z)}

            { G1Projective::roll(1) }
            { Fr::fromaltstack() }
            { G1Projective::scalar_mul() }

            { G1Projective::roll(1) }
            { Fr::fromaltstack() }
            { G1Projective::scalar_mul() }

            { G1Projective::add() }
            { G1Projective::add() }

        }
    }

    /// compute f (5)
    //[ y scalar_f1, scalar_f2, scalar_e, scalar_j]
    fn compute_f_opt(
        c0x: &str,
        c0y: &str,
        c0z: &str,
        c1x: &str,
        c1y: &str,
        c1z: &str,
        c2x: &str,
        c2y: &str,
        c2z: &str,
    ) -> Script {
        script! {

            // push quotient1, quotient2 (2 elements)
            { Fr::copy(3)}
            { Fr::copy(3)}

            { Fr::toaltstack() }
            { Fr::toaltstack() }

            // push (C0x, C0y), C1, C2 (9 elements)
            { Fq::push_dec(c0x)}
            { Fq::push_dec(c0y)}
            { Fq::push_dec(c0z)}
            { Fq::push_dec(c1x)}
            { Fq::push_dec(c1y)}
            { Fq::push_dec(c1z)}
            { Fq::push_dec(c2x)}
            { Fq::push_dec(c2y)}
            { Fq::push_dec(c2z)}

            { G1Projective::roll(1) } // [c0, c2, c1, q1; q2]
            { Fr::fromaltstack() }
            { Fq::roll(6)} {Fq::roll(6)} {Fq::roll(6)} // [c0, c1, q1, c2]
            { Fr::fromaltstack() } // [c0, c1, q1, c2, q2]
            { G1Projective::batched_scalar_mul::<2>() }
            { G1Projective::add() }

        }
    }

    /// compute e (6)
    // [y, scalar_f1, scalar_f2, scalar_e, scalar_j, f.x, f.y, f.z]
    fn compute_e(g1x: &str, g1y: &str, g1z: &str) -> Script {
        script! {

            { Fq::toaltstack() }
            { Fq::toaltstack() }
            { Fq::toaltstack() }

            // push the scalar
            { Fr::copy(1)}
            { Fr::toaltstack()}

            { Fq::push_dec(g1x) }
            { Fq::push_dec(g1y) }
            { Fq::push_dec(g1z) }

            // [y, scalar_f1, scalar_f2, scalar_e, scalar_j, e.x, e.y, e.z ] | [f.z, f.y, f.x]
            { Fr::fromaltstack() }
            { G1Projective::scalar_mul() }
        }
    }

    /// compute j (11)
    /// [ y, scalar_f1, scalar_f2, scalar_e, scalar_j, e.x, e.y, e.z] | [f.z, f.y, f.x]
    fn compute_j(w1x: &str, w1y: &str) -> Script {
        script! {
            // to alt stack: | [f.z, f.y, f.z, e.z, e.y, e.z ]
            { Fq::toaltstack() }
            { Fq::toaltstack() }
            { Fq::toaltstack() }

            // push the scalar
            { Fr::toaltstack() }
            // push G1x, G1y (3 elements)
            { Fq::push_dec(w1x) }
            { Fq::push_dec(w1y) }
            { Fq::push_dec("1") }
            { Fr::fromaltstack() }
            { G1Projective::scalar_mul() }
            // [y, scalar_f1, scalar_f2, scalar_e, j.x, j.y, j.z ] | [f.z, f.y, f.x, e.z, e.y, e.x]
        }
    }

    /// verify pairings
    /// compute j (14)
    // [y, scalar_f1, scalar_f2, scalar_e, j.x, j.y, j.z ] | [f.z, f.y, f.x, e.z, e.y, e.x]
    fn checkpairing_a1(proof_w2x: &str, proof_w2y: &str) -> Script {
        script! {
            // ] | [f.z, f.y, f.x, e.z, e.y, e.x, j.z, j.y, j.x]
            { Fq::toaltstack() }
            { Fq::toaltstack() }
            { Fq::toaltstack() }

            // ] | [f, e, j]
            { Fr::roll(3) }
            // ] | [f, e, j, y]
            { Fr::toaltstack() }

            // W2 ] | [f, e, j, y]
            { Fq::push_dec(proof_w2x) }
            { Fq::push_dec(proof_w2y) }
            { Fq::push_dec("1") }

            // W2, y ] | [f, e, j]
            { Fr::fromaltstack() }

            // W2 * y ] | [f, e, j]
            { G1Projective::scalar_mul() }

            // W2 * y, j, e, f ]
            { G1Projective::fromaltstack() }
            { G1Projective::fromaltstack() }
            // W2 * y, j, e] | [ f ]
            // W2 * y, j + e] | [ f ]
            { G1Projective::add() }
            // W2 * y, - (j + e)] | [ f ]
            { G1Projective::neg() }
            // W2 * y - (j + e)] | [ f ]
            { G1Projective::add() }
            // W2 * y - (j + e), f ]
            { G1Projective::fromaltstack() }
            // A1 = w2 * y + f - (e + j)
            { G1Projective::add() }

            { G1Projective::toaltstack() }

            { Fr::drop() }
            { Fr::drop() }
            { Fr::drop() }

            { G1Projective::fromaltstack() }
            { G1Projective::into_affine() }

        }
    }

    // todo
    /// fflonk_pairing_with_c_wi
    // compute j (60)
    // stack input: [A1.x, A1.y]
    fn fflonk_pairing_with_c_wi(
        w2: ark_bn254::g1::G1Affine,
        c: ark_bn254::Fq12,
        c_inv: ark_bn254::Fq12,
        wi: ark_bn254::Fq12,
        constant_1: &G2Prepared,
        constant_2: &G2Prepared,
    ) -> Script {
        script! {
            // [A1.x, A1.y]
            { utils::from_eval_point_in_stack() }
            // [A1.x', A1.y'] = [-A1.x/A1.y, 1/A1.y]
            { utils::from_eval_point(w2) }
            // [w2.x', w2.y'] = [-w2.x/w2.y, 1/w2.y]
            // [A1.x', A1.y', w2.x', w2.y']
            { fq12_push(c) }
            { fq12_push(c_inv) }
            { fq12_push(wi) }
            // [A1.x', A1.y', w2.x', w2.y', c, c_inv, wi]
            { Pairing::dual_miller_loop_with_c_wi(constant_1, constant_2, true) }
        }
    }

    // refer table 3 of https://eprint.iacr.org/2009/457.pdf
    // a: Fp12 which is cubic residue
    // c: random Fp12 which is cubic non-residue
    // s: satisfying p^12 - 1 = 3^s * t
    // t: satisfying p^12 - 1 = 3^s * t
    // k: k = (t + 1) // 3
    fn tonelli_shanks_cubic(
        a: ark_bn254::Fq12,
        c: ark_bn254::Fq12,
        s: u32,
        t: BigUint,
        k: BigUint,
    ) -> ark_bn254::Fq12 {
        let mut r = a.pow(t.to_u64_digits());
        let e = 3_u32.pow(s - 1);
        let exp = 3_u32.pow(s) * &t;

        // compute cubic root of (a^t)^-1, say h
        let (mut h, cc, mut c) = (
            ark_bn254::Fq12::ONE,
            c.pow([e as u64]),
            c.inverse().unwrap(),
        );
        for i in 1..(s as i32) {
            let delta = (s as i32) - i - 1;
            let d = if delta < 0 {
                r.pow((&exp / 3_u32.pow((-delta) as u32)).to_u64_digits())
            } else {
                r.pow([3_u32.pow(delta as u32).to_u64().unwrap()])
            };
            if d == cc {
                (h, r) = (h * c, r * c.pow([3_u64]));
            } else if d == cc.pow([2_u64]) {
                (h, r) = (h * c.pow([2_u64]), r * c.pow([3_u64]).pow([2_u64]));
            }
            c = c.pow([3_u64])
        }

        // recover cubic root of a
        r = a.pow(k.to_u64_digits()) * h;
        if t == 3_u32 * k + 1_u32 {
            r = r.inverse().unwrap();
        }

        assert_eq!(r.pow([3_u64]), a);
        r
    }

    // refer from Algorithm 5 of "On Proving Pairings"(https://eprint.iacr.org/2024/640.pdf)
    fn compute_c_wi(f: ark_bn254::Fq12) -> (ark_bn254::Fq12, ark_bn254::Fq12) {
        let p = BigUint::from_str_radix(Fq::MODULUS, 16).unwrap();
        let r = BigUint::from_str(
            "21888242871839275222246405745257275088548364400416034343698204186575808495617",
        )
        .unwrap();
        let lambda = BigUint::from_str(
            "10486551571378427818905133077457505975146652579011797175399169355881771981095211883813744499745558409789005132135496770941292989421431235276221147148858384772096778432243207188878598198850276842458913349817007302752534892127325269"
        ).unwrap();
        let s = 3_u32;
        let exp = p.pow(12_u32) - 1_u32;
        let h = &exp / &r;
        let t = &exp / 3_u32.pow(s);
        let k = (&t + 1_u32) / 3_u32;
        let m = &lambda / &r;
        let d = 3_u32;
        let mm = &m / d;

        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let cofactor_cubic = 3_u32.pow(s - 1) * &t;

        // make f is r-th residue, but it's not cubic residue
        assert_eq!(f.pow(h.to_u64_digits()), ark_bn254::Fq12::ONE);
        assert_ne!(f.pow(cofactor_cubic.to_u64_digits()), ark_bn254::Fq12::ONE);

        // sample a proper scalar w which is cubic non-residue
        let w = {
            let (mut w, mut z) = (ark_bn254::Fq12::ONE, ark_bn254::Fq12::ONE);
            while w == ark_bn254::Fq12::ONE {
                // choose z which is 3-th non-residue
                let mut legendre = ark_bn254::Fq12::ONE;
                while legendre == ark_bn254::Fq12::ONE {
                    z = ark_bn254::Fq12::rand(&mut prng);
                    legendre = z.pow(cofactor_cubic.to_u64_digits());
                }
                // obtain w which is t-th power of z
                w = z.pow(t.to_u64_digits());
            }
            w
        };
        // make sure 27-th root w, is 3-th non-residue and r-th residue
        assert_ne!(w.pow(cofactor_cubic.to_u64_digits()), ark_bn254::Fq12::ONE);
        assert_eq!(w.pow(h.to_u64_digits()), ark_bn254::Fq12::ONE);

        // just two option, w and w^2, since w^3 must be cubic residue, leading f*w^3 must not be cubic residue
        let mut wi = w;
        if (f * wi).pow(cofactor_cubic.to_u64_digits()) != ark_bn254::Fq12::ONE {
            assert_eq!(
                (f * w * w).pow(cofactor_cubic.to_u64_digits()),
                ark_bn254::Fq12::ONE
            );
            wi = w * w;
        }
        assert_eq!(wi.pow(h.to_u64_digits()), ark_bn254::Fq12::ONE);

        assert_eq!(lambda, &d * &mm * &r);
        // f1 is scaled f
        let f1 = f * wi;

        // r-th root of f1, say f2
        let r_inv = r.modinv(&h).unwrap();
        assert_ne!(r_inv, BigUint::one());
        let f2 = f1.pow(r_inv.to_u64_digits());
        assert_ne!(f2, ark_bn254::Fq12::ONE);

        // m'-th root of f, say f3
        let mm_inv = mm.modinv(&(r * h)).unwrap();
        assert_ne!(mm_inv, BigUint::one());
        let f3 = f2.pow(mm_inv.to_u64_digits());
        assert_eq!(f3.pow(cofactor_cubic.to_u64_digits()), ark_bn254::Fq12::ONE);
        assert_ne!(f3, ark_bn254::Fq12::ONE);

        // d-th (cubic) root, say c
        let c = tonelli_shanks_cubic(f3, w, s, t, k);
        assert_ne!(c, ark_bn254::Fq12::ONE);
        assert_eq!(c.pow(lambda.to_u64_digits()), f * wi);

        (c, wi)
    }

    #[test]
    fn test_fflonk_verifier() {
        let (c0_x, c0_y, c0_z, c1_x, c1_y, c1_z, inp_1, inp_2) = (
            "303039279492065453055049758769758984569666029850327527958551993331680103359",
            "15061669176783843627135305167141360334623983780813847469326507992811672859575",
            "1",
            "8993820735255461694205287896466659762517378169680151817278189507219986014273",
            "20608602847008036615737932995836476570376266531776948091942386633580114403199",
            "1",
            "246513590391103489634602289097178521809",
            "138371009144214353742010089705444713455",
        );
        let (xi, ql, qr, qm, qo, qc, s1, s2, s3, a, b, c, z, zw, t1w, t2w) = (
            "12675309311304482509247823029963782393309524866265275290730041635615278736000",
            "4305584171954448775801758618991977283131671407134816099015723841718827300684",
            "12383383973686840675128398394454489421896122330596726461131121746926747341189",
            "84696450614978050680673343346456326547032107368333805624994614151289555853",
            "3940439340424631873531863239669720717811550024514867065774687720368464792371",
            "16961785810060156933739931986193776143069216115530808410139185289490606944009",
            "12474437127153975801320290893919924661315458586210754316226946498711086665749",
            "599434615255095347665395089945860172292558760398201299457995057871688253664",
            "16217604511932175446614838218599989473511950977205890369538297955449224727219",
            "7211168621666826182043583595845418959530786367587156242724929610231435505336",
            "848088075173937026388846472327431819307508078325359401333033359624801042",
            "18963734392470978715233675860777231227480937309534365140504133190694875258320",
            "2427313569771756255376235777000596702684056445296844486767054635200432142794",
            "8690328511114991742730387856275843464438882369629727414507275814599493141660",
            "20786626696833495453279531623626288211765949258916047124642669459480728122908",
            "12092130080251498309415337127155404037148503145602589831662396526189421234148",
        );
        let (w1_x, w1_y, w1_z) = (
            "32650538602400348219903702316313439265244325226254563471430382441955222030",
            "1102261574488401129043229793384018650738538286437537952751903719159654317199",
            "1",
        );

        let (w2_x, w2_y, w2_z) = (
            "11695827642347470645483614914520090101440686332033956264171712726147972703435",
            "8930092616903485317239646434389939466400752538134075201209141980838088395614",
            "1",
        );

        let (c2_x, c2_y, c2_z) = (
            "7381325072443970270370678023564870071058744625357849943766655609499175274412",
            "15178578915928592705383893120230835636411008017183180871962629962483134367891",
            "1",
        );
        let (w8_1, w8_2, w8_3, w8_4, w8_5, w8_6, w8_7, w3, w3_2, w4, w4_2, w4_3, wr) = (
            "19540430494807482326159819597004422086093766032135589407132600596362845576832",
            "21888242871839275217838484774961031246007050428528088939761107053157389710902",
            "13274704216607947843011480449124596415239537050559949017414504948711435969894",
            "21888242871839275222246405745257275088548364400416034343698204186575808495616",
            "2347812377031792896086586148252853002454598368280444936565603590212962918785",
            "4407920970296243842541313971887945403937097133418418784715",
            "8613538655231327379234925296132678673308827349856085326283699237864372525723",
            "21888242871839275217838484774961031246154997185409878258781734729429964517155",
            "4407920970296243842393367215006156084916469457145843978461",
            "21888242871839275217838484774961031246007050428528088939761107053157389710902",
            "21888242871839275222246405745257275088548364400416034343698204186575808495616",
            "4407920970296243842541313971887945403937097133418418784715",
            "19699792133865984655632994927951174943026102279822605383822362801478354085676",
        );
        let (w1, inv) = (
            "11699596668367776675346610687704220591435078791727316319397053191800576917728",
            "21247383512588455895834686692756529012394058115069710447132959660051940541361",
        );

        let (g1_x, g1_y, g1_z) = ("1", "2", "1");

        let hash_128 = blake3_var_length(128);
        let hash_32 = blake3_var_length(32);
        let hash_512 = blake3_var_length(512);
        let hash_64 = blake3_var_length(64);

        // ****************** prepare for pairing_verify **************************
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

        let projective = ark_bn254::G1Projective::new(
            ark_bn254::Fq::from_str(
                "21025932300722401404248737517866966587837387913191004025854702115722286998035",
            )
            .unwrap(),
            ark_bn254::Fq::from_str(
                "5748766770337880144484917096976043621609890780406924686031233755006782215858",
            )
            .unwrap(),
            ark_bn254::Fq::from_str(
                "18747233771850556311508953762939425433543524671221692065979284256379095132287",
            )
            .unwrap(),
        );
        let affine = projective.into_affine();

        let Q0 = ark_bn254::g2::G2Affine::new(
            ark_bn254::Fq2::new(
                ark_bn254::Fq::from_str(
                    "10857046999023057135944570762232829481370756359578518086990519993285655852781",
                )
                .unwrap(),
                ark_bn254::Fq::from_str(
                    "11559732032986387107991004021392285783925812861821192530917403151452391805634",
                )
                .unwrap(),
            ),
            ark_bn254::Fq2::new(
                ark_bn254::Fq::from_str(
                    "8495653923123431417604973247489272438418190587263600148770280649306958101930",
                )
                .unwrap(),
                ark_bn254::Fq::from_str(
                    "4082367875863433681332203403145435568316851327593401208105741076214120093531",
                )
                .unwrap(),
            ),
        );
        let Q0_prepared = G2Prepared::from_affine(Q0);

        let Q1 = ark_bn254::g2::G2Affine::new(
            ark_bn254::Fq2::new(
                ark_bn254::Fq::from_str(
                    "21831381940315734285607113342023901060522397560371972897001948545212302161822",
                )
                .unwrap(),
                ark_bn254::Fq::from_str(
                    "17231025384763736816414546592865244497437017442647097510447326538965263639101",
                )
                .unwrap(),
            ),
            ark_bn254::Fq2::new(
                ark_bn254::Fq::from_str(
                    "2388026358213174446665280700919698872609886601280537296205114254867301080648",
                )
                .unwrap(),
                ark_bn254::Fq::from_str(
                    "11507326595632554467052522095592665270651932854513688777769618397986436103170",
                )
                .unwrap(),
            ),
        );
        let Q1_prepared = G2Prepared::from_affine(-Q1);

        let w2 = ark_bn254::g1::G1Affine::new(
            ark_bn254::Fq::from_str(
                "11695827642347470645483614914520090101440686332033956264171712726147972703435",
            )
            .unwrap(),
            ark_bn254::Fq::from_str(
                "8930092616903485317239646434389939466400752538134075201209141980838088395614",
            )
            .unwrap(),
        );

        let f = Bn254::multi_miller_loop_affine([affine, w2], [Q0, -Q1]).0;

        let (c_ori, wi) = compute_c_wi(f);
        let c_inv = c_ori.inverse().unwrap();
        let hint = if sign {
            f * wi * (c_inv.pow(exp.to_u64_digits()))
        } else {
            f * wi * (c_inv.pow(exp.to_u64_digits()).inverse().unwrap())
        };

        assert_eq!(hint, c_ori.pow(p_pow3.to_u64_digits()));

        let script = script! {
            // compute challenge beta and check
            {  compute_challenges_beta(&hash_128, c0_x, c0_y, c1_x, c1_y, inp_1, inp_2) }
            // [beta]

            // compute challenge gamma and check
            { compute_challenges_gamma(&hash_32) }
            // [beta, gamma]

            // // compute alpha
            { compute_challenges_alpha(&hash_512,
                xi,
                ql,
                qr,
                qm,
                qo,
                qc,
                s1,
                s2,
                s3,
                a,
                b,
                c,
                z,
                zw,
                t1w,
                t2w) }
            // [beta, gamma, alpha]

            //// compute challenges_y
            { compute_challenges_y(&hash_64, w1_x, w1_y) }
            // [beta, gamma, alpha, y]

            { compute_challenges_xiseed(&hash_64, c2_x, c2_y) }
            // [beta, gamma, alpha, y, xiseed]

            {
                compute_challenges_xin(
                    w8_1,
                    w8_2,
                    w8_3,
                    w8_4,
                    w8_5,
                    w8_6,
                    w8_7,
                    w3,
                    w3_2,
                    w4,
                    w4_2,
                    w4_3,
                    wr,
                )
            }
            // [beta, gamma, alpha, y, pH0w8_0, pH0w8_1, pH0w8_2, pH0w8_3, pH0w8_4, pH0w8_5, pH0w8_6, pH0w8_7,
            // pH1w4_0, pH1w4_1, pH1w4_2, pH1w4_3, pH2w3_0, pH2w3_1, pH2w3_2, pH3w3_0, pH3w3_1, pH2w3_2, xi, zh]

            { compute_inversions(w1, inv) }
            // [beta, gamma, alpha, y, pH0w8_0, pH0w8_1, pH0w8_2, pH0w8_3, pH0w8_4, pH0w8_5, pH0w8_6, pH0w8_7,
            // pH1w4_0, pH1w4_1, pH1w4_2, pH1w4_3, pH2w3_0, pH2w3_1, pH2w3_2, pH3w3_0, pH3w3_1, pH2w3_2, xi, zh,
            // ZH, DenH1, DenH2, LiS0_1, LiS0_2, LiS0_3, ...]

            { compute_lagranges(w1) }
            // pH1w4_0, pH1w4_1, pH1w4_2, pH1w4_3, pH2w3_0, pH2w3_1, pH2w3_2, pH3w3_0, pH3w3_1, pH2w3_2, xi, zh,
            // ZH, DenH1, DenH2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8,
            // LiS1_1, LiS1_2, LiS1_3, LiS1_4, LiS2_1, LiS2_2, LiS2_3, LiS3_1, LiS3_2, LiS3_3, Li_1, Li_2, L[1], L[2]]

            { compute_pi(inp_1, inp_2) }
            // pH1w4_0, pH1w4_1, pH1w4_2, pH1w4_3, pH2w3_0, pH2w3_1, pH2w3_2, pH3w3_0, pH3w3_1, pH2w3_2, xi, zh,
            // ZH, DenH1, DenH2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8,
            // LiS1_1, LiS1_2, LiS1_3, LiS1_4, LiS2_1, LiS2_2, LiS2_3, LiS3_1, LiS3_2, LiS3_3, Li_1, Li_2, pi]

            { compute_r0(ql, qr, qo, qm, qc, s1, s2, s3) }
            // pH1w4_0, pH1w4_1, pH1w4_2, pH1w4_3, pH2w3_0, pH2w3_1, pH2w3_2, pH3w3_0, pH3w3_1, pH2w3_2, xi, zh,
            // ZH, DenH1, DenH2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8,
            // LiS1_1, LiS1_2, LiS1_3, LiS1_4, LiS2_1, LiS2_2, LiS2_3, LiS3_1, LiS3_2, LiS3_3, Li_1, Li_2, pi, r0]

            { compute_r1(ql, qr, qm, qo, qc, a, b, c) }

            { compute_r2(a, b, c, z, zw, s1, s2, s3, t1w, t2w, w1) }

            { compute_fej() }

            {compute_f_opt(c0_x, c0_y, c0_z, c1_x, c1_y, c1_z, c2_x, c2_y, c2_z)}


            // save f
            { Fq::toaltstack() }
            { Fq::toaltstack() }
            { Fq::toaltstack() }

            // push the scalar
            { Fr::copy(1)}
            { Fr::toaltstack()} // [ | e_scalar]

            // push g1
            { Fq::push_dec(g1_x) }
            { Fq::push_dec(g1_y) }
            { Fq::push_dec(g1_z) } // [-g1 | e_scalar]
            { G1Projective::neg() }
            { G1Projective::toaltstack() } // [ | -g1 e_scalar]

            // push the scalar
            { Fr::toaltstack() }
            // push G1x, G1y (3 elements)
            { Fq::push_dec(w1_x) }
            { Fq::push_dec(w1_y) }
            { Fq::push_dec("1") }
            { G1Projective::neg() }
            { G1Projective::toaltstack() } // [| -w1, w1_scalar, -g1, e_scalar]

            {Fr::roll(3)}
            {Fr::toaltstack()}

            {Fq::push_dec(w2_x)}
            {Fq::push_dec(w2_y)}
            {Fq::push_dec("1")}
            {Fr::fromaltstack()} // [w2, w2_scalar(y) | -w1, w1_scalar, -g1, e_scalar ]

            { Fr::fromaltstack() }
            { G1Projective::fromaltstack() }
            { Fr::fromaltstack() }
            { G1Projective::fromaltstack() } // [w2, w2_scalar(y) -w1, w1_scalar, -g1, e_scalar ]

            { G1Projective::batched_scalar_mul::<3>()} // W2 * y - (j + e)] | [ f ]
            { G1Projective::fromaltstack() }
            { G1Projective::add() }  // A1 = w2 * y + f - (e + j)

            // clear stack
            {G1Projective::toaltstack()}
            {Fr::drop()}
            {Fr::drop()}
            {Fr::drop()}
            {G1Projective::fromaltstack()}

            // A1 to affine
            {G1Projective::into_affine()}

            { fflonk_pairing_with_c_wi(w2, c_ori, c_inv, wi, &Q0_prepared, &Q1_prepared) }

            { fq12_push(hint) }
            { Fq12::equalverify() }

            OP_TRUE

        };
        println!("fflonk.checkpairing_miller_loop = {} bytes", script.len());
        run(script);
    }

    #[test]
    fn test_fflonk_verifier_as_chunks() {
        let (c0_x, c0_y, c0_z, c1_x, c1_y, c1_z, inp_1, inp_2) = (
            "303039279492065453055049758769758984569666029850327527958551993331680103359",
            "15061669176783843627135305167141360334623983780813847469326507992811672859575",
            "1",
            "8993820735255461694205287896466659762517378169680151817278189507219986014273",
            "20608602847008036615737932995836476570376266531776948091942386633580114403199",
            "1",
            "246513590391103489634602289097178521809",
            "138371009144214353742010089705444713455",
        );
        let (xi, ql, qr, qm, qo, qc, s1, s2, s3, a, b, c, z, zw, t1w, t2w) = (
            "12675309311304482509247823029963782393309524866265275290730041635615278736000",
            "4305584171954448775801758618991977283131671407134816099015723841718827300684",
            "12383383973686840675128398394454489421896122330596726461131121746926747341189",
            "84696450614978050680673343346456326547032107368333805624994614151289555853",
            "3940439340424631873531863239669720717811550024514867065774687720368464792371",
            "16961785810060156933739931986193776143069216115530808410139185289490606944009",
            "12474437127153975801320290893919924661315458586210754316226946498711086665749",
            "599434615255095347665395089945860172292558760398201299457995057871688253664",
            "16217604511932175446614838218599989473511950977205890369538297955449224727219",
            "7211168621666826182043583595845418959530786367587156242724929610231435505336",
            "848088075173937026388846472327431819307508078325359401333033359624801042",
            "18963734392470978715233675860777231227480937309534365140504133190694875258320",
            "2427313569771756255376235777000596702684056445296844486767054635200432142794",
            "8690328511114991742730387856275843464438882369629727414507275814599493141660",
            "20786626696833495453279531623626288211765949258916047124642669459480728122908",
            "12092130080251498309415337127155404037148503145602589831662396526189421234148",
        );
        let (w1_x, w1_y, w1_z) = (
            "32650538602400348219903702316313439265244325226254563471430382441955222030",
            "1102261574488401129043229793384018650738538286437537952751903719159654317199",
            "1",
        );

        let (w2_x, w2_y, w2_z) = (
            "11695827642347470645483614914520090101440686332033956264171712726147972703435",
            "8930092616903485317239646434389939466400752538134075201209141980838088395614",
            "1",
        );

        let (c2_x, c2_y, c2_z) = (
            "7381325072443970270370678023564870071058744625357849943766655609499175274412",
            "15178578915928592705383893120230835636411008017183180871962629962483134367891",
            "1",
        );
        let (w8_1, w8_2, w8_3, w8_4, w8_5, w8_6, w8_7, w3, w3_2, w4, w4_2, w4_3, wr) = (
            "19540430494807482326159819597004422086093766032135589407132600596362845576832",
            "21888242871839275217838484774961031246007050428528088939761107053157389710902",
            "13274704216607947843011480449124596415239537050559949017414504948711435969894",
            "21888242871839275222246405745257275088548364400416034343698204186575808495616",
            "2347812377031792896086586148252853002454598368280444936565603590212962918785",
            "4407920970296243842541313971887945403937097133418418784715",
            "8613538655231327379234925296132678673308827349856085326283699237864372525723",
            "21888242871839275217838484774961031246154997185409878258781734729429964517155",
            "4407920970296243842393367215006156084916469457145843978461",
            "21888242871839275217838484774961031246007050428528088939761107053157389710902",
            "21888242871839275222246405745257275088548364400416034343698204186575808495616",
            "4407920970296243842541313971887945403937097133418418784715",
            "19699792133865984655632994927951174943026102279822605383822362801478354085676",
        );
        let (w1, inv) = (
            "11699596668367776675346610687704220591435078791727316319397053191800576917728",
            "21247383512588455895834686692756529012394058115069710447132959660051940541361",
        );

        let (g1_x, g1_y, g1_z) = ("1", "2", "1");

        let hash_128 = blake3_var_length(128);
        let hash_32 = blake3_var_length(32);
        let hash_512 = blake3_var_length(512);
        let hash_64 = blake3_var_length(64);

        // ****************** prepare for pairing_verify **************************
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

        let projective = ark_bn254::G1Projective::new(
            ark_bn254::Fq::from_str(
                "21025932300722401404248737517866966587837387913191004025854702115722286998035",
            )
            .unwrap(),
            ark_bn254::Fq::from_str(
                "5748766770337880144484917096976043621609890780406924686031233755006782215858",
            )
            .unwrap(),
            ark_bn254::Fq::from_str(
                "18747233771850556311508953762939425433543524671221692065979284256379095132287",
            )
            .unwrap(),
        );
        let affine = projective.into_affine();

        let Q0 = ark_bn254::g2::G2Affine::new(
            ark_bn254::Fq2::new(
                ark_bn254::Fq::from_str(
                    "10857046999023057135944570762232829481370756359578518086990519993285655852781",
                )
                .unwrap(),
                ark_bn254::Fq::from_str(
                    "11559732032986387107991004021392285783925812861821192530917403151452391805634",
                )
                .unwrap(),
            ),
            ark_bn254::Fq2::new(
                ark_bn254::Fq::from_str(
                    "8495653923123431417604973247489272438418190587263600148770280649306958101930",
                )
                .unwrap(),
                ark_bn254::Fq::from_str(
                    "4082367875863433681332203403145435568316851327593401208105741076214120093531",
                )
                .unwrap(),
            ),
        );
        let Q0_prepared = G2Prepared::from_affine(Q0);

        let Q1 = ark_bn254::g2::G2Affine::new(
            ark_bn254::Fq2::new(
                ark_bn254::Fq::from_str(
                    "21831381940315734285607113342023901060522397560371972897001948545212302161822",
                )
                .unwrap(),
                ark_bn254::Fq::from_str(
                    "17231025384763736816414546592865244497437017442647097510447326538965263639101",
                )
                .unwrap(),
            ),
            ark_bn254::Fq2::new(
                ark_bn254::Fq::from_str(
                    "2388026358213174446665280700919698872609886601280537296205114254867301080648",
                )
                .unwrap(),
                ark_bn254::Fq::from_str(
                    "11507326595632554467052522095592665270651932854513688777769618397986436103170",
                )
                .unwrap(),
            ),
        );
        let Q1_prepared = G2Prepared::from_affine(-Q1);

        let w2 = ark_bn254::g1::G1Affine::new(
            ark_bn254::Fq::from_str(
                "11695827642347470645483614914520090101440686332033956264171712726147972703435",
            )
            .unwrap(),
            ark_bn254::Fq::from_str(
                "8930092616903485317239646434389939466400752538134075201209141980838088395614",
            )
            .unwrap(),
        );

        let f = Bn254::multi_miller_loop_affine([affine, w2], [Q0, -Q1]).0;

        let (c_ori, wi) = compute_c_wi(f);
        let c_inv = c_ori.inverse().unwrap();
        let hint = if sign {
            f * wi * (c_inv.pow(exp.to_u64_digits()))
        } else {
            f * wi * (c_inv.pow(exp.to_u64_digits()).inverse().unwrap())
        };

        assert_eq!(hint, c_ori.pow(p_pow3.to_u64_digits()));

        let script = script! {
            // compute challenge beta and check
            {  compute_challenges_beta(&hash_128, c0_x, c0_y, c1_x, c1_y, inp_1, inp_2) }
            // [beta]

            // compute challenge gamma and check
            { compute_challenges_gamma(&hash_32) }
            // [beta, gamma]

            // // compute alpha
            { compute_challenges_alpha(&hash_512,
                xi,
                ql,
                qr,
                qm,
                qo,
                qc,
                s1,
                s2,
                s3,
                a,
                b,
                c,
                z,
                zw,
                t1w,
                t2w) }
            // [beta, gamma, alpha]

            //// compute challenges_y
            { compute_challenges_y(&hash_64, w1_x, w1_y) }
            // [beta, gamma, alpha, y]

            { compute_challenges_xiseed(&hash_64, c2_x, c2_y) }
            // [beta, gamma, alpha, y, xiseed]

            {
                compute_challenges_xin(
                    w8_1,
                    w8_2,
                    w8_3,
                    w8_4,
                    w8_5,
                    w8_6,
                    w8_7,
                    w3,
                    w3_2,
                    w4,
                    w4_2,
                    w4_3,
                    wr,
                )
            }
            // [beta, gamma, alpha, y, pH0w8_0, pH0w8_1, pH0w8_2, pH0w8_3, pH0w8_4, pH0w8_5, pH0w8_6, pH0w8_7,
            // pH1w4_0, pH1w4_1, pH1w4_2, pH1w4_3, pH2w3_0, pH2w3_1, pH2w3_2, pH3w3_0, pH3w3_1, pH2w3_2, xi, zh]

            { compute_inversions(w1, inv) }
            // [beta, gamma, alpha, y, pH0w8_0, pH0w8_1, pH0w8_2, pH0w8_3, pH0w8_4, pH0w8_5, pH0w8_6, pH0w8_7,
            // pH1w4_0, pH1w4_1, pH1w4_2, pH1w4_3, pH2w3_0, pH2w3_1, pH2w3_2, pH3w3_0, pH3w3_1, pH2w3_2, xi, zh,
            // ZH, DenH1, DenH2, LiS0_1, LiS0_2, LiS0_3, ...]

            { compute_lagranges(w1) }
            // pH1w4_0, pH1w4_1, pH1w4_2, pH1w4_3, pH2w3_0, pH2w3_1, pH2w3_2, pH3w3_0, pH3w3_1, pH2w3_2, xi, zh,
            // ZH, DenH1, DenH2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8,
            // LiS1_1, LiS1_2, LiS1_3, LiS1_4, LiS2_1, LiS2_2, LiS2_3, LiS3_1, LiS3_2, LiS3_3, Li_1, Li_2, L[1], L[2]]

            { compute_pi(inp_1, inp_2) }
            // pH1w4_0, pH1w4_1, pH1w4_2, pH1w4_3, pH2w3_0, pH2w3_1, pH2w3_2, pH3w3_0, pH3w3_1, pH2w3_2, xi, zh,
            // ZH, DenH1, DenH2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8,
            // LiS1_1, LiS1_2, LiS1_3, LiS1_4, LiS2_1, LiS2_2, LiS2_3, LiS3_1, LiS3_2, LiS3_3, Li_1, Li_2, pi]

            { compute_r0(ql, qr, qo, qm, qc, s1, s2, s3) }
            // pH1w4_0, pH1w4_1, pH1w4_2, pH1w4_3, pH2w3_0, pH2w3_1, pH2w3_2, pH3w3_0, pH3w3_1, pH2w3_2, xi, zh,
            // ZH, DenH1, DenH2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8,
            // LiS1_1, LiS1_2, LiS1_3, LiS1_4, LiS2_1, LiS2_2, LiS2_3, LiS3_1, LiS3_2, LiS3_3, Li_1, Li_2, pi, r0]

            { compute_r1(ql, qr, qm, qo, qc, a, b, c) }

            { compute_r2(a, b, c, z, zw, s1, s2, s3, t1w, t2w, w1) }

            { compute_fej() }

            { compute_f_opt(c0_x, c0_y, c0_z, c1_x, c1_y, c1_z, c2_x, c2_y, c2_z) }


            // save f
            { Fq::toaltstack() }
            { Fq::toaltstack() }
            { Fq::toaltstack() }

            // push the scalar
            { Fr::copy(1)}
            { Fr::toaltstack()} // [ | e_scalar]

            // push g1
            { Fq::push_dec(g1_x) }
            { Fq::push_dec(g1_y) }
            { Fq::push_dec(g1_z) } // [-g1 | e_scalar]
            { G1Projective::neg() }
            { G1Projective::toaltstack() } // [ | -g1 e_scalar]

            // push the scalar
            { Fr::toaltstack() }
            // push G1x, G1y (3 elements)
            { Fq::push_dec(w1_x) }
            { Fq::push_dec(w1_y) }
            { Fq::push_dec("1") }
            { G1Projective::neg() }
            { G1Projective::toaltstack() } // [| -w1, w1_scalar, -g1, e_scalar]

            {Fr::roll(3)}
            {Fr::toaltstack()}

            {Fq::push_dec(w2_x)}
            {Fq::push_dec(w2_y)}
            {Fq::push_dec("1")}
            {Fr::fromaltstack()} // [w2, w2_scalar(y) | -w1, w1_scalar, -g1, e_scalar ]

            { Fr::fromaltstack() }
            { G1Projective::fromaltstack() }
            { Fr::fromaltstack() }
            { G1Projective::fromaltstack() } // [w2, w2_scalar(y) -w1, w1_scalar, -g1, e_scalar ]

            { G1Projective::batched_scalar_mul::<3>()} // W2 * y - (j + e)] | [ f ]
            { G1Projective::fromaltstack() }
            { G1Projective::add() }  // A1 = w2 * y + f - (e + j)

            // clear stack
            {G1Projective::toaltstack()}
            {Fr::drop()}
            {Fr::drop()}
            {Fr::drop()}
            {G1Projective::fromaltstack()}

            // A1 to affine
            {G1Projective::into_affine()}

            { fflonk_pairing_with_c_wi(w2, c_ori, c_inv, wi, &Q0_prepared, &Q1_prepared) }

            { fq12_push(hint) }
            { Fq12::equalverify() }

            OP_TRUE

        };
        println!("fflonk.checkpairing_miller_loop = {} bytes", script.len());
        let interval = script.max_op_if_interval();
        println!(
            "Max if interval: {:?} difference: {}, debug info: {}, {}",
            interval,
            interval.1 - interval.0,
            script.debug_info(interval.0),
            script.debug_info(interval.1)
        );
        let stack = script.analyze_stack();
        println!("stack: {:?}", stack);
        //let exec_result = execute_script_as_chunks(script, 3_000_000, 2_000_000);
        //println!("{}", exec_result);
        //assert!(exec_result.success);
    }
}
