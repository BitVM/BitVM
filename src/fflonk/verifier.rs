#[cfg(test)]
mod test {
    use crate::bn254::curves::G1Affine;
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::bn254::fq::Fq;
    use crate::bn254::fr::Fr;
    use crate::hash::blake3::blake3_var_length;
    use crate::treepp::*;

    //// compute challenges
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

    //// compute inversions
    fn compute_inversions(w: &str, inv: &str) -> Script {
        script! {
            // push Z_H
            // { Fr::copy(0) }
            { Fr::toaltstack() }

            // push y
            { Fr::copy(19) }
            // push H1w4_0, H1w4_1, H1w4_2, H1w4_3
            { Fr::copy(11) }
            { Fr::copy(11) }
            { Fr::copy(11) }
            { Fr::copy(11) }
            // [..., xi, y, pH1w4_0, pH1w4_1, pH1w4_2, pH1w4_3 | Z_H]

            { Fr::copy(4) }
            { Fr::sub(0, 1) }
            // [xi, y, pH1w4_0, pH1w4_1, pH1w4_2, y - pH1w4_3 | Z_H]
            { Fr::copy(4) }
            { Fr::sub(0, 2) }
            // [xi, y, pH1w4_0, pH1w4_1, y - pH1w4_3, y - pH1w4_2 | Z_H]
            { Fr::copy(4) }
            { Fr::sub(0, 3) }
            // [y, pH1w4_0, y - pH1w4_3, y - pH1w4_2, y - pH1w4_1 | Z_H]
            { Fr::copy(4) }
            { Fr::sub(0, 4) }
            // [y, y - pH1w4_3, y - pH1w4_2, y - pH1w4_1, y - pH1w4_0 | Z_H]

            { Fr::mul() }
            { Fr::mul() }
            { Fr::mul() }
            // [y, (y - pH1w4_3) * (y - pH1w4_2) * (y - pH1w4_1) * (y - pH1w4_0)]
            { Fr::toaltstack() }
            // [y | Z_H, (y - pH1w4_3) * (y - pH1w4_2) * (y - pH1w4_1) * (y - pH1w4_0)]

            // push H2w3_0, H2w3_1, H2w3_2, H3w3_0, H3w3_1, H3w3_2
            { Fr::copy(7) }
            { Fr::copy(7) }
            { Fr::copy(7) }
            { Fr::copy(7) }
            { Fr::copy(7) }
            { Fr::copy(7) }
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
            { Fr::copy(19) }
            { Fr::copy(19) }
            { Fr::copy(19) }
            { Fr::copy(19) }
            { Fr::copy(19) }
            { Fr::copy(19) }
            { Fr::copy(19) }
            { Fr::copy(19) }
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
            { Fr::copy(11) }
            { Fr::copy(11) }
            { Fr::copy(11) }
            { Fr::copy(11) }

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
            { Fr::copy(7) }
            { Fr::copy(7) }
            { Fr::copy(7) }
            // [y, H2w3_0, H2w3_1, H2w3_2 | Z_H, prod_1, prod_2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8, LiS1_1, LiS1_2, LiS1_3, LiS1_4]

            // push xi
            // { Fr::push_dec("14814634099415170872937750660683266261347419959225231219985478027287965492246") }
            { Fr::copy(4) }
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
            // { Fr::push_dec("21405568746311661929319138487394095463124289053215849061649274916682085734478") }
            // { Fr::push_dec("16458699422327211795980147165837933894457139622322803085568450314170832928180") }
            // { Fr::push_dec("5912217575039676719193525837282520819515300125293416540178683142298698328576") }
            { Fr::copy(5) }
            { Fr::copy(5) }
            { Fr::copy(5) }
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
            // [ | Z_H, prod_1, prod_2, LiS0_1, LiS0_2, LiS0_3, LiS0_4, LiS0_5, LiS0_6, LiS0_7, LiS0_8, LiS1_1, LiS1_2, LiS1_3, LiS1_4, LiS2_1, LiS2_2, LiS2_3, LiS3_1, LiS3_2, LiS3_3]

            // push xi again
            // { Fr::push_dec("14814634099415170872937750660683266261347419959225231219985478027287965492246") }
            { Fr::copy(0) }
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
            // [ZH | ..., LiS0_3, LiS0_2, LiS0_1, DenH2, DenH1]

            for _ in 0..22 {
                { Fr::fromaltstack() }
            }
            // [..., xi, ZH, DenH1, DenH2, LiS0_1, LiS0_2, LiS0_3, ...]
        }
    }

    //// compute lagranges
    fn compute_lagranges() -> Script {
        todo!()
    }

    //// compute pi
    fn compute_pi() -> Script {
        todo!()
    }

    //// compute R
    fn compute_r() -> Script {
        todo!()
    }

    //// compute fej
    fn compute_fej() -> Script {
        todo!()
    }

    //// verify pairings
    fn verify_pairings() -> Script {
        todo!()
    }

    #[test]
    fn test_verifier() {
        let (c0_x, c0_y, c1_x, c1_y, inp_1, inp_2) = (
            "303039279492065453055049758769758984569666029850327527958551993331680103359",
            "15061669176783843627135305167141360334623983780813847469326507992811672859575",
            "8993820735255461694205287896466659762517378169680151817278189507219986014273",
            "20608602847008036615737932995836476570376266531776948091942386633580114403199",
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
        let (w1_x, w1_y) = (
            "32650538602400348219903702316313439265244325226254563471430382441955222030",
            "1102261574488401129043229793384018650738538286437537952751903719159654317199",
        );
        let (c2_x, c2_y) = (
            "7381325072443970270370678023564870071058744625357849943766655609499175274412",
            "15178578915928592705383893120230835636411008017183180871962629962483134367891",
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
        let hash_128 = blake3_var_length(128);
        let hash_32 = blake3_var_length(32);
        let hash_512 = blake3_var_length(512);
        let hash_64 = blake3_var_length(64);

        let script = script! {
            // compute challenge beta and check
            {  compute_challenges_beta(&hash_128, c0_x, c0_y, c1_x, c1_y, inp_1, inp_2) }
            // { Fr::push_dec("485596931070696584921673007746559446164232583596250406637950679013042540061")}
            // { Fr::equal(1, 0) }
            // [beta]

            // compute challenge gamma and check
            { compute_challenges_gamma(&hash_32) }
            // { Fr::push_dec("19250037324033436581569284153336383290774316882310310865823706333327285195728") }
            // { Fr::equal(1, 0) }
            // { Fr::drop() }
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
            // { Fr::push_dec("13196272401875304388921830696024531900252495617961467853893732289110815791950") }
            // { Fr::equal(1, 0) }
            // { Fr::drop() }
            // { Fr::drop() }
            // [beta, gamma, alpha]

            //// compute challenges_y
            { compute_challenges_y(&hash_64, w1_x, w1_y) }
            // { Fr::push_dec("6824639836122392703554190210911349683223362245243195922653951653214183338070") }
            // { Fr::equal(1, 0) }
            // { Fr::drop() }
            // { Fr::drop() }
            // { Fr::drop() }
            // [beta, gamma, alpha, y]

            { compute_challenges_xiseed(&hash_64, c2_x, c2_y) }
            // { Fr::push_dec("12675309311304482509247823029963782393309524866265275290730041635615278736000") }
            // { Fr::equal(1, 0) }
            // { Fr::drop() }
            // { Fr::drop() }
            // { Fr::drop() }
            // { Fr::drop() }
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
            // { Fr::push_dec("9539499652122301619680560867461437153480631573357135330838514610439758374055") }
            // { Fr::equalverify(1, 0) }
            // { Fr::drop() }
            // { Fr::drop() }
            // { Fr::drop() }
            // { Fr::drop() }
            // { Fr::drop() }
            // { Fr::drop() }
            // { Fr::drop() }
            // { Fr::drop() }
            // { Fr::drop() }
            // { Fr::drop() }
            // { Fr::drop() }
            // { Fr::drop() }
            // { Fr::drop() }
            // { Fr::drop() }
            // { Fr::drop() }
            // { Fr::drop() }
            // { Fr::drop() }
            // { Fr::drop() }
            // { Fr::drop() }
            // { Fr::drop() }
            // { Fr::drop() }
            // { Fr::drop() }
            // { Fr::drop() }
            // OP_TRUE
            // [beta, gamma, alpha, y, pH0w8_0, pH0w8_1, pH0w8_2, pH0w8_3, pH0w8_4, pH0w8_5, pH0w8_6, pH0w8_7,
            // pH1w4_0, pH1w4_1, pH1w4_2, pH1w4_3, pH2w3_0, pH2w3_1, pH2w3_2, pH3w3_0, pH3w3_1, pH2w3_2, xi, zh]

            { compute_inversions(w1, inv) }
            // [beta, gamma, alpha, y, pH0w8_0, pH0w8_1, pH0w8_2, pH0w8_3, pH0w8_4, pH0w8_5, pH0w8_6, pH0w8_7,
            // pH1w4_0, pH1w4_1, pH1w4_2, pH1w4_3, pH2w3_0, pH2w3_1, pH2w3_2, pH3w3_0, pH3w3_1, pH2w3_2, xi,
            // ZH, DenH1, DenH2, LiS0_1, LiS0_2, LiS0_3, ...]

            // { Fr::copy(22) }
            // { Fr::push_dec("9539499652122301619680560867461437153480631573357135330838514610439758374055") }
            // { Fr::mul() }
            // { Fr::is_one_keep_element(0) }
            // OP_VERIFY
            // { Fr::drop() } // is_one does not consume the input
            // for _ in 0..47 {
            //     { Fr::drop() }
            // }
            // OP_TRUE

        };
        println!("fflonk.checkpairing_miller_loop = {} bytes", script.len());
        let exec_result = execute_script(script);
        println!("{}", exec_result);
        assert!(exec_result.success);
    }
}
