use crate::bn254::fq::Fq;
use crate::bn254::fq2::Fq2;
use crate::bn254::fq6::Fq6;
use crate::treepp::{pushable, script, Script};

pub struct Fq12;

static FQ12_FROBENIUS_COEFF_C1: [[&'static str; 2]; 12] = [
    ["1", "0"],
    [
        "1284b71c2865a7dfe8b99fdd76e68b605c521e08292f2176d60b35dadcc9e470",
        "246996f3b4fae7e6a6327cfe12150b8e747992778eeec7e5ca5cf05f80f362ac",
    ],
    [
        "30644e72e131a0295e6dd9e7e0acccb0c28f069fbb966e3de4bd44e5607cfd49",
        "0",
    ],
    [
        "19dc81cfcc82e4bbefe9608cd0acaa90894cb38dbe55d24ae86f7d391ed4a67f",
        "abf8b60be77d7306cbeee33576139d7f03a5e397d439ec7694aa2bf4c0c101",
    ],
    [
        "30644e72e131a0295e6dd9e7e0acccb0c28f069fbb966e3de4bd44e5607cfd48",
        "0",
    ],
    [
        "757cab3a41d3cdc072fc0af59c61f302cfa95859526b0d41264475e420ac20f",
        "ca6b035381e35b618e9b79ba4e2606ca20b7dfd71573c93e85845e34c4a5b9c",
    ],
    [
        "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd46",
        "0",
    ],
    [
        "1ddf9756b8cbf849cf96a5d90a9accfd3b2f4c893f42a9166615563bfbb318d7",
        "bfab77f2c36b843121dc8b86f6c4ccf2307d819d98302a771c39bb757899a9b",
    ],
    ["59e26bcea0d48bacd4f263f1acdb5c4f5763473177fffffe", "0"],
    [
        "1687cca314aebb6dc866e529b0d4adcd0e34b703aa1bf84253b10eddb9a856c8",
        "2fb855bcd54a22b6b18456d34c0b44c0187dc4add09d90a0c58be1eae3bc3c46",
    ],
    ["59e26bcea0d48bacd4f263f1acdb5c4f5763473177ffffff", "0"],
    [
        "290c83bf3d14634db120850727bb392d6a86d50bd34b19b929bc44b896723b38",
        "23bd9e3da9136a739f668e1adc9ef7f0f575ec93f71a8df953c846338c32a1ab",
    ],
];

impl Fq12 {
    pub fn add(mut a: u32, mut b: u32) -> Script {
        if a < b {
            (a, b) = (b, a);
        }
        script! {
            { Fq6::add(a + 6, b + 6) }
            { Fq6::add(a, b + 6) }
        }
    }

    pub fn double(a: u32) -> Script {
        script! {
            { Fq6::double(a + 6) }
            { Fq6::double(a + 6) }
        }
    }

    pub fn equalverify() -> Script {
        script! {
            for i in 0..12 {
                { Fq::equalverify(23 - i * 2, 11 - i) }
            }
        }
    }

    pub fn mul_fq6_by_nonresidue() -> Script {
        script! {
            { Fq6::mul_fq2_by_nonresidue() }
            { Fq2::roll(4) }
            { Fq2::roll(4) }
        }
    }

    pub fn mul(mut a: u32, mut b: u32) -> Script {
        if a < b {
            (a, b) = (b, a);
        }

        // The degree-12 extension on BN254 Fq6 is under the polynomial z^2 - y

        script! {
            { Fq6::copy(a + 6) }
            { Fq6::copy(b + 12) }
            { Fq6::mul(6, 0) }
            { Fq6::copy(a + 6) }
            { Fq6::copy(b + 12) }
            { Fq6::mul(6, 0) }
            { Fq6::add(a + 12, a + 18) }
            { Fq6::add(b + 18, b + 24) }
            { Fq6::mul(6, 0) }
            { Fq6::copy(12) }
            { Fq6::copy(12) }
            { Fq12::mul_fq6_by_nonresidue() }
            { Fq6::add(6, 0) }
            { Fq6::add(18, 12)}
            { Fq6::sub(12, 0) }
        }
    }

    // input:
    //   p   (12 elements)
    //   c0  (2 elements)
    //   c3  (2 elements)
    //   c4  (2 elements)
    pub fn mul_by_034() -> Script {
        script! {
            // copy p.c1, c3, c4
            { Fq6::copy(6) }
            { Fq2::copy(8) }
            { Fq2::copy(8) }

            // compute b = p.c1 * (c3, c4)
            { Fq6::mul_by_01() }

            // copy p.c0, c0
            { Fq6::copy(18) }
            { Fq2::copy(16) }
            { Fq6::mul_by_fp2() }

            // compute beta * b
            { Fq6::copy(6) }
            { Fq12::mul_fq6_by_nonresidue() }

            // compute final c0 = a + beta * b
            { Fq6::copy(6) }
            { Fq6::add(6, 0) }

            // compute e = p.c0 + p.c1
            { Fq6::add(30, 24) }

            // compute c0 + c3
            { Fq2::add(28, 26) }

            // roll c4
            { Fq2::roll(26) }

            // update e = e * (c0 + c3, c4)
            { Fq6::mul_by_01() }

            // sum a and b
            { Fq6::add(18, 12) }

            // compute final c1 = e - (a + b)
            { Fq6::sub(6, 0) }
        }
    }

    pub fn copy(a: u32) -> Script {
        script! {
            { Fq6::copy(a + 6) }
            { Fq6::copy(a + 6) }
        }
    }

    pub fn roll(a: u32) -> Script {
        script! {
            { Fq6::roll(a + 6) }
            { Fq6::roll(a + 6) }
        }
    }

    pub fn square() -> Script {
        // https://eprint.iacr.org/2009/565.pdf
        // based on the implementation in arkworks-rs, fq12_2over3over2.rs

        let sqr = || {
            script! {
                // compute tmp = ra * rb
                { Fq2::copy(2) }
                { Fq2::copy(2) }
                { Fq2::mul(2, 0) }

                // compute ra + rb
                { Fq2::copy(4) }
                { Fq2::copy(4) }
                { Fq2::add(2, 0) }

                // compute ra + beta * rb
                { Fq2::roll(4) }
                { Fq6::mul_fq2_by_nonresidue() }
                { Fq2::roll(6) }
                { Fq2::add(2, 0) }

                // compute (ra + rb) * (ra + beta * rb) - tmp - tmp * beta
                { Fq2::mul(2, 0) }
                { Fq2::copy(2) }
                { Fq6::mul_fq2_by_nonresidue() }
                { Fq2::copy(4) }
                { Fq2::add(2, 0) }
                { Fq2::sub(2, 0) }
                { Fq2::double(2) }
            }
        };

        script! {
            // copy r0 = c0.c0 and r1 = c1.c1
            { Fq2::copy(10) }
            { Fq2::copy(4) }

            // compute t0 = r0^2 + r1^2 * beta, t1 = 2r0r1
            { sqr() }

            // copy r2 = c1.c0 and r3 = c0.c2
            { Fq2::copy(8) }
            { Fq2::copy(12) }

            // compute t2 = r2^2 + r3^2 * beta, t3 = 2r2r3
            { sqr() }

            // copy r4 = c0.c1 and r5 = c1.c2
            { Fq2::copy(16) }
            { Fq2::copy(10) }

            // compute t4 = r4^2 + r5^2 * beta, t5 = 242r5
            { sqr() }

            // z0 = 2 * (t0 - r0) + t0
            { Fq2::copy(10) }
            { Fq2::roll(24) }
            { Fq2::sub(2, 0) }
            { Fq2::double(0) }
            { Fq2::roll(12) }
            { Fq2::add(2, 0) }

            // z4 = 2 * (t2 - r4) + t2
            { Fq2::copy(8) }
            { Fq2::roll(22) }
            { Fq2::sub(2, 0) }
            { Fq2::double(0) }
            { Fq2::roll(10) }
            { Fq2::add(2, 0) }

            // z3 = 2 * (t4 - r3) + t4
            { Fq2::copy(6) }
            { Fq2::roll(20) }
            { Fq2::sub(2, 0) }
            { Fq2::double(0) }
            { Fq2::roll(8) }
            { Fq2::add(2, 0) }

            // z2 = 2 * (beta * t5 + r2) + (beta * t5)
            { Fq2::roll(6) }
            { Fq6::mul_fq2_by_nonresidue() }
            { Fq2::copy(0) }
            { Fq2::roll(18) }
            { Fq2::add(2, 0) }
            { Fq2::double(0) }
            { Fq2::add(2, 0) }

            // z1 = 2 * (t1 + r1) + t1
            { Fq2::copy(10) }
            { Fq2::roll(16) }
            { Fq2::add(2, 0) }
            { Fq2::double(0) }
            { Fq2::roll(12) }
            { Fq2::add(2, 0) }

            // z5 = 2 * (t3 + r5) + t5
            { Fq2::copy(10) }
            { Fq2::roll(14) }
            { Fq2::add(2, 0) }
            { Fq2::double(0) }
            { Fq2::roll(12) }
            { Fq2::add(2, 0) }
        }
    }

    pub fn inv() -> Script {
        script! {
            // copy c1
            { Fq6::copy(0) }

            // compute beta * v1 = beta * c1^2
            { Fq6::square() }
            { Fq12::mul_fq6_by_nonresidue() }

            // copy c0
            { Fq6::copy(12) }

            // compute v0 = c0^2 + beta * v1
            { Fq6::square() }
            { Fq6::sub(0, 6) }

            // compute inv v0
            { Fq6::inv() }

            // dup inv v0
            { Fq6::copy(0) }

            // compute c0
            { Fq6::roll(18) }
            { Fq6::mul(6, 0) }

            // compute c1
            { Fq6::roll(12) }
            { Fq6::roll(12) }
            { Fq6::mul(6, 0) }
            { Fq6::neg(0) }
        }
    }

    pub fn frobenius_map(i: usize) -> Script {
        script! {
            { Fq6::roll(6) }
            { Fq6::frobenius_map(i) }
            { Fq6::roll(6) }
            { Fq6::frobenius_map(i) }
            { Fq::push_hex(FQ12_FROBENIUS_COEFF_C1[i % FQ12_FROBENIUS_COEFF_C1.len()][0]) }
            { Fq::push_hex(FQ12_FROBENIUS_COEFF_C1[i % FQ12_FROBENIUS_COEFF_C1.len()][1]) }
            { Fq6::mul_by_fp2() }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::bn254::fq::Fq;
    use crate::bn254::fq12::Fq12;
    use crate::treepp::*;
    use ark_ff::{CyclotomicMultSubgroup, Field};
    use ark_std::UniformRand;
    use core::ops::Mul;
    use num_bigint::BigUint;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn fq2_push(element: ark_bn254::Fq2) -> Script {
        script! {
            { Fq::push_u32_le(&BigUint::from(element.c0).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(element.c1).to_u32_digits()) }
        }
    }

    fn fq12_push(element: ark_bn254::Fq12) -> Script {
        script! {
            for elem in element.to_base_prime_field_elements() {
                { Fq::push_u32_le(&BigUint::from(elem).to_u32_digits()) }
           }
        }
    }

    #[test]
    fn test_bn254_fq12_add() {
        println!("Fq12.add: {} bytes", Fq12::add(12, 0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let a = ark_bn254::Fq12::rand(&mut prng);
            let b = ark_bn254::Fq12::rand(&mut prng);
            let c = &a + &b;

            let script = script! {
                { fq12_push(a) }
                { fq12_push(b) }
                { Fq12::add(12, 0) }
                { fq12_push(c) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_bn254_fq12_double() {
        println!("Fq12.double: {} bytes", Fq12::double(0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let a = ark_bn254::Fq12::rand(&mut prng);
            let c = a.double();

            let script = script! {
                { fq12_push(a) }
                { Fq12::double(0) }
                { fq12_push(c) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_bn254_fq12_mul() {
        println!("Fq12.mul: {} bytes", Fq12::mul(12, 0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::Fq12::rand(&mut prng);
            let b = ark_bn254::Fq12::rand(&mut prng);
            let c = a.mul(&b);

            let script = script! {
                { fq12_push(a) }
                { fq12_push(b) }
                { Fq12::mul(12, 0) }
                { fq12_push(c) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_bn254_fq12_square() {
        println!("Fq12.sqr: {} bytes", Fq12::square().len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::Fq12::rand(&mut prng);
            let c = a.cyclotomic_square();

            let script = script! {
                { fq12_push(a) }
                { Fq12::square() }
                { fq12_push(c) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_bn254_fq12_mul_by_034() {
        println!("Fq12.mul_by_034: {} bytes", Fq12::mul_by_034().len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::Fq12::rand(&mut prng);
            let c0 = ark_bn254::Fq2::rand(&mut prng);
            let c3 = ark_bn254::Fq2::rand(&mut prng);
            let c4 = ark_bn254::Fq2::rand(&mut prng);
            let mut b = a.clone();
            b.mul_by_034(&c0, &c3, &c4);

            let script = script! {
                { fq12_push(a) }
                { fq2_push(c0) }
                { fq2_push(c3) }
                { fq2_push(c4) }
                { Fq12::mul_by_034() }
                { fq12_push(b) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_bn254_fq12_inv() {
        println!("Fq12.inv: {} bytes", Fq12::inv().len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::Fq12::rand(&mut prng);
            let b = a.inverse().unwrap();

            let script = script! {
                { fq12_push(a) }
                { Fq12::inv() }
                { fq12_push(b) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_bn254_fq12_frobenius_map() {
        println!("Fq12.frobenius_map: {} bytes", Fq12::frobenius_map(0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            for i in 0..12 {
                let a = ark_bn254::Fq12::rand(&mut prng);
                let b = a.frobenius_map(i);

                let script = script! {
                    { fq12_push(a) }
                    { Fq12::frobenius_map(i) }
                    { fq12_push(b) }
                    { Fq12::equalverify() }
                    OP_TRUE
                };
                let exec_result = execute_script(script);
                assert!(exec_result.success);
            }
        }
    }
}
