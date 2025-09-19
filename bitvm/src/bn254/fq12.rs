use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::fq::Fq;
use crate::bn254::fq2::Fq2;
use crate::bn254::fq6::Fq6;
use crate::bn254::utils::Hint;
use crate::treepp::{script, Script};
use ark_ff::{Field, Fp12Config};
use num_bigint::BigUint;

pub struct Fq12;

impl Fq12 {
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

    pub fn drop() -> Script {
        script! {
            { Fq6::drop() }
            { Fq6::drop() }
        }
    }

    pub fn toaltstack() -> Script {
        script! {
            { Fq6::toaltstack() }
            { Fq6::toaltstack() }
        }
    }

    pub fn fromaltstack() -> Script {
        script! {
            { Fq6::fromaltstack() }
            { Fq6::fromaltstack() }
        }
    }

    pub fn push(a: ark_bn254::Fq12) -> Script {
        script! {
            for elem in a.to_base_prime_field_elements() {
                { Fq::push_u32_le(&BigUint::from(elem).to_u32_digits()) }
           }
        }
    }

    pub fn push_zero() -> Script {
        script! {
            { Fq6::push_zero() }
            { Fq6::push_zero() }
        }
    }

    pub fn equalverify() -> Script {
        script! {
            for i in 0..12 {
                { Fq::equalverify(23 - i * 2, 11 - i) }
            }
        }
    }

    pub fn add(mut a: u32, mut b: u32) -> Script {
        if a < b {
            (a, b) = (b, a);
        }
        script! {
            { Fq6::add(a + 6, b + 6) }
            { Fq6::add(a, b + 6) }
        }
    }

    pub fn sub(a: u32, b: u32) -> Script {
        if a > b {
            script! {
                { Fq6::sub(a + 6, b + 6) }
                { Fq6::sub(a, b + 6) }
            }
        } else {
            script! {
                { Fq6::sub(a + 6, b + 6) }
                { Fq6::sub(a + 6, b) }
            }
        }
    }

    pub fn double(a: u32) -> Script {
        script! {
            { Fq6::double(a + 6) }
            { Fq6::double(a + 6) }
        }
    }

    pub fn mul_fq6_by_nonresidue() -> Script {
        script! {
            { Fq6::mul_fq2_by_nonresidue() }
            { Fq2::roll(4) }
            { Fq2::roll(4) }
        }
    }

    pub fn hinted_mul(
        mut a_depth: u32,
        mut a: ark_bn254::Fq12,
        mut b_depth: u32,
        mut b: ark_bn254::Fq12,
    ) -> (Script, Vec<Hint>) {
        if a_depth < b_depth {
            (a_depth, b_depth) = (b_depth, a_depth);
            (a, b) = (b, a);
        }
        assert_ne!(a_depth, b_depth);
        let mut hints = Vec::new();

        let (hinted_script1, hint1) = Fq6::hinted_mul(6, a.c0, 0, b.c0);
        let (hinted_script2, hint2) = Fq6::hinted_mul(6, a.c1, 0, b.c1);
        let (hinted_script3, hint3) = Fq6::hinted_mul(6, a.c0 + a.c1, 0, b.c0 + b.c1);

        let script = script! {
            { Fq6::copy(a_depth + 6) }
            { Fq6::copy(b_depth + 12) }
            { hinted_script1 }
            { Fq6::copy(a_depth + 6) }
            { Fq6::copy(b_depth + 12) }
            { hinted_script2 }
            { Fq6::add(a_depth + 12, a_depth + 18) }
            { Fq6::add(b_depth + 18, b_depth + 24) }
            { hinted_script3 }
            { Fq6::copy(12) }
            { Fq6::copy(12) }
            { Fq12::mul_fq6_by_nonresidue() }
            { Fq6::add(6, 0) }
            { Fq6::add(18, 12) }
            { Fq6::sub(12, 0) }
        };

        hints.extend(hint1);
        hints.extend(hint2);
        hints.extend(hint3);

        (script, hints)
    }

    // input:
    //   p   (12 elements)
    //   c3  (2 elements)
    //   c4  (2 elements)
    // where c0 is a trival value ONE, so we can ignore it
    pub fn hinted_mul_by_34(
        p: ark_bn254::Fq12,
        c3: ark_bn254::Fq2,
        c4: ark_bn254::Fq2,
    ) -> (Script, Vec<Hint>) {
        let mut hints = Vec::new();

        let (hinted_script1, hint1) = Fq6::hinted_mul_by_01(p.c1, c3, c4);
        let (hinted_script2, hint2) =
            Fq6::hinted_mul_by_01(p.c0 + p.c1, c3 + ark_bn254::Fq2::ONE, c4);

        let script = script! {
            // copy p.c1, c3, c4
            { Fq6::copy(4) }
            { Fq2::copy(8) }
            { Fq2::copy(8) }
            // [p, c3, c4, p.c1, c3, c4]

            // compute b = p.c1 * (c3, c4)
            { hinted_script1 }
            // [p, c3, c4, b]

            // a = p.c0 * c0, where c0 = 1
            { Fq6::copy(16) }
            // [p, c3, c4, b, a]

            // compute beta * b
            { Fq6::copy(6) }
            { Fq12::mul_fq6_by_nonresidue() }
            // [p, c3, c4, b, a, beta * b]

            // compute final c0 = a + beta * b
            { Fq6::copy(6) }
            { Fq6::add(6, 0) }
            // [p, c3, c4, b, a, c0]

            // compute e = p.c0 + p.c1
            { Fq6::add(28, 22) }
            // [c3, c4, b, a, c0, e]

            // compute c0 + c3, where c0 = 1
            { Fq2::roll(26) }
            { Fq2::push_one() }
            { Fq2::add(2, 0) }
            // [c4, b, a, c0, e, 1 + c3]

            // update e = e * (c0 + c3, c4), where c0 = 1
            { Fq2::roll(26) }
            { hinted_script2 }
            // [b, a, c0, e]

            // sum a and b
            { Fq6::add(18, 12) }
            // [c0, e, a + b]

            // compute final c1 = e - (a + b)
            { Fq6::sub(6, 0) }
        };

        hints.extend(hint1);
        hints.extend(hint2);

        (script, hints)
    }

    pub fn hinted_square(a: ark_bn254::Fq12) -> (Script, Vec<Hint>) {
        let mut hints = Vec::new();

        let (hinted_script1, hints1) = Fq6::hinted_mul(12, a.c1, 18, a.c0);
        let mut beta_ac1 = a.c1;
        ark_bn254::Fq12Config::mul_fp6_by_nonresidue_in_place(&mut beta_ac1);
        let (hinted_script2, hints2) = Fq6::hinted_mul(12, a.c0 + a.c1, 6, a.c0 + beta_ac1);

        let script = script! {
            // v0 = c0 + c1
            { Fq6::copy(6) }
            { Fq6::copy(6) }
            { Fq6::add(6, 0) }
            // v3 = c0 + beta * c1
            { Fq6::copy(6) }
            { Fq12::mul_fq6_by_nonresidue() }
            { Fq6::copy(18) }
            { Fq6::add(0, 6) }
            // v2 = c0 * c1
            { hinted_script1 }
            // v0 = v0 * v3
            { hinted_script2 }
            // final c0 = v0 - (beta + 1) * v2
            { Fq6::copy(6) }
            { Fq12::mul_fq6_by_nonresidue() }
            { Fq6::copy(12) }
            { Fq6::add(6, 0) }
            { Fq6::sub(6, 0) }
            // final c1 = 2 * v2
            { Fq6::double(6) }
        };

        hints.extend(hints1);
        hints.extend(hints2);

        (script, hints)
    }

    pub fn hinted_frobenius_map(i: usize, a: ark_bn254::Fq12) -> (Script, Vec<Hint>) {
        let mut hints = Vec::new();

        let (hinted_script1, hint1) = Fq6::hinted_frobenius_map(i, a.c0);
        let (hinted_script2, hint2) = Fq6::hinted_frobenius_map(i, a.c1);
        let (hinted_script3, hint3) = Fq6::hinted_mul_by_fp2_constant(
            a.c1.frobenius_map(i),
            &ark_bn254::Fq12Config::FROBENIUS_COEFF_FP12_C1
                [i % ark_bn254::Fq12Config::FROBENIUS_COEFF_FP12_C1.len()],
        );

        let script = script! {
            { Fq6::roll(6) }
            { hinted_script1 }
            { Fq6::roll(6) }
            { hinted_script2 }
            { hinted_script3 }
        };

        hints.extend(hint1);
        hints.extend(hint2);
        hints.extend(hint3);

        (script, hints)
    }

    pub fn check_validity() -> Script {
        script! {
            for _ in 0..2 { 
                { Fq6::check_validity() }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::bn254::fq12::Fq12;
    use crate::bn254::fq2::Fq2;
    use crate::treepp::*;
    use ark_ff::AdditiveGroup;
    use ark_ff::Field;
    use ark_std::UniformRand;
    use core::ops::Mul;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_bn254_fq12_add() {
        println!("Fq12.add: {} bytes", Fq12::add(12, 0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let a = ark_bn254::Fq12::rand(&mut prng);
            let b = ark_bn254::Fq12::rand(&mut prng);
            let c = a + b;

            let script = script! {
                { Fq12::push(a) }
                { Fq12::push(b) }
                { Fq12::add(12, 0) }
                { Fq12::push(c) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            run(script);
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
                { Fq12::push(a) }
                { Fq12::double(0) }
                { Fq12::push(c) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_bn254_fq12_hinted_mul() {
        let mut prng: ChaCha20Rng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::Fq12::rand(&mut prng);
            let b = ark_bn254::Fq12::rand(&mut prng);
            let c = a.mul(&b);

            let (hinted_mul, hints) = Fq12::hinted_mul(12, a, 0, b);
            println!("Fq12.hinted_mul: {} bytes", hinted_mul.len());

            let script = script! {
                for hint in hints {
                    { hint.push() }
                }
                { Fq12::push(a) }
                { Fq12::push(b) }
                { hinted_mul.clone() }
                { Fq12::push(c) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_bn254_fq12_hinted_mul_by_34() {
        let mut prng: ChaCha20Rng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::Fq12::rand(&mut prng);
            let c0 = ark_bn254::Fq2::ONE;
            let c3 = ark_bn254::Fq2::rand(&mut prng);
            let c4 = ark_bn254::Fq2::rand(&mut prng);
            let mut b = a;
            b.mul_by_034(&c0, &c3, &c4);
            let (hinted_mul_by_34, hints) = Fq12::hinted_mul_by_34(a, c3, c4);
            println!("Fq12.hinted_mul_by_34: {} bytes", hinted_mul_by_34.len());

            let script = script! {
                for hint in hints {
                    { hint.push() }
                }
                { Fq12::push(a) }
                { Fq2::push(c3) }
                { Fq2::push(c4) }
                { hinted_mul_by_34.clone() }
                { Fq12::push(b) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_bn254_fq12_hinted_square() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::Fq12::rand(&mut prng);
            let b = a.square();

            let (hinted_square, hints) = Fq12::hinted_square(a);
            println!("Fq12.hinted_square: {} bytes", hinted_square.len());

            let script = script! {
                for hint in hints {
                    { hint.push() }
                }
                { Fq12::push(a) }
                { hinted_square.clone() }
                { Fq12::push(b) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_bn254_fq12_hinted_frobenius_map() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            for i in 0..12 {
                let a = ark_bn254::Fq12::rand(&mut prng);
                let b = a.frobenius_map(i);

                let (hinted_frobenius_map, hints) = Fq12::hinted_frobenius_map(i, a);
                println!(
                    "Fq12.hinted_frobenius_map({}): {} bytes",
                    i,
                    hinted_frobenius_map.len()
                );

                let script = script! {
                    for hint in hints {
                        { hint.push() }
                    }
                    { Fq12::push(a) }
                    { hinted_frobenius_map.clone() }
                    { Fq12::push(b) }
                    { Fq12::equalverify() }
                    OP_TRUE
                };
                run(script);
            }
        }
    }
}
