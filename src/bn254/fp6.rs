use crate::bn254::fp::Fp;
use crate::bn254::fp2::Fp2;
use crate::treepp::{pushable, script, Script};

pub struct Fp6;

impl Fp6 {
    pub fn add(mut a: u32, mut b: u32) -> Script {
        if a < b {
            (a, b) = (b, a);
        }
        script! {
            { Fp2::add(a + 4, b + 4) }
            { Fp2::add(a + 2, b + 4) }
            { Fp2::add(a, b + 4) }
        }
    }

    pub fn double(a: u32) -> Script {
        script! {
            { Fp2::double(a + 4) }
            { Fp2::double(a + 4) }
            { Fp2::double(a + 4) }
        }
    }

    pub fn equalverify() -> Script {
        script! {
            for i in 0..6 {
                { Fp::equalverify(11 - i * 2, 5 - i) }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::bn254::fp::Fp;
    use crate::bn254::fp6::Fp6;
    use crate::execute_script;
    use crate::treepp::*;
    use ark_bn254::Fq6;
    use ark_ff::Field;
    use ark_std::UniformRand;
    use num_bigint::BigUint;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn fp6_push(element: Fq6) -> Script {
        script! {
            for elem in element.to_base_prime_field_elements() {
                { Fp::push_u32_le(&BigUint::from(elem).to_u32_digits()) }
           }
        }
    }

    #[test]
    fn test_bn254_fp6_add() {
        println!("Fp6.add: {} bytes", Fp6::add(6, 0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let a = ark_bn254::Fq6::rand(&mut prng);
            let b = ark_bn254::Fq6::rand(&mut prng);
            let c = &a + &b;

            let script = script! {
                { fp6_push(a) }
                { fp6_push(b) }
                { Fp6::add(6, 0) }
                { fp6_push(c) }
                { Fp6::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_bn254_fp6_double() {
        println!("Fp6.double: {} bytes", Fp6::double(0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let a = ark_bn254::Fq6::rand(&mut prng);
            let c = a.double();

            let script = script! {
                { fp6_push(a) }
                { Fp6::double(0) }
                { fp6_push(c) }
                { Fp6::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}
