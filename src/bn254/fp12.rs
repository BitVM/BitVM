use crate::bn254::fp6::Fp6;
use crate::bn254::fp::Fp;
use crate::treepp::{pushable, script, Script};

pub struct Fp12;

impl Fp12 {
    pub fn add(mut a: u32, mut b: u32) -> Script {
        if a < b {
            (a, b) = (b, a);
        }
        script! {
            { Fp6::add(a + 6, b + 6) }
            { Fp6::add(a, b + 6) }
        }
    }

    pub fn double(a: u32) -> Script {
        script! {
            { Fp6::double(a + 6) }
            { Fp6::double(a + 6) }
        }
    }

    pub fn equalverify() -> Script {
        script!{
            for i in 0..12 {
                { Fp::equalverify(23 - i * 2, 11 - i) }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::bn254::fp::Fp;
    use crate::bn254::fp12::Fp12;
    use crate::execute_script;
    use crate::treepp::*;
    use ark_bn254::Fq12;
    use ark_ff::Field;
    use ark_std::UniformRand;
    use num_bigint::BigUint;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn fp12_push(element: Fq12) -> Script {
        script!{
            for elem in element.to_base_prime_field_elements() {
                { Fp::push_u32_le(&BigUint::from(elem).to_u32_digits()) }
           }
        }
    }

    #[test]
    fn test_bn254_fp12_add() {
        println!("Fp12.add: {} bytes", Fp12::add(12, 0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let a = ark_bn254::Fq12::rand(&mut prng);
            let b = ark_bn254::Fq12::rand(&mut prng);
            let c = &a + &b;

            let script = script! {
                { fp12_push(a) }
                { fp12_push(b) }
                { Fp12::add(12, 0) }
                { fp12_push(c) }
                { Fp12::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_bn254_fp12_double() {
        println!("Fp12.double: {} bytes", Fp12::double(0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let a = ark_bn254::Fq12::rand(&mut prng);
            let c = a.double();

            let script = script! {
                { fp12_push(a) }
                { Fp12::double(0) }
                { fp12_push(c) }
                { Fp12::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}
