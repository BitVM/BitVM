use crate::bn254::fp::Fp;
use crate::treepp::{pushable, script, Script};

pub struct Fp2;

impl Fp2 {
    pub fn add(mut a: u32, mut b: u32) -> Script {
        if a < b {
            (a, b) = (b, a);
        }

        script! {
            { Fp::add_mod(a + 1, b + 1) }
            { Fp::add_mod(a, b + 1) }
        }
    }

    pub fn double(a: u32) -> Script {
        script! {
            { Fp::double_mod(a + 1) }
            { Fp::double_mod(a + 1) }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::bn254::fp::Fp;
    use crate::bn254::fp2::Fp2;
    use crate::execute_script;
    use crate::treepp::*;
    use ark_bn254::Fq2;
    use ark_ff::Field;
    use ark_std::UniformRand;
    use num_bigint::BigUint;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;


    fn fp2_push(element: Fq2) -> Script {
        script!{
            { Fp::push_u32_le(&BigUint::from(element.c0).to_u32_digits()) }
            { Fp::push_u32_le(&BigUint::from(element.c1).to_u32_digits()) }
        }
    }

    #[test]
    fn test_bn254_fp2_add() {
        println!("Fp2.add: {} bytes", Fp2::add(2, 0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let a = ark_bn254::Fq2::rand(&mut prng);
            let b = ark_bn254::Fq2::rand(&mut prng);
            let c = &a + &b;

            let script = script! {
                { fp2_push(a) }
                { fp2_push(b) }
                { Fp2::add(2, 0) }
                { fp2_push(c) }
                { Fp::equalverify(3, 1) }
                { Fp::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);

            let script = script! {
                { fp2_push(a) }
                { fp2_push(b) }
                { Fp2::add(0, 2) }
                { fp2_push(c) }
                { Fp::equalverify(3, 1) }
                { Fp::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_bn254_fp2_double() {
        println!("Fp2.double: {} bytes", Fp2::double(0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let a = ark_bn254::Fq2::rand(&mut prng);
            let c = a.double();

            let script = script! {
                { fp2_push(a) }
                { Fp2::double(0) }
                { fp2_push(c) }
                { Fp::equalverify(3, 1) }
                { Fp::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}
