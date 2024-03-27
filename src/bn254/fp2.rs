use crate::bn254::fp::Fp;
use crate::treepp::{pushable, script, Script};

pub struct Fp2;

impl Fp2 {
    pub fn add_mod(a: u32, b: u32) -> Script {
        script! {
            { Fp::add_mod(a + 1, b + 1) }
            if a < b {
                { Fp::add_mod(a + 1, b) }
            } else {
                { Fp::add_mod(a, b + 1) }
            }
        }
    }

    pub fn double_mod(a: u32) -> Script {
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
    use crate::treepp::{pushable, script};
    use ark_ff::Field;
    use ark_std::UniformRand;
    use num_bigint::BigUint;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_bn254_fp2_add() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let a = ark_bn254::Fq2::rand(&mut prng);
            let b = ark_bn254::Fq2::rand(&mut prng);
            let c = &a + &b;

            let script = script! {
                { Fp::push_u32_le(&BigUint::from(a.c0).to_u32_digits()) }
                { Fp::push_u32_le(&BigUint::from(a.c1).to_u32_digits()) }
                { Fp::push_u32_le(&BigUint::from(b.c0).to_u32_digits()) }
                { Fp::push_u32_le(&BigUint::from(b.c1).to_u32_digits()) }
                { Fp2::add_mod(2, 0) }
                { Fp::push_u32_le(&BigUint::from(c.c0).to_u32_digits()) }
                { Fp::push_u32_le(&BigUint::from(c.c1).to_u32_digits()) }
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
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let a = ark_bn254::Fq2::rand(&mut prng);
            let c = a.double();

            let script = script! {
                { Fp::push_u32_le(&BigUint::from(a.c0).to_u32_digits()) }
                { Fp::push_u32_le(&BigUint::from(a.c1).to_u32_digits()) }
                { Fp2::double_mod(0) }
                { Fp::push_u32_le(&BigUint::from(c.c0).to_u32_digits()) }
                { Fp::push_u32_le(&BigUint::from(c.c1).to_u32_digits()) }
                { Fp::equalverify(3, 1) }
                { Fp::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(
                exec_result.success,
                "{:?} {:?}",
                exec_result.error, exec_result.final_stack
            );
        }
    }
}
