use crate::bn254::fp2::Fp2;
use crate::treepp::{pushable, script, Script};

pub struct Fp6;

impl Fp6 {
    pub fn add_mod(mut a: u32, mut b: u32) -> Script {
        if a < b {
            (a, b) = (b, a);
        }
        script! {
            { Fp2::add_mod(a + 4, b + 4) }
            { Fp2::add_mod(a + 2, b + 4) }
            { Fp2::add_mod(a, b + 4) }
        }
    }

    pub fn double_mod(a: u32) -> Script {
        script! {
            { Fp2::double_mod(a + 4) }
            { Fp2::double_mod(a + 4) }
            { Fp2::double_mod(a + 4) }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::bn254::fp::Fp;
    use crate::bn254::fp6::Fp6;
    use crate::execute_script;
    use crate::treepp::{pushable, script};
    use ark_ff::Field;
    use ark_std::UniformRand;
    use num_bigint::BigUint;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_bn254_fp6_add() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let a = ark_bn254::Fq6::rand(&mut prng);
            let b = ark_bn254::Fq6::rand(&mut prng);
            let c = &a + &b;

            let script = script! {
                { Fp::push_u32_le(&BigUint::from(a.c0.c0).to_u32_digits()) }
                { Fp::push_u32_le(&BigUint::from(a.c0.c1).to_u32_digits()) }
                { Fp::push_u32_le(&BigUint::from(a.c1.c0).to_u32_digits()) }
                { Fp::push_u32_le(&BigUint::from(a.c1.c1).to_u32_digits()) }
                { Fp::push_u32_le(&BigUint::from(a.c2.c0).to_u32_digits()) }
                { Fp::push_u32_le(&BigUint::from(a.c2.c1).to_u32_digits()) }
                { Fp::push_u32_le(&BigUint::from(b.c0.c0).to_u32_digits()) }
                { Fp::push_u32_le(&BigUint::from(b.c0.c1).to_u32_digits()) }
                { Fp::push_u32_le(&BigUint::from(b.c1.c0).to_u32_digits()) }
                { Fp::push_u32_le(&BigUint::from(b.c1.c1).to_u32_digits()) }
                { Fp::push_u32_le(&BigUint::from(b.c2.c0).to_u32_digits()) }
                { Fp::push_u32_le(&BigUint::from(b.c2.c1).to_u32_digits()) }
                { Fp6::add_mod(6, 0) }
                { Fp::push_u32_le(&BigUint::from(c.c0.c0).to_u32_digits()) }
                { Fp::push_u32_le(&BigUint::from(c.c0.c1).to_u32_digits()) }
                { Fp::push_u32_le(&BigUint::from(c.c1.c0).to_u32_digits()) }
                { Fp::push_u32_le(&BigUint::from(c.c1.c1).to_u32_digits()) }
                { Fp::push_u32_le(&BigUint::from(c.c2.c0).to_u32_digits()) }
                { Fp::push_u32_le(&BigUint::from(c.c2.c1).to_u32_digits()) }
                { Fp::equalverify(11, 5) }
                { Fp::equalverify(9, 4) }
                { Fp::equalverify(7, 3) }
                { Fp::equalverify(5, 2) }
                { Fp::equalverify(3, 1) }
                { Fp::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_bn254_fp6_double() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let a = ark_bn254::Fq6::rand(&mut prng);
            let c = a.double();

            let script = script! {
                { Fp::push_u32_le(&BigUint::from(a.c0.c0).to_u32_digits()) }
                { Fp::push_u32_le(&BigUint::from(a.c0.c1).to_u32_digits()) }
                { Fp::push_u32_le(&BigUint::from(a.c1.c0).to_u32_digits()) }
                { Fp::push_u32_le(&BigUint::from(a.c1.c1).to_u32_digits()) }
                { Fp::push_u32_le(&BigUint::from(a.c2.c0).to_u32_digits()) }
                { Fp::push_u32_le(&BigUint::from(a.c2.c1).to_u32_digits()) }
                { Fp6::double_mod(0) }
                { Fp::push_u32_le(&BigUint::from(c.c0.c0).to_u32_digits()) }
                { Fp::push_u32_le(&BigUint::from(c.c0.c1).to_u32_digits()) }
                { Fp::push_u32_le(&BigUint::from(c.c1.c0).to_u32_digits()) }
                { Fp::push_u32_le(&BigUint::from(c.c1.c1).to_u32_digits()) }
                { Fp::push_u32_le(&BigUint::from(c.c2.c0).to_u32_digits()) }
                { Fp::push_u32_le(&BigUint::from(c.c2.c1).to_u32_digits()) }
                { Fp::equalverify(11, 5) }
                { Fp::equalverify(9, 4) }
                { Fp::equalverify(7, 3) }
                { Fp::equalverify(5, 2) }
                { Fp::equalverify(3, 1) }
                { Fp::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}
