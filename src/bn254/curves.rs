use crate::bn254::fp::Fp;
use crate::treepp::{pushable, script, Script};

pub struct G1;

impl G1 {
    pub fn push_generator_affine() -> Script {
        script! {
            { Fp::push_hex("1") }
            { Fp::push_hex("2") }
        }
    }

    pub fn affine_to_projective() -> Script {
        script! {
            { Fp::push_one() }
        }
    }

    pub fn double_projective() -> Script {
        script! {
            { Fp::copy(2) }
            { Fp::square_mod() }
            { Fp::copy(2) }
            { Fp::square_mod() }
            { Fp::copy(0) }
            { Fp::square_mod() }
            { Fp::add_mod(5, 1) }
            { Fp::square_mod() }
            { Fp::copy(1) }
            { Fp::sub_mod(1, 0) }
            { Fp::copy(2) }
            { Fp::sub_mod(1, 0) }
            { Fp::double_mod(0) }
            { Fp::copy(2) }
            { Fp::double_mod(0) }
            { Fp::add_mod(3, 0) }
            { Fp::copy(0) }
            { Fp::square_mod() }
            { Fp::copy(2) }
            { Fp::double_mod(0) }
            { Fp::sub_mod(1, 0) }
            { Fp::copy(0) }
            { Fp::sub_mod(3, 0) }
            { Fp::roll(2) }
            { Fp::mul_mod() }
            { Fp::double_mod(2) }
            { Fp::double_mod(0) }
            { Fp::double_mod(0) }
            { Fp::sub_mod(1, 0) }
            { Fp::roll(2) }
            { Fp::roll(3) }
            { Fp::mul_mod() }
            { Fp::double_mod(0) }
        }
    }

    pub fn nonzero_add_projective() -> Script {
        script! {
            { Fp::copy(3) }
            { Fp::square_mod() }
            { Fp::copy(1) }
            { Fp::square_mod() }
            { Fp::roll(7) }
            { Fp::copy(1) }
            { Fp::mul_mod() }
            { Fp::roll(5) }
            { Fp::copy(3) }
            { Fp::mul_mod() }
            { Fp::copy(2) }
            { Fp::roll(8) }
            { Fp::mul_mod() }
            { Fp::copy(5) }
            { Fp::mul_mod() }
            { Fp::copy(4) }
            { Fp::roll(7) }
            { Fp::mul_mod() }
            { Fp::copy(7) }
            { Fp::mul_mod() }
            { Fp::add_mod(7, 6)}
            { Fp::copy(4) }
            { Fp::sub_mod(4, 0)}
            { Fp::copy(0) }
            { Fp::double_mod(0) }
            { Fp::square_mod() }
            { Fp::copy(1) }
            { Fp::copy(1) }
            { Fp::mul_mod() }
            { Fp::copy(5) }
            { Fp::sub_mod(5, 0) }
            { Fp::double_mod(0) }
            { Fp::roll(6) }
            { Fp::roll(3) }
            { Fp::mul_mod() }
            { Fp::copy(1) }
            { Fp::square_mod() }
            { Fp::copy(3) }
            { Fp::sub_mod(1, 0) }
            { Fp::copy(1) }
            { Fp::double_mod(0) }
            { Fp::sub_mod(1, 0) }
            { Fp::copy(0) }
            { Fp::sub_mod(2, 0) }
            { Fp::roll(2) }
            { Fp::mul_mod() }
            { Fp::roll(5) }
            { Fp::roll(3) }
            { Fp::mul_mod() }
            { Fp::double_mod(0) }
            { Fp::sub_mod(1, 0) }
            { Fp::roll(3) }
            { Fp::square_mod() }
            { Fp::sub_mod(0, 5) }
            { Fp::sub_mod(0, 4) }
            { Fp::roll(3) }
            { Fp::mul_mod() }
        }
    }


    pub fn copy(mut a: u32) -> Script {
        a = a * 3;
        script! {
            { Fp::copy(a + 2) }
            { Fp::copy(a + 2) }
            { Fp::copy(a + 2) }
        }
    }
    
    pub fn roll(mut a: u32) -> Script {
        a = a * 3;
        script! {
            { Fp::roll(a + 2) }
            { Fp::roll(a + 2) }
            { Fp::roll(a + 2) }
        }
    }

    pub fn equalverify() -> Script {
        script! {
            { Fp::equalverify(5, 2) }
            { Fp::equalverify(3, 1) }
            { Fp::equalverify(1, 0) }
        }
    }

    pub fn drop() -> Script {
        script! {
            { Fp::drop() }
            { Fp::drop() }
            { Fp::drop() }
        }
    }

}

#[cfg(test)]
mod test {
    use crate::bn254::curves::G1;
    use crate::bn254::fp::Fp;
    use crate::{execute_script};
    use crate::treepp::{pushable, script, Script};

    use ark_bn254::G1Projective;
    use ark_std::UniformRand;
    use core::ops::Add;
    use num_bigint::BigUint;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn push_g1(point: G1Projective) -> Script {
        script!{
            { Fp::push_u32_le(&BigUint::from(point.x).to_u32_digits()) }
            { Fp::push_u32_le(&BigUint::from(point.y).to_u32_digits()) }
            { Fp::push_u32_le(&BigUint::from(point.z).to_u32_digits()) }
        }
    }

    #[test]
    fn test_copy() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::G1Projective::rand(&mut prng);
            let b = ark_bn254::G1Projective::rand(&mut prng);

            let script = script! {
                { push_g1(a) }
                { push_g1(b) }
                
                // Copy a
                { G1::copy(1) }

                // Push another `a` and then compare
                { push_g1(a) }
                { G1::equalverify() }

                // Drop the original a and b
                { G1::drop() } 
                { G1::drop() } 
                OP_TRUE
            };
            println!("Script size: {}", G1::double_projective().len());
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_roll() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::G1Projective::rand(&mut prng);
            let b = ark_bn254::G1Projective::rand(&mut prng);

            let script = script! {
                { push_g1(a) }
                { push_g1(b) }
                
                // Roll a
                { G1::roll(1) }

                // Push another `a` and then compare
                { push_g1(a) }
                { G1::equalverify() }

                // Drop the original a and b
                { G1::drop() } 
                OP_TRUE
            };
            println!("Script size: {}", G1::double_projective().len());
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_double_projective() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::G1Projective::rand(&mut prng);
            let c = a.add(&a);

            let script = script! {
                { push_g1(a) }
                { G1::double_projective() }
                { push_g1(c) }
                { G1::equalverify() }
                OP_TRUE
            };
            println!("Script size: {}", G1::double_projective().len());
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_nonzero_add_projective() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::G1Projective::rand(&mut prng);
            let b = ark_bn254::G1Projective::rand(&mut prng);
            let c = a.add(&b);

            let script = script! {
                { push_g1(a) }
                { push_g1(b) }
                { G1::nonzero_add_projective() }
                { push_g1(c) }
                { G1::equalverify() }
                OP_TRUE
            };
            println!("Script size: {}", G1::nonzero_add_projective().len());
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }




}
