use crate::bn254::fq::Fq;
use crate::treepp::{pushable, script, Script};
use std::sync::OnceLock;

static G1_DOUBLE_PROJECTIVE: OnceLock<Script> = OnceLock::new();
static G1_NONZERO_ADD_PROJECTIVE: OnceLock<Script> = OnceLock::new();
static G1_SCALAR_MUL_LOOP: OnceLock<Script> = OnceLock::new();

pub struct G1;

impl G1 {
    pub fn push_generator_affine() -> Script {
        script! {
            { Fq::push_hex("1") }
            { Fq::push_hex("2") }
        }
    }

    pub fn affine_to_projective() -> Script {
        script! {
            { Fq::push_one() }
        }
    }

    pub fn double_projective() -> Script {
        G1_DOUBLE_PROJECTIVE
            .get_or_init(|| {
                script! {
                    { Fq::copy(2) }
                    { Fq::square() }
                    { Fq::copy(2) }
                    { Fq::square() }
                    { Fq::copy(0) }
                    { Fq::square() }
                    { Fq::add(5, 1) }
                    { Fq::square() }
                    { Fq::copy(1) }
                    { Fq::sub(1, 0) }
                    { Fq::copy(2) }
                    { Fq::sub(1, 0) }
                    { Fq::double(0) }
                    { Fq::copy(2) }
                    { Fq::double(0) }
                    { Fq::add(3, 0) }
                    { Fq::copy(0) }
                    { Fq::square() }
                    { Fq::copy(2) }
                    { Fq::double(0) }
                    { Fq::sub(1, 0) }
                    { Fq::copy(0) }
                    { Fq::sub(3, 0) }
                    { Fq::roll(2) }
                    { Fq::mul() }
                    { Fq::double(2) }
                    { Fq::double(0) }
                    { Fq::double(0) }
                    { Fq::sub(1, 0) }
                    { Fq::roll(2) }
                    { Fq::roll(3) }
                    { Fq::mul() }
                    { Fq::double(0) }
                }
            })
            .clone()
    }

    pub fn nonzero_add_projective() -> Script {
        G1_NONZERO_ADD_PROJECTIVE
            .get_or_init(|| {
                script! {
                    { Fq::copy(3) }
                    { Fq::square() }
                    { Fq::copy(1) }
                    { Fq::square() }
                    { Fq::roll(7) }
                    { Fq::copy(1) }
                    { Fq::mul() }
                    { Fq::roll(5) }
                    { Fq::copy(3) }
                    { Fq::mul() }
                    { Fq::copy(2) }
                    { Fq::roll(8) }
                    { Fq::mul() }
                    { Fq::copy(5) }
                    { Fq::mul() }
                    { Fq::copy(4) }
                    { Fq::roll(7) }
                    { Fq::mul() }
                    { Fq::copy(7) }
                    { Fq::mul() }
                    { Fq::add(7, 6)}
                    { Fq::copy(4) }
                    { Fq::sub(4, 0)}
                    { Fq::copy(0) }
                    { Fq::double(0) }
                    { Fq::square() }
                    { Fq::copy(1) }
                    { Fq::copy(1) }
                    { Fq::mul() }
                    { Fq::copy(5) }
                    { Fq::sub(5, 0) }
                    { Fq::double(0) }
                    { Fq::roll(6) }
                    { Fq::roll(3) }
                    { Fq::mul() }
                    { Fq::copy(1) }
                    { Fq::square() }
                    { Fq::copy(3) }
                    { Fq::sub(1, 0) }
                    { Fq::copy(1) }
                    { Fq::double(0) }
                    { Fq::sub(1, 0) }
                    { Fq::copy(0) }
                    { Fq::sub(2, 0) }
                    { Fq::roll(2) }
                    { Fq::mul() }
                    { Fq::roll(5) }
                    { Fq::roll(3) }
                    { Fq::mul() }
                    { Fq::double(0) }
                    { Fq::sub(1, 0) }
                    { Fq::roll(3) }
                    { Fq::square() }
                    { Fq::sub(0, 5) }
                    { Fq::sub(0, 4) }
                    { Fq::roll(3) }
                    { Fq::mul() }
                }
            })
            .clone()
    }

    pub fn copy(mut a: u32) -> Script {
        a = a * 3;
        script! {
            { Fq::copy(a + 2) }
            { Fq::copy(a + 2) }
            { Fq::copy(a + 2) }
        }
    }

    pub fn roll(mut a: u32) -> Script {
        a = a * 3;
        script! {
            { Fq::roll(a + 2) }
            { Fq::roll(a + 2) }
            { Fq::roll(a + 2) }
        }
    }

    pub fn equalverify() -> Script {
        script! {
            { Fq::equalverify(5, 2) }
            { Fq::equalverify(3, 1) }
            { Fq::equalverify(1, 0) }
        }
    }

    pub fn drop() -> Script {
        script! {
            { Fq::drop() }
            { Fq::drop() }
            { Fq::drop() }
        }
    }

    pub fn scalar_mul() -> Script {
        let loop_code = G1_SCALAR_MUL_LOOP.get_or_init(|| {
            script! {
                { G1::roll(1) }
                    { G1::double_projective() }
                    { G1::roll(1) }
                    OP_FROMALTSTACK
                    OP_IF
                        { G1::copy(1) }
                        { G1::nonzero_add_projective() }
                    OP_ENDIF
            }
        });

        script! {
            { Fq::convert_to_bits_toaltstack() }

            { G1::push_generator_affine() }

            OP_FROMALTSTACK
            OP_IF
                { G1::copy(1) }
                { G1::nonzero_add_projective() }
            OP_ENDIF

            for i in 1..Fq::N_BITS - 1 {
                { loop_code.clone() }
            }

            { G1::roll(1) }
            { G1::double_projective() }
            OP_FROMALTSTACK
            OP_IF
                { G1::nonzero_add_projective() }
            OP_ELSE
                { G1::drop() }
            OP_ENDIF
        }
    }
}

#[cfg(test)]
mod test {
    use crate::bigint::U254;
    use crate::bn254::curves::G1;
    use crate::bn254::fq::Fq;
    use crate::execute_script;
    use crate::treepp::{pushable, script, Script};

    use ark_bn254::{Fr, G1Projective};
    use ark_std::UniformRand;
    use core::ops::Add;
    use num_bigint::BigUint;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::ops::Mul;

    fn g1_push(point: G1Projective) -> Script {
        script! {
            { Fq::push_u32_le(&BigUint::from(point.x).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(point.y).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(point.z).to_u32_digits()) }
        }
    }

    fn fr_push(scalar: Fr) -> Script {
        script! {
            { U254::push_u32_le(&BigUint::from(scalar).to_u32_digits()) }
        }
    }

    #[test]
    fn test_copy() {
        println!("G1.copy: {} bytes", G1::copy(1).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::G1Projective::rand(&mut prng);
            let b = ark_bn254::G1Projective::rand(&mut prng);

            let script = script! {
                { g1_push(a) }
                { g1_push(b) }

                // Copy a
                { G1::copy(1) }

                // Push another `a` and then compare
                { g1_push(a) }
                { G1::equalverify() }

                // Drop the original a and b
                { G1::drop() }
                { G1::drop() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_roll() {
        println!("G1.roll: {} bytes", G1::roll(1).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::G1Projective::rand(&mut prng);
            let b = ark_bn254::G1Projective::rand(&mut prng);

            let script = script! {
                { g1_push(a) }
                { g1_push(b) }

                // Roll a
                { G1::roll(1) }

                // Push another `a` and then compare
                { g1_push(a) }
                { G1::equalverify() }

                // Drop the original a and b
                { G1::drop() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_double_projective() {
        println!("G1.double: {} bytes", G1::double_projective().len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::G1Projective::rand(&mut prng);
            let c = a.add(&a);

            let script = script! {
                { g1_push(a) }
                { G1::double_projective() }
                { g1_push(c) }
                { G1::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_nonzero_add_projective() {
        println!(
            "G1.nonzero_add: {} bytes",
            G1::nonzero_add_projective().len()
        );
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::G1Projective::rand(&mut prng);
            let b = ark_bn254::G1Projective::rand(&mut prng);
            let c = a.add(&b);

            let script = script! {
                { g1_push(a) }
                { g1_push(b) }
                { G1::nonzero_add_projective() }
                { g1_push(c) }
                { G1::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    // #[test]
    fn test_scalar_mul() {
        println!("G1.scalar_mul: {} bytes", G1::scalar_mul().len());

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let scalar = Fr::rand(&mut prng);

            let p = ark_bn254::G1Projective::rand(&mut prng);
            let q = p.mul(scalar);

            let script = script! {
                { g1_push(p) }
                { fr_push(scalar) }
                { G1::scalar_mul() }
                { g1_push(q) }
                { G1::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}
