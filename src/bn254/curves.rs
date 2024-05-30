use crate::bigint::U254;
use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::fq::Fq;
use crate::bn254::fr::Fr;
use crate::treepp::{pushable, script, Script};
use std::sync::OnceLock;

static G1_DOUBLE_PROJECTIVE: OnceLock<Script> = OnceLock::new();
static G1_NONZERO_ADD_PROJECTIVE: OnceLock<Script> = OnceLock::new();
static G1_SCALAR_MUL_LOOP: OnceLock<Script> = OnceLock::new();

pub struct G1Projective;

impl G1Projective {
    pub fn push_generator() -> Script {
        script! {
            { Fq::push_one() }
            { Fq::push_hex("2") }
            { Fq::push_one() }
        }
    }

    pub fn push_zero() -> Script {
        script! {
            { Fq::push_zero() }
            { Fq::push_zero() }
            { Fq::push_zero() }
        }
    }

    pub fn is_zero_keep_element(a: u32) -> Script {
        script! {
            // Check if the third coordinate is zero
            { Fq::is_zero_keep_element(a * 3) }
        }
    }

    pub fn nonzero_double() -> Script {
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

    pub fn double() -> Script {
        script! {
            // Check if the first point is zero
            { G1Projective::is_zero_keep_element(0) }
            OP_NOTIF
                // If not, perform a regular addition
                { G1Projective::nonzero_double() }
            OP_ENDIF
            // Otherwise, nothing to do
        }
    }

    pub fn nonzero_add() -> Script {
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

    pub fn add() -> Script {
        script! {
            // Handle zeros

            // Check if the first point is zero
            { G1Projective::is_zero_keep_element(0) }
            OP_IF
                // If so, drop the zero and return the other summand
                { G1Projective::drop() }
            OP_ELSE
                // Otherwise, check if the second point is zero
                { G1Projective::is_zero_keep_element(1) }
                OP_IF
                    // If so, drop the zero and return the other summand
                    { G1Projective::roll(1) }
                    { G1Projective::drop() }
                OP_ELSE
                    // Otherwise, perform a regular addition
                    { G1Projective::nonzero_add() }
                OP_ENDIF
            OP_ENDIF
        }
    }

    pub fn neg() -> Script {
        script! {
            { Fq::neg(1) }
            { Fq::roll(1) }
        }
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
            { Fq::copy(3) }
            { Fq::square() }
            { Fq::roll(4) }
            { Fq::copy(1) }
            { Fq::mul() }

            { Fq::copy(2) }
            { Fq::square() }
            { Fq::roll(3) }
            { Fq::copy(1) }
            { Fq::mul() }

            { Fq::roll(7) }
            { Fq::roll(2) }
            { Fq::mul() }
            { Fq::roll(5) }
            { Fq::roll(4) }
            { Fq::mul() }
            { Fq::equalverify(1, 0) }

            { Fq::roll(3) }
            { Fq::roll(1) }
            { Fq::mul() }
            { Fq::roll(2) }
            { Fq::roll(2) }
            { Fq::mul() }
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

    pub fn toaltstack() -> Script {
        script! {
            { Fq::toaltstack() }
            { Fq::toaltstack() }
            { Fq::toaltstack() }
        }
    }

    pub fn fromaltstack() -> Script {
        script! {
            { Fq::fromaltstack() }
            { Fq::fromaltstack() }
            { Fq::fromaltstack() }
        }
    }

    // Input Stack: [x, y, z]
    // Output Stack: [x/z^2, y/z^3]
    pub fn into_affine() -> Script {
        script!(
            // Handle zeros

            // 1. Check if the first point is zero
            { G1Projective::is_zero_keep_element(0) }
            OP_IF
                // If so, drop the point and return the affine::identity
                { G1Projective::drop() }
                {G1Affine::identity()}
            OP_ELSE
                // 2. Otherwise, check if the point.z is one
                { Fq::is_one_keep_element(0) }
                OP_IF
                    // 2.1 If so, drop the p.z.
                    // If Z is one, the point is already normalized, so that: projective.x = affine.x, projective.y = affine.y
                    { Fq::drop() }

                OP_ELSE
                    // 2.2 Otherwise, Z is non-one, so it must have an inverse in a field.
                    // conpute Z^-1
                    { Fq::inv() }
                    // compute Z^-2
                    { Fq::copy(0) }
                    { Fq::square() }
                    // compute Z^-3 = Z^-2 * z^-1
                    { Fq::copy(0) }
                    {Fq::roll(2)}
                    { Fq::mul() }

                    // For now, stack: [x, y, z^-2, z^-3]

                    // compute Y/Z^3 = Y * Z^-3
                    {Fq::roll(2)}
                    { Fq::mul() }

                    // compute X/Z^2 = X * Z^-2
                    {Fq::roll(1)}
                    {Fq::roll(2)}
                    { Fq::mul() }

                    // Return (x,y)
                    {Fq::roll(1)}

                OP_ENDIF
            OP_ENDIF
        )
    }

    pub fn scalar_mul() -> Script {
        assert_eq!(Fq::N_BITS % 2, 0);

        let loop_code = G1_SCALAR_MUL_LOOP
            .get_or_init(|| {
                script! {
                    { G1Projective::double() }
                    { G1Projective::double() }

                    OP_FROMALTSTACK OP_FROMALTSTACK
                    OP_IF
                        OP_IF
                            { G1Projective::copy(1) }
                        OP_ELSE
                            { G1Projective::copy(3) }
                        OP_ENDIF
                        OP_TRUE
                    OP_ELSE
                        OP_IF
                            { G1Projective::copy(2) }
                            OP_TRUE
                        OP_ELSE
                            OP_FALSE
                        OP_ENDIF
                    OP_ENDIF
                    OP_IF
                        { G1Projective::add() }
                    OP_ENDIF
                }
            })
            .as_bytes()
            .to_vec();

        let mut script_bytes = vec![];

        script_bytes.extend(
            script! {
                { Fr::convert_to_le_bits_toaltstack() }

                { G1Projective::copy(0) }
                { G1Projective::double() }
                { G1Projective::copy(1) }
                { G1Projective::copy(1) }
                { G1Projective::add() }

                { G1Projective::push_zero() }

                OP_FROMALTSTACK OP_FROMALTSTACK
                OP_IF
                    OP_IF
                        { G1Projective::copy(1) }
                    OP_ELSE
                        { G1Projective::copy(3) }
                    OP_ENDIF
                    OP_TRUE
                OP_ELSE
                    OP_IF
                        { G1Projective::copy(2) }
                        OP_TRUE
                    OP_ELSE
                        OP_FALSE
                    OP_ENDIF
                OP_ENDIF
                OP_IF
                    { G1Projective::add() }
                OP_ENDIF
            }
            .as_bytes(),
        );

        for _ in 1..(Fq::N_BITS) / 2 {
            script_bytes.extend(loop_code.clone());
        }

        script_bytes.extend_from_slice(
            script! {
                { G1Projective::toaltstack() }
                { G1Projective::drop() }
                { G1Projective::drop() }
                { G1Projective::drop() }
                { G1Projective::fromaltstack() }
            }
            .as_bytes(),
        );
        Script::from(script_bytes)
    }
}

pub struct G1Affine;

impl G1Affine {
    pub fn identity() -> Script {
        script! {
            { Fq::push_zero() }
            { Fq::push_zero() }
        }
    }

    pub fn is_on_curve() -> Script {
        script! {
            { Fq::copy(1) }
            { Fq::square() }
            { Fq::roll(2) }
            { Fq::mul() }
            { Fq::push_hex("3") }
            { Fq::add(1, 0) }
            { Fq::roll(1) }
            { Fq::square() }
            { Fq::equal(1, 0) }
        }
    }

    pub fn convert_to_compressed() -> Script {
        script! {
            // move y to the altstack
            { Fq::toaltstack() }
            // convert x into bytes
            { Fq::convert_to_be_bytes() }
            // bring y to the main stack
            { Fq::fromaltstack() }
            // push (q + 1) / 2
            { Fq::push_hex(Fq::P_PLUS_ONE_DIV2) }
            // check if y >= (q + 1) / 2
            { U254::greaterthanorequal(1, 0) }
            // modify the most significant byte
            OP_IF
                { 0x80 } OP_ADD
            OP_ENDIF
        }
    }
}

#[cfg(test)]
mod test {
    use crate::bigint::U254;
    use crate::bn254::curves::{G1Affine, G1Projective};
    use crate::bn254::fq::Fq;
    use crate::execute_script;
    use crate::treepp::{pushable, script, Script};

    use crate::bn254::fp254impl::Fp254Impl;
    use ark_bn254::Fr;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::{BigInteger, PrimeField};
    use ark_std::UniformRand;
    use core::ops::{Add, Mul};
    use num_bigint::BigUint;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::ops::Neg;

    fn g1_projective_push(point: ark_bn254::G1Projective) -> Script {
        script! {
            { Fq::push_u32_le(&BigUint::from(point.x).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(point.y).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(point.z).to_u32_digits()) }
        }
    }

    fn g1_affine_push(point: ark_bn254::G1Affine) -> Script {
        script! {
            { Fq::push_u32_le(&BigUint::from(point.x).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(point.y).to_u32_digits()) }
        }
    }

    fn fr_push(scalar: Fr) -> Script {
        script! {
            { U254::push_u32_le(&BigUint::from(scalar).to_u32_digits()) }
        }
    }

    #[test]
    fn test_copy() {
        println!("G1.copy: {} bytes", G1Projective::copy(1).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::G1Projective::rand(&mut prng);
            let b = ark_bn254::G1Projective::rand(&mut prng);

            let script = script! {
                { g1_projective_push(a) }
                { g1_projective_push(b) }

                // Copy a
                { G1Projective::copy(1) }

                // Push another `a` and then compare
                { g1_projective_push(a) }
                { G1Projective::equalverify() }

                // Drop the original a and b
                { G1Projective::drop() }
                { G1Projective::drop() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_roll() {
        println!("G1.roll: {} bytes", G1Projective::roll(1).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::G1Projective::rand(&mut prng);
            let b = ark_bn254::G1Projective::rand(&mut prng);

            let script = script! {
                { g1_projective_push(a) }
                { g1_projective_push(b) }

                // Roll a
                { G1Projective::roll(1) }

                // Push another `a` and then compare
                { g1_projective_push(a) }
                { G1Projective::equalverify() }

                // Drop the original a and b
                { G1Projective::drop() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_double_projective() {
        println!("G1.double: {} bytes", G1Projective::double().len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::G1Projective::rand(&mut prng);
            let c = a.add(&a);

            let script = script! {
                { g1_projective_push(a) }
                { G1Projective::double() }
                { g1_projective_push(c) }
                { G1Projective::equalverify() }
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
            G1Projective::nonzero_add().len()
        );
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::G1Projective::rand(&mut prng);
            let b = ark_bn254::G1Projective::rand(&mut prng);
            let c = a.add(&b);

            let script = script! {
                { g1_projective_push(a) }
                { g1_projective_push(b) }
                { G1Projective::nonzero_add() }
                { g1_projective_push(c) }
                { G1Projective::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_add() {
        println!("G1.nonzero_add: {} bytes", G1Projective::add().len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::G1Projective::rand(&mut prng);
            let b = ark_bn254::G1Projective::rand(&mut prng);
            let c = a.add(&b);

            let script = script! {
                // Test random a + b = c
                { g1_projective_push(a) }
                { g1_projective_push(b) }
                { G1Projective::add() }
                { g1_projective_push(c) }
                { G1Projective::equalverify() }

                // Test random a + 0 = a
                { g1_projective_push(a) }
                { G1Projective::push_zero() }
                { G1Projective::add() }
                { g1_projective_push(a) }
                { G1Projective::equalverify() }

                // Test random 0 + a = a
                { G1Projective::push_zero() }
                { g1_projective_push(a) }
                { G1Projective::add() }
                { g1_projective_push(a) }
                { G1Projective::equalverify() }

                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_scalar_mul() {
        let scalar_mul = G1Projective::scalar_mul();
        println!("G1.scalar_mul: {} bytes", scalar_mul.len());

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let scalar = Fr::rand(&mut prng);

            let p = ark_bn254::G1Projective::rand(&mut prng);
            let q = p.mul(scalar);

            let script = script! {
                { g1_projective_push(p) }
                { fr_push(scalar) }
                { scalar_mul.clone() }
                { g1_projective_push(q) }
                { G1Projective::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_equalverify() {
        let equalverify = G1Projective::equalverify();
        println!("G1.equalverify: {} bytes", equalverify.len());

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let scalar = Fr::rand(&mut prng);

            let p = ark_bn254::G1Projective::rand(&mut prng).mul(scalar);
            let q = p.into_affine();

            let script = script! {
                { g1_projective_push(p) }
                { Fq::push_u32_le(&BigUint::from(q.x).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(q.y).to_u32_digits()) }
                { Fq::push_one() }
                { equalverify.clone() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_affine_is_on_curve() {
        let affine_is_on_curve = G1Affine::is_on_curve();
        println!("G1.affine_is_on_curve: {} bytes", affine_is_on_curve.len());

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..3 {
            let p = ark_bn254::G1Affine::rand(&mut prng);

            let script = script! {
                { g1_affine_push(p) }
                { affine_is_on_curve.clone() }
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);

            let script = script! {
                { g1_affine_push(p) }
                { Fq::double(0) }
                { affine_is_on_curve.clone() }
                OP_NOT
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_convert_to_compressed() {
        let convert_to_compressed_script = G1Affine::convert_to_compressed();
        println!(
            "G1.convert_to_compressed_script: {} bytes",
            convert_to_compressed_script.len()
        );

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..3 {
            let mut p = ark_bn254::G1Affine::rand(&mut prng);
            if p.y()
                .unwrap()
                .gt(&ark_bn254::Fq::from_bigint(ark_bn254::Fq::MODULUS_MINUS_ONE_DIV_TWO).unwrap())
            {
                p = p.neg();
            }

            let bytes = p.x().unwrap().into_bigint().to_bytes_be();

            let script = script! {
                { g1_affine_push(p) }
                { convert_to_compressed_script.clone() }
                for i in 0..32 {
                    { bytes[i] } OP_EQUALVERIFY
                }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }

        for _ in 0..3 {
            let mut p = ark_bn254::G1Affine::rand(&mut prng);
            if p.y()
                .unwrap()
                .into_bigint()
                .le(&ark_bn254::Fq::MODULUS_MINUS_ONE_DIV_TWO)
            {
                p = p.neg();
            }
            assert!(p
                .y()
                .unwrap()
                .into_bigint()
                .gt(&ark_bn254::Fq::MODULUS_MINUS_ONE_DIV_TWO));

            let bytes = p.x().unwrap().into_bigint().to_bytes_be();

            let script = script! {
                { g1_affine_push(p) }
                { convert_to_compressed_script.clone() }
                { bytes[0] | 0x80 }
                OP_EQUALVERIFY
                for i in 1..32 {
                    { bytes[i] } OP_EQUALVERIFY
                }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }

        for _ in 0..3 {
            let p = ark_bn254::G1Affine::rand(&mut prng);
            let bytes = p.x().unwrap().into_bigint().to_bytes_be();

            let script = script! {
                { Fq::push_u32_le(&BigUint::from(p.x).to_u32_digits()) }
                { Fq::push_hex(&Fq::P_PLUS_ONE_DIV2) }
                { convert_to_compressed_script.clone() }
                { bytes[0] | 0x80 }
                OP_EQUALVERIFY
                for i in 1..32 {
                    { bytes[i] } OP_EQUALVERIFY
                }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}
