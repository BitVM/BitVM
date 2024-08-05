use bitcoin::opcodes::all::{OP_ENDIF, OP_FROMALTSTACK, OP_TOALTSTACK};

use crate::bigint::U254;
use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::fq::Fq;
use crate::bn254::fr::Fr;
use crate::treepp::{script, Script};
use std::sync::OnceLock;

static G1_DOUBLE_PROJECTIVE: OnceLock<Script> = OnceLock::new();
static G1_NONZERO_ADD_PROJECTIVE: OnceLock<Script> = OnceLock::new();
static G1_SCALAR_MUL_LOOP: OnceLock<Script> = OnceLock::new();

pub struct G1Projective;

fn restart_if() -> Script {
   script! {
        OP_ENDIF
        OP_FROMALTSTACK
        OP_DUP
        OP_TOALTSTACK
        OP_IF
   }
}

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
            // Check if the third coordinate(z) is zero
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
    
    pub fn nonzero_double_with_if() -> Script {
        G1_DOUBLE_PROJECTIVE
            .get_or_init(|| {
                script! {
                    { Fq::copy(2) }
                    restart_if
                    { Fq::square() }
                    restart_if
                    { Fq::copy(2) }
                    restart_if
                    { Fq::square() }
                    restart_if
                    { Fq::copy(0) }
                    restart_if
                    { Fq::square() }
                    restart_if
                    { Fq::add(5, 1) }
                    restart_if
                    { Fq::square() }
                    restart_if
                    { Fq::copy(1) }
                    restart_if
                    { Fq::sub(1, 0) }
                    restart_if
                    { Fq::copy(2) }
                    restart_if
                    { Fq::sub(1, 0) }
                    restart_if
                    { Fq::double(0) }
                    restart_if
                    { Fq::copy(2) }
                    restart_if
                    { Fq::double(0) }
                    restart_if
                    { Fq::add(3, 0) }
                    restart_if
                    { Fq::copy(0) }
                    restart_if
                    { Fq::square() }
                    restart_if
                    { Fq::copy(2) }
                    restart_if
                    { Fq::double(0) }
                    restart_if
                    { Fq::sub(1, 0) }
                    restart_if
                    { Fq::copy(0) }
                    restart_if
                    { Fq::sub(3, 0) }
                    restart_if
                    { Fq::roll(2) }
                    restart_if
                    { Fq::mul() }
                    restart_if
                    { Fq::double(2) }
                    restart_if
                    { Fq::double(0) }
                    restart_if
                    { Fq::double(0) }
                    restart_if
                    { Fq::sub(1, 0) }
                    restart_if
                    { Fq::roll(2) }
                    restart_if
                    { Fq::roll(3) }
                    restart_if
                    { Fq::mul() }
                    restart_if
                    { Fq::double(0) }
                }
            })
            .clone()
    }

    pub fn double() -> Script {
        script! {
            // Check if the first point is zero
            { G1Projective::is_zero_keep_element(0) }
            OP_NOT
            OP_DUP
            OP_TOALTSTACK
            OP_IF
                // If not, perform a regular addition
                { G1Projective::nonzero_double_with_if() }
            OP_ENDIF
            OP_FROMALTSTACK
            OP_DROP
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
    
    pub fn nonzero_add_with_if() -> Script {
        G1_NONZERO_ADD_PROJECTIVE
            .get_or_init(|| {
                script! {
                    { Fq::copy(3) }
                    { Fq::square() }
                    restart_if
                    { Fq::copy(1) }
                    restart_if
                    { Fq::square() }
                    restart_if
                    { Fq::roll(7) }
                    restart_if
                    { Fq::copy(1) }
                    restart_if
                    { Fq::mul() }
                    restart_if
                    { Fq::roll(5) }
                    restart_if
                    { Fq::copy(3) }
                    restart_if
                    { Fq::mul() }
                    restart_if
                    { Fq::copy(2) }
                    restart_if
                    { Fq::roll(8) }
                    restart_if
                    { Fq::mul() }
                    restart_if
                    { Fq::copy(5) }
                    restart_if
                    { Fq::mul() }
                    restart_if
                    { Fq::copy(4) }
                    restart_if
                    { Fq::roll(7) }
                    restart_if
                    { Fq::mul() }
                    restart_if
                    { Fq::copy(7) }
                    restart_if
                    { Fq::mul() }
                    restart_if
                    { Fq::add(7, 6)}
                    restart_if
                    { Fq::copy(4) }
                    restart_if
                    { Fq::sub(4, 0)}
                    restart_if
                    { Fq::copy(0) }
                    restart_if
                    { Fq::double(0) }
                    restart_if
                    { Fq::square() }
                    restart_if
                    { Fq::copy(1) }
                    restart_if
                    { Fq::copy(1) }
                    restart_if
                    { Fq::mul() }
                    restart_if
                    { Fq::copy(5) }
                    restart_if
                    { Fq::sub(5, 0) }
                    restart_if
                    { Fq::double(0) }
                    restart_if
                    { Fq::roll(6) }
                    restart_if
                    { Fq::roll(3) }
                    restart_if
                    { Fq::mul() }
                    restart_if
                    { Fq::copy(1) }
                    restart_if
                    { Fq::square() }
                    restart_if
                    { Fq::copy(3) }
                    restart_if
                    { Fq::sub(1, 0) }
                    restart_if
                    { Fq::copy(1) }
                    restart_if
                    { Fq::double(0) }
                    restart_if
                    { Fq::sub(1, 0) }
                    restart_if
                    { Fq::copy(0) }
                    restart_if
                    { Fq::sub(2, 0) }
                    restart_if
                    { Fq::roll(2) }
                    restart_if
                    { Fq::mul() }
                    restart_if
                    { Fq::roll(5) }
                    restart_if
                    { Fq::roll(3) }
                    restart_if
                    { Fq::mul() }
                    restart_if
                    { Fq::double(0) }
                    restart_if
                    { Fq::sub(1, 0) }
                    restart_if
                    { Fq::roll(3) }
                    restart_if
                    { Fq::square() }
                    restart_if
                    { Fq::sub(0, 5) }
                    restart_if
                    { Fq::sub(0, 4) }
                    restart_if
                    { Fq::roll(3) }
                    restart_if
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
            // Put if flag on altstack
            OP_DUP OP_NOT OP_TOALTSTACK
            OP_IF
                // If so, drop the zero and return the other summand
                { G1Projective::drop() }
            OP_ELSE
                // Otherwise, check if the second point is zero
                { G1Projective::is_zero_keep_element(1) }
                // Update if flag
                OP_DUP OP_NOT
                OP_FROMALTSTACK
                OP_BOOLAND
                OP_TOALTSTACK
                
                OP_IF
                    // If so, drop the zero and return the other summand
                    { G1Projective::roll(1) }
                    { G1Projective::drop() }
                OP_ENDIF
            OP_ENDIF
            OP_FROMALTSTACK
            OP_DUP
            OP_TOALTSTACK
            OP_IF
                    // Otherwise, perform a regular addition
                    { G1Projective::nonzero_add_with_if() }
            OP_ENDIF
            OP_FROMALTSTACK
            OP_DROP
        }
    }

    pub fn neg() -> Script {
        script! {
            { Fq::neg(1) }
            { Fq::roll(1) }
        }
    }

    pub fn copy(mut a: u32) -> Script {
        a *= 3;
        script! {
            { Fq::copy(a + 2) }
            { Fq::copy(a + 2) }
            { Fq::copy(a + 2) }
        }
    }

    pub fn roll(mut a: u32) -> Script {
        a *= 3;
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
            OP_DUP
            OP_NOT
            OP_TOALTSTACK
            OP_IF
                // If so, drop the point and return the affine::identity
                { G1Projective::drop() }
                { G1Affine::identity() }

            OP_ENDIF
            OP_FROMALTSTACK
            OP_DUP
            OP_TOALTSTACK
            OP_IF
                // 2. Otherwise, check if the point.z is one
                { Fq::is_one_keep_element(0) }

                // Update if flag
                OP_DUP
                OP_NOT
                OP_FROMALTSTACK
                OP_BOOLAND
                OP_TOALTSTACK

                OP_IF
                    // 2.1 If so, drop the p.z.
                    // If Z is one, the point is already normalized, so that: projective.x = affine.x, projective.y = affine.y
                    { Fq::drop() }

                OP_ENDIF
            OP_ENDIF
            OP_FROMALTSTACK
            OP_DUP
            OP_TOALTSTACK
            OP_IF
                    // 2.2 Otherwise, Z is non-one, so it must have an inverse in a field.
                    // conpute Z^-1
                    { Fq::inv_with_if() } // TODO: OP_IF is closed and reopened in here.

                    // compute Z^-2
                    { Fq::copy(0) }
                    { Fq::square() }
                    // compute Z^-3 = Z^-2 * z^-1
                    { Fq::copy(0) }
                    { Fq::roll(2) }
                    { Fq::mul() }

                    // For now, stack: [x, y, z^-2, z^-3]

                    // compute Y/Z^3 = Y * Z^-3
                    { Fq::roll(2) }
                    { Fq::mul() }

                    // compute X/Z^2 = X * Z^-2
                    { Fq::roll(1) }
                    { Fq::roll(2) }
                    { Fq::mul() }

                    // Return (x,y)
                    { Fq::roll(1) }

            OP_ENDIF
            OP_FROMALTSTACK
            OP_DROP
        )
    }

    /// Convert a number to digits
    fn to_digits_helper<const DIGIT_COUNT: usize>(mut number: u32) -> [u8; DIGIT_COUNT] {
        let mut digits: [u8; DIGIT_COUNT] = [0; DIGIT_COUNT];
        for i in 0..DIGIT_COUNT {
            let digit = number % 2;
            number = (number - digit) / 2;
            digits[i] = digit as u8;
        }
        digits
    }

    /// input stack: point_0, scalar_0, ..., point_{TERMS-1}, scalar_{TERMS-1}
    /// output stack: sum of scalar_i * point_i for 0..TERMS
    /// comments: pi -> point_i, si -> scalar_i
    pub fn batched_scalar_mul<const TERMS: usize>() -> Script {
        // comments for 2
        // point_0 scalar_0 point_1 scalar_1
        let s = script! {
            // convert scalars to bit-style
            for i in 0..1 {
                { Fq::roll(4*(TERMS - i - 1) as u32) }

                { Fr::decode_montgomery() }
                { Fr::convert_to_le_bits_toaltstack() }
            }

            for term in 1..TERMS {
                { Fq::roll(4*(TERMS - term - 1) as u32) }

                { Fr::decode_montgomery() }
                { Fr::convert_to_le_bits_toaltstack() }

                for _ in 0..2*Fr::N_BITS {
                    OP_FROMALTSTACK
                }

                // zip scalars
                // [p0, p1, s1_0, s1_1, s1_2, ..., s0_0, s0_1, s0_2, ...]
                for i in 0..Fr::N_BITS {
                    { Fr::N_BITS - i } OP_ROLL
                    for _ in 0..term {OP_DUP OP_ADD} OP_ADD //  s0_0 + s1_0*2
                    OP_TOALTSTACK
                }
            }

            // get some bases (2^TERMS bases) [p0, p1]
            // ouptut: [p1+p0, p1, p0, 0]
            { G1Projective::push_zero() }
            { G1Projective::toaltstack() }

            for i in 1..(u32::pow(2, TERMS as u32)) {
                {G1Projective::push_zero()}
                for (j, mark) in Self::to_digits_helper::<TERMS>(i).iter().enumerate() {
                    if *mark == 1 {
                        { G1Projective::copy(TERMS as u32 - j as u32) }
                        { G1Projective::add() }
                    }
                }
                { G1Projective::toaltstack() }
            }

            for _ in 0..TERMS {
                { G1Projective::drop() }
            }

            for _ in 0..(u32::pow(2, TERMS as u32)) {
                { G1Projective::fromaltstack() }
            }

            { G1Projective::push_zero() } // target
            // [p1+p0, p1, p0, 0, target]
            // for i in 0..Fr::N_BITS {
            for i in 0..Fr::N_BITS {
                OP_FROMALTSTACK // idx = s1_0*2 + s0_0
                OP_1 OP_ADD // idx + 1

                // simulate {G1Projective::pick()}
                for _ in 0..26 { OP_DUP }
                for _ in 0..26 { OP_ADD }
                { 26 } OP_ADD // [p1+p0, p1, p0, 0, target, 27*(idx+1)+26]
                for _ in 0..26 { OP_DUP }
                for _ in 0..26 { OP_TOALTSTACK }
                OP_PICK
                for _ in 0..26 { OP_FROMALTSTACK OP_PICK }

                { G1Projective::add() }
                // jump the last one
                if i != Fr::N_BITS-1 {
                    { G1Projective::double() }
                }
            }

            // clear stack
            { G1Projective::toaltstack() }
            for _ in 0..u32::pow(2, TERMS as u32) {
                { G1Projective::drop() }
            }

            { G1Projective::fromaltstack() }
        };
        s
    }

    // [g1projective, scalar]
    pub fn scalar_mul() -> Script {
        assert_eq!(Fq::N_BITS % 2, 0);

        let loop_code = G1_SCALAR_MUL_LOOP.get_or_init(|| {
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
        });

        script! {
            { Fr::decode_montgomery() }
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

            for _ in 1..(Fq::N_BITS) / 2 {
                { loop_code.clone() }
            }

            { G1Projective::toaltstack() }
            { G1Projective::drop() }
            { G1Projective::drop() }
            { G1Projective::drop() }
            { G1Projective::fromaltstack() }
        }
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
            { Fq::decode_montgomery() }
            // push (q + 1) / 2
            { U254::push_hex(Fq::P_PLUS_ONE_DIV2) }
            // check if y >= (q + 1) / 2
            { U254::greaterthanorequal(1, 0) }
            // modify the most significant byte
            OP_IF
                { 0x80 } OP_ADD
            OP_ENDIF
        }
    }
    // Init stack: [x1,y1,x2,y2)
    pub fn equalverify() -> Script {
        script! {
            { Fq::roll(2) }
            { Fq::equalverify(1, 0) }
            { Fq::equalverify(1, 0) }
        }
    }
    // Input Stack: [x,y]
    // Output Stack: [x,y,z] (z=1)
    pub fn into_projective() -> Script { script!({ Fq::push_one() }) }
}

#[cfg(test)]
mod test {

    use crate::bn254::curves::{G1Affine, G1Projective};
    use crate::bn254::fq::Fq;
    use crate::execute_script;
    use crate::treepp::{script, Script};

    use crate::bn254::fp254impl::Fp254Impl;
    use ark_bn254::Fr;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::{BigInteger, Field, PrimeField};
    use ark_std::{end_timer, start_timer, UniformRand};
    use core::ops::{Add, Mul};
    use num_bigint::BigUint;
    use num_traits::{One, Zero};
    // use std::ops::Mul;

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
            { crate::bn254::fr::Fr::push_u32_le(&BigUint::from(scalar).to_u32_digits()) }
        }
    }

    #[test]
    fn test_affine_identity() {
        let equalverify = G1Affine::equalverify();
        println!("G1Affine.equalverify: {} bytes", equalverify.len());

        for _ in 0..1 {
            let expect = ark_bn254::G1Affine::identity();

            let script = script! {
                { G1Affine::identity() }
                { g1_affine_push(expect) }
                { equalverify.clone() }
                OP_TRUE
            };
            println!("curves::test_affine_identity = {} bytes", script.len());
            let exec_result = execute_script(script);
            assert!(exec_result.success);
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
            println!("curves::test_copy = {} bytes", script.len());
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
            println!("curves::test_roll = {} bytes", script.len());
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
            println!("curves::test_double_projective = {} bytes", script.len());
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
            println!(
                "curves::test_nonzero_add_projective = {} bytes",
                script.len()
            );
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
            println!("curves::test_add = {} bytes", script.len());
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
            println!("curves::test_scalar_mul = {} bytes", script.len());
            let exec_result = execute_script(script);
            // println!("res: {:100}", exec_result);
            assert!(exec_result.success);
        }
    }

    #[test]
    // #[ignore]
    fn test_projective_into_affine() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let scalar = Fr::rand(&mut prng);

            let p_zero = ark_bn254::G1Projective::zero();
            let q_zero = p_zero.into_affine();

            let q_z_one = ark_bn254::G1Affine::rand(&mut prng);
            let p_z_one = ark_bn254::G1Projective::from(q_z_one);

            let p = ark_bn254::G1Projective::rand(&mut prng).mul(scalar);
            assert!(!p.z.is_one() && !p.z.is_zero());
            let q = p.into_affine();
            let z = p.z;
            let z_inv = z.inverse().unwrap();
            let z_inv_pow2 = z_inv.square();
            let z_inv_pow3 = z_inv_pow2.mul(z_inv);

            let start = start_timer!(|| "collect_script");

            let script = script! {
                // When point is zero.
                { g1_projective_push(p_zero) }
                { G1Projective::into_affine() }
                { g1_affine_push(q_zero) }
                { G1Affine::equalverify() }

                // when  p.z = one
                { g1_projective_push(p_z_one) }
                { G1Projective::into_affine() }
                { g1_affine_push(q_z_one) }
                { G1Affine::equalverify() }

                // Otherwise, (X,Y,Z)->(X/z^2, Y/z^3)
                { g1_projective_push(p) }
                { G1Projective::into_affine() }
                { g1_affine_push(q) }
                { G1Affine::equalverify() }
                OP_TRUE
            };
            end_timer!(start);

            println!(
                "curves::test_projective_into_affine = {} bytes",
                script.len()
            );
            let if_interval = script.max_op_if_interval();
            println!(
                "Max interval: {:?} debug info: {}, {}",
                if_interval,
                script.debug_info(if_interval.0),
                script.debug_info(if_interval.1)
            );

            let start = start_timer!(|| "execute_script");
            let exec_result = execute_script(script);
            println!("Exec result: {}", exec_result);
            end_timer!(start);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_batched_scalar_mul2() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        // println!(
        // "script size is {}",
        // G1Projective::batched_scalar_mul::<2>().len()
        // );

        for _ in 0..1 {
            let scalar0 = Fr::rand(&mut prng);
            println!("scalar0 => {}", scalar0);
            let point0 = ark_bn254::G1Projective::rand(&mut prng);
            let scalar1 = Fr::rand(&mut prng);
            println!("scalar1 => {}", scalar1);
            let point1 = ark_bn254::G1Projective::rand(&mut prng);

            // batched_scalar_mul
            let q0 = point0.mul(scalar0);
            let q1 = point1.mul(scalar1);
            let q0q1 = q0.add(q1);

            let script = script! {
                { g1_projective_push(point0) }
                { fr_push(scalar0) }
                { g1_projective_push(point1) }
                { fr_push(scalar1) }
                { G1Projective::batched_scalar_mul::<2>() }
                { g1_projective_push(q0q1) }
                { G1Projective::equalverify() }
                OP_TRUE
            };
            let if_interval = script.max_op_if_interval();
            println!(
                "Max interval: {:?} debug info: {}, {}",
                if_interval,
                script.debug_info(if_interval.0),
                script.debug_info(if_interval.1)
            );

            let exec_result = execute_script(script);
            // println!("res: {:100}", exec_result);
            // println!("res stack length: {}", exec_result.final_stack.len());
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_affine_into_projective() {
        let equalverify = G1Projective::equalverify();
        println!("G1.equalverify: {} bytes", equalverify.len());

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let scalar = Fr::rand(&mut prng);

            let p = ark_bn254::G1Projective::rand(&mut prng).mul(scalar);
            let q = p.into_affine();

            let start = start_timer!(|| "collect_script");

            let script = script! {
                { g1_affine_push(q) }
                { G1Affine::into_projective() }
                { g1_projective_push(p) }
                { equalverify.clone() }
                OP_TRUE
            };
            end_timer!(start);

            println!(
                "curves::test_affine_into_projective = {} bytes",
                script.len()
            );
            let start = start_timer!(|| "execute_script");
            let exec_result = execute_script(script);
            end_timer!(start);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_batched_scalar_mul3() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        // println!(
        // "script size is {}",
        // G1Projective::batched_scalar_mul::<2>().len()
        // );

        for _ in 0..1 {
            let scalar0 = Fr::rand(&mut prng);
            println!("scalar0 => {}", scalar0);
            let point0 = ark_bn254::G1Projective::rand(&mut prng);

            let scalar1 = Fr::rand(&mut prng);
            println!("scalar1 => {}", scalar1);
            let point1 = ark_bn254::G1Projective::rand(&mut prng);

            let scalar2 = Fr::rand(&mut prng);
            println!("scalar2 => {}", scalar2);
            let point2 = ark_bn254::G1Projective::rand(&mut prng);

            // let scalar3 = Fr::rand(&mut prng);
            // println!("scalar3 => {}", scalar3);
            // let point3 = ark_bn254::G1Projective::rand(&mut prng);

            // let scalar4 = Fr::rand(&mut prng);
            // println!("scalar4 => {}", scalar4);
            // let point4 = ark_bn254::G1Projective::rand(&mut prng);

            // batched_scalar_mul
            let q0 = point0.mul(scalar0);
            let q1 = point1.mul(scalar1);
            let q2 = point2.mul(scalar2);
            // let q3 = point3.mul(scalar3);
            // let q4 = point4.mul(scalar4);
            let sum = q0.add(q1).add(q2);

            let script = script! {
                { g1_projective_push(point0) }
                { fr_push(scalar0) }
                { g1_projective_push(point1) }
                { fr_push(scalar1) }
                { g1_projective_push(point2) }
                { fr_push(scalar2) }
                // { g1_projective_push(point3) }
                // { fr_push(scalar3) }
                // { g1_projective_push(point4) }
                // { fr_push(scalar4) }

                { G1Projective::batched_scalar_mul::<3>() }
                { g1_projective_push(sum) }
                { G1Projective::equalverify() }
                OP_TRUE
            };
            // println!("script length: {}", script.len());
            let exec_result = execute_script(script);
            // println!("max stack items: {}", exec_result.stats.max_nb_stack_items);
            // println!("res stack length: {}", exec_result.final_stack.len());
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_projective_equalverify() {
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
            println!("curves::test_equalverify = {} bytes", script.len());
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_affine_equalverify() {
        let equalverify = G1Affine::equalverify();
        println!("G1Affine.equalverify: {} bytes", equalverify.len());

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let scalar = Fr::rand(&mut prng);

            let p = ark_bn254::G1Projective::rand(&mut prng).mul(scalar);
            let q = p.into_affine();

            let script = script! {
                { g1_affine_push(p.into_affine()) }
                { g1_affine_push(q) }
                { equalverify.clone() }
                OP_TRUE
            };
            println!("curves::test_equalverify = {} bytes", script.len());
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
            println!("curves::test_affine_is_on_curve = {} bytes", script.len());
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
                { Fq::push_hex(Fq::P_PLUS_ONE_DIV2) }
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
