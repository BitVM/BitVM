use crate::bigint::add::limb_add_carry;
use crate::bigint::bits::limb_to_be_bits;
use crate::bigint::sub::limb_sub_borrow;
use crate::bigint::u29x9::{
    u29x9_mul_karazuba, u29x9_mul_karazuba_imm, u29x9_mulhi_karazuba_imm, u29x9_mullo_karazuba_imm,
    u29x9_square,
};
use crate::bigint::U254;
use crate::bn254::fq::Fq;
use crate::bn254::utils::fq_to_bits;
use crate::pseudo::OP_256MUL;
use crate::treepp::*;
use ark_ff::{BigInteger, PrimeField};
use bitcoin_script::script;
use num_bigint::{BigInt, BigUint};
use num_traits::{Num, One};
use std::ops::{Add, Div, Mul, Rem, Shl};
use std::str::FromStr;
use std::sync::OnceLock;

use super::utils::{fq_push_not_montgomery, Hint};

pub trait Fp254Impl {
    const MODULUS: &'static str;
    const MONTGOMERY_ONE: &'static str;
    const N_LIMBS: u32 = U254::N_LIMBS;
    const N_BITS: u32 = U254::N_BITS;

    // Modulus as 30-bit limbs
    const MODULUS_LIMBS: [u32; U254::N_LIMBS as usize];
    const MODULUS_INV_261: [u32; U254::N_LIMBS as usize];

    const P_PLUS_ONE_DIV2: &'static str;
    const TWO_P_PLUS_ONE_DIV3: &'static str;
    const P_PLUS_TWO_DIV3: &'static str;

    const ADD_ONCELOCK: OnceLock<Script> = OnceLock::new();
    const SUB_ONCELOCK: OnceLock<Script> = OnceLock::new();
    const MUL_ONCELOCK: OnceLock<Script> = OnceLock::new();

    type ConstantType: PrimeField;

    #[inline]
    fn copy(a: u32) -> Script { U254::copy(a) }

    #[inline]
    fn roll(a: u32) -> Script { U254::roll(a) }

    #[inline]
    fn drop() -> Script { U254::drop() }

    #[inline]
    fn zip(a: u32, b: u32) -> Script { U254::zip(a, b) }

    #[inline]
    fn push_u32_le(v: &[u32]) -> Script {
        let r = BigUint::from_str_radix(Self::MONTGOMERY_ONE, 16).unwrap();
        let p = BigUint::from_str_radix(Self::MODULUS, 16).unwrap();
        script! {
            { U254::push_u32_le(&BigUint::from_slice(v).mul(r).rem(p).to_u32_digits()) }
        }
    }

    #[inline]
    fn push_u32_le_not_montgomery(v: &[u32]) -> Script {
        script! {
            { U254::push_u32_le(&BigUint::from_slice(v).to_u32_digits()) }
        }
    }

    #[inline]
    fn equal(a: u32, b: u32) -> Script { U254::equal(a, b) }

    #[inline]
    fn equalverify(a: u32, b: u32) -> Script { U254::equalverify(a, b) }

    #[inline]
    fn push_dec(dec_string: &str) -> Script {
        let v = BigUint::from_str_radix(dec_string, 10).unwrap();
        let r = BigUint::from_str_radix(Self::MONTGOMERY_ONE, 16).unwrap();
        let p = BigUint::from_str_radix(Self::MODULUS, 16).unwrap();
        script! {
            { U254::push_u32_le(&v.mul(r).rem(p).to_u32_digits()) }
        }
    }

    #[inline]
    fn push_dec_not_montgomery(dec_string: &str) -> Script {
        let v = BigUint::from_str_radix(dec_string, 10).unwrap();
        script! {
            { U254::push_u32_le(&v.to_u32_digits()) }
        }
    }

    #[inline]
    fn push_hex(hex_string: &str) -> Script {
        let v = BigUint::from_str_radix(hex_string, 16).unwrap();
        let r = BigUint::from_str_radix(Self::MONTGOMERY_ONE, 16).unwrap();
        let p = BigUint::from_str_radix(Self::MODULUS, 16).unwrap();
        script! {
            { U254::push_u32_le(&v.mul(r).rem(p).to_u32_digits()) }
        }
    }

    #[inline]
    fn push_hex_not_montgomery(hex_string: &str) -> Script {
        let v = BigUint::from_str_radix(hex_string, 16).unwrap();
        script! {
            { U254::push_u32_le(&v.to_u32_digits()) }
        }
    }

    #[inline]
    fn convert_to_be_bits() -> Script { U254::convert_to_be_bits() }

    #[inline]
    fn convert_to_be_bits_toaltstack() -> Script { U254::convert_to_be_bits_toaltstack() }

    #[inline]
    fn convert_to_le_bits() -> Script { U254::convert_to_le_bits() }

    #[inline]
    fn convert_to_le_bits_toaltstack() -> Script { U254::convert_to_le_bits_toaltstack() }

    #[inline]
    fn push_modulus() -> Script { U254::push_hex(Self::MODULUS) }

    #[inline]
    fn push_zero() -> Script { U254::push_zero() }

    #[inline]
    fn push_one() -> Script { U254::push_hex(Self::MONTGOMERY_ONE) }

    #[inline]
    fn push_one_not_montgomery() -> Script { U254::push_one() }

    fn decode_montgomery() -> Script {
        script! {
            // a ⋅ p⁻¹
            { u29x9_mullo_karazuba_imm(Self::MODULUS_INV_261) }
            // ⋯ ❨A₂₆₀…₀⋅P⁻¹₂₆₀…₀❩₂₆₀…₀

            // ❨a ⋅ p⁻¹❩ ⋅ p
            { u29x9_mulhi_karazuba_imm(Self::MODULUS_LIMBS) }
            // ⋯ ❨❨A₂₆₀…₀⋅P⁻¹₂₆₀…₀❩₂₆₀…₀⋅P₂₆₀…₀❩₅₂₁…₂₆₁

            // - ❨a ⋅ p⁻¹❩ ⋅ p
            { Self::neg(0) }
            // ⋯ ❨A₂₆₀…₀⋅2⁻²⁶¹❩₂₆₀…₀
        }
    }

    // A + B mod M
    // Ci⁺ overflow carry bit (A+B)
    // Ci⁻ overflow carry bit (A-B)
    fn add(a: u32, b: u32) -> Script {
        let binding = Self::ADD_ONCELOCK;
        let add_script = binding.get_or_init(|| {
            script! {
                // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ B₁ A₀ B₀
                { 0x20000000 }
                // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ B₁ A₀ B₀ 2²⁹

                // A₀ + B₀
                limb_add_carry
                // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ B₁ 2²⁹ C₀⁺ A₀+B₀
                OP_DUP
                OP_TOALTSTACK
                // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ B₁ 2²⁹ C₀⁺ A₀+B₀ | A₀+B₀
                OP_ROT
                // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ B₁ C₀⁺ A₀+B₀ 2²⁹
                { Self::MODULUS_LIMBS[0] }
                OP_SWAP
                // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ B₁ C₀⁺ A₀+B₀ M₀ 2²⁹
                limb_sub_borrow
                OP_TOALTSTACK
                // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ B₁ C₀⁺ 2²⁹ C₀⁻ | (A₀+B₀)-M₀

                // from     A₁      + B₁        + carry_0
                //   to     A{N-2}  + B{N-2}    + carry_{N-3}
                for i in 1..Self::N_LIMBS-1 {
                    OP_2SWAP
                    // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ 2²⁹ C₀⁻ B₁ C₀⁺
                    OP_ADD
                    // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ 2²⁹ C₀⁻ B₁+C₀⁺
                    OP_2SWAP
                    // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ C₀⁻ B₁+C₀⁺ A₁ 2²⁹
                    limb_add_carry
                    OP_DUP
                    OP_TOALTSTACK
                    // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ C₀⁻ 2²⁹ C₁⁺ (B₁+C₀)+A₁ | (B₁+C₀)+A₁
                    OP_2SWAP
                    OP_SWAP
                    // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ C₁⁺ (B₁+C₀)+A₁ 2²⁹ C₀⁻
                    { Self::MODULUS_LIMBS[i as usize] }
                    // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ C₁⁺ (B₁+C₀)+A₁ 2²⁹ C₀⁻ M₁
                    OP_ADD
                    // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ C₁⁺ (B₁+C₀)+A₁ 2²⁹ C₀⁻+M₁
                    OP_ROT
                    OP_SWAP
                    OP_ROT
                    // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ C₁⁺ (B₁+C₀)+A₁ C₀⁻+M₁ 2²⁹
                    limb_sub_borrow
                    OP_TOALTSTACK
                    // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ C₁⁺ 2²⁹ C₁⁻ | ((B₁+C₀)+A₁)-(C₀⁻+M₁)
                }
                // ⋯ A₈ B₈ C₇⁺ 2²⁹ C₇⁻
                OP_2SWAP
                OP_ADD
                // ⋯ A₈ 2²⁹ C₇⁻ B₈+C₇⁺
                OP_2SWAP
                OP_ROT
                OP_ROT
                // ⋯ C₇⁻ 2²⁹ B₈+C₇⁺ A₈
                OP_ADD
                // ⋯ C₇⁻ 2²⁹ (B₈+C₇⁺)+A₈
                OP_DUP
                OP_TOALTSTACK
                OP_ROT
                // ⋯ 2²⁹ (B₈+C₇⁺)+A₈ C₇⁻
                { *Self::MODULUS_LIMBS.last().unwrap() }
                // ⋯ 2²⁹ (B₈+C₇⁺)+A₈ C₇⁻ M₈
                OP_ADD
                OP_ROT
                // ⋯ (B₈+C₇⁺)+A₈ C₇⁻+M₈ 2²⁹
                limb_sub_borrow
                OP_TOALTSTACK
                // ⋯ 2²⁹ C₈⁻ | ((B₈+C₇⁺)+A₈)-(C₇⁻+M₈)
                OP_NIP
                OP_DUP

                { script! {
                    // ⋯ C₈⁻ C₈⁻
                    OP_IF
                        OP_FROMALTSTACK
                        OP_DROP
                    OP_ENDIF

                    OP_FROMALTSTACK
                    // ⋯ (B₈+C₇⁺)+A₈ C₈⁻ | ((B₇+C₆⁺)+A₇)-(C₆⁻+M₇)
                    // ⋯ ((B₈+C₇⁺)+A₈)-(C₇⁻+M₈) C₈⁻ | (B₈+C₇⁺)+A₈
                    for _ in 0..Self::N_LIMBS-1 {
                        OP_FROMALTSTACK  OP_DROP
                        OP_FROMALTSTACK
                    }
                    // ⋯ (B₈+C₇⁺)+A₈ (B₇+C₆⁺)+A₇ ... (B₂+C₁⁺)+A₂ (B₁+C₀⁺)+A₁ A₀+B₀ C₈⁻
                    // ⋯ ((B₈+C₇⁺)+A₈)-(C₇⁻+M₈) ... (A₀+B₀)-M₀ C₈⁻ | A₀+B₀
                    { Self::N_LIMBS }
                    OP_ROLL
                    OP_NOTIF
                        OP_FROMALTSTACK
                        OP_DROP
                    OP_ENDIF
                    // ⋯ (B₈+C₇⁺)+A₈ (B₇+C₆⁺)+A₇ ... (B₁+C₀⁺)+A₁ A₀+B₀
                    // ⋯ ((B₈+C₇⁺)+A₈)-(C₇⁻+M₈) ... (A₀+B₀)-M₀
                }.add_stack_hint(-2, Self::N_LIMBS as i32 - 2).add_altstack_hint(-2 * Self::N_LIMBS as i32, -2 * Self::N_LIMBS as i32)}
            }
        });
        script! {
            { Self::zip(a, b) }
            { add_script.clone() }
        }
    }

    fn neg(a: u32) -> Script {
        script! {
            // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ A₁ A₀ ⋯
            { Self::roll(a) }
            // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ A₁ A₀
            { Self::MODULUS_LIMBS[0] } OP_SWAP { 0x20000000 }
            limb_sub_borrow OP_TOALTSTACK
            // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ A₁ 2²⁹ C₀⁻ | M₀-A₀ ⋯
            OP_ROT OP_ADD
            // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ 2²⁹ C₀⁻+A₁
            { Self::MODULUS_LIMBS[1] } OP_SWAP OP_ROT
            limb_sub_borrow OP_TOALTSTACK
            // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ 2²⁹ C₁⁻ | M₁-(C₀⁻+A₁) ⋯
            OP_ROT OP_ADD
            // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ 2²⁹ C₁⁻+A₂
            { Self::MODULUS_LIMBS[2] } OP_SWAP OP_ROT
            limb_sub_borrow OP_TOALTSTACK
            // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ 2²⁹ C₂⁻ | M₂-(C₁⁻+A₂) ⋯
            OP_ROT OP_ADD
            // ⋯ A₈ A₇ A₆ A₅ A₄ 2²⁹ C₂⁻+A₃
            { Self::MODULUS_LIMBS[3] } OP_SWAP OP_ROT
            limb_sub_borrow OP_TOALTSTACK
            // ⋯ A₈ A₇ A₆ A₅ A₄ 2²⁹ C₃⁻ | M₃-(C₂⁻+A₃) ⋯
            OP_ROT OP_ADD
            // ⋯ A₈ A₇ A₆ A₅ 2²⁹ C₃⁻+A₄
            { Self::MODULUS_LIMBS[4] } OP_SWAP OP_ROT
            limb_sub_borrow OP_TOALTSTACK
            // ⋯ A₈ A₇ A₆ A₅ 2²⁹ C₄⁻ | M₄-(C₃⁻+A₄) ⋯
            OP_ROT OP_ADD
            // ⋯ A₈ A₇ A₆ 2²⁹ C₄⁻+A₅
            { Self::MODULUS_LIMBS[5] } OP_SWAP OP_ROT
            limb_sub_borrow OP_TOALTSTACK
            // ⋯ A₈ A₇ A₆ 2²⁹ C₅⁻ | M₅-(C₄⁻+A₅) ⋯
            OP_ROT OP_ADD
            // ⋯ A₈ A₇ 2²⁹ C₅⁻+A₆
            { Self::MODULUS_LIMBS[6] } OP_SWAP OP_ROT
            limb_sub_borrow OP_TOALTSTACK
            // ⋯ A₈ A₇ 2²⁹ C₆⁻ | M₆-(C₅⁻+A₆) ⋯
            OP_ROT OP_ADD
            // ⋯ A₈ 2²⁹ C₆⁻+A₇
            { Self::MODULUS_LIMBS[7] } OP_SWAP OP_ROT
            limb_sub_borrow OP_TOALTSTACK
            // ⋯ A₈ 2²⁹ C₇⁻ | M₇-(C₆⁻+A₇) ⋯
            OP_NIP OP_ADD
            // ⋯ C₇⁻+A₈
            { Self::MODULUS_LIMBS[8] } OP_SWAP OP_SUB
            // ⋯ M₈-(C₇⁻+A₈)
            OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK
            OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK
        }
    }

    // A - B mod M
    // Ci⁻ overflow carry bit (A-B)
    // Ci⁺ overflow carry bit (A+B)
    fn sub(a: u32, b: u32) -> Script {
        let binding = Self::SUB_ONCELOCK;
        let sub_script = binding.get_or_init(|| {
            script! {
                // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ B₁ A₀ B₀
                { 0x20000000 }
                // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ B₁ A₀ B₀ 2²⁹

                // A₀ - B₀
                limb_sub_borrow
                // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ B₁ 2²⁹ C₀⁻ A₀-B₀
                OP_DUP
                OP_TOALTSTACK
                // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ B₁ 2²⁹ C₀⁻ A₀-B₀ | A₀-B₀
                OP_ROT
                // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ B₁ C₀⁻ A₀-B₀ 2²⁹
                { Self::MODULUS_LIMBS[0] }
                OP_SWAP
                // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ B₁ C₀⁻ A₀-B₀ M₀ 2²⁹
                limb_add_carry
                OP_TOALTSTACK
                // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ B₁ C₀⁻ 2²⁹ C₀⁺ | (A₀-B₀)+M₀

                // from     A₁      - B₁        - carry_0
                //   to     A{N-2}  - B{N-2}    - carry_{N-3}
                for i in 1..Self::N_LIMBS-1 {
                    // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ B₁ C₀⁻ 2²⁹ C₀⁺
                    OP_2SWAP
                    // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ 2²⁹ C₀⁺ B₁ C₀⁻
                    OP_ADD
                    // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ 2²⁹ C₀⁺ B₁+C₀⁻
                    OP_2SWAP
                    // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ C₀⁺ B₁+C₀⁻ A₁ 2²⁹
                    OP_TOALTSTACK OP_SWAP OP_FROMALTSTACK
                    limb_sub_borrow
                    OP_DUP
                    OP_TOALTSTACK
                    // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ C₀⁺ 2²⁹ C₁⁻ A₁-(B₁+C₀) | A₁-(B₁+C₀)
                    OP_2SWAP
                    OP_SWAP
                    // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ C₁⁻ A₁-(B₁+C₀) 2²⁹ C₀⁺
                    { Self::MODULUS_LIMBS[i as usize] }
                    // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ C₁⁻ A₁-(B₁+C₀) 2²⁹ C₀⁺ M₁
                    OP_ADD
                    // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ C₁⁻ A₁-(B₁+C₀) 2²⁹ C₀⁺+M₁
                    OP_SWAP
                    // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ C₁⁻ A₁-(B₁+C₀) C₀⁺+M₁ 2²⁹
                    limb_add_carry
                    OP_TOALTSTACK
                    // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ C₁⁻ 2²⁹ C₁⁺ | (A₁-(B₁+C₀))+(C₀⁺+M₁)
                }
                // ⋯ A₈ B₈ C₇⁻ 2²⁹ C₇⁺
                OP_2SWAP
                OP_ADD
                // ⋯ A₈ 2²⁹ C₇⁺ B₈+C₇⁻
                OP_2SWAP
                // ⋯ C₇⁺ B₈+C₇⁻ A₈ 2²⁹
                OP_TOALTSTACK OP_SWAP OP_FROMALTSTACK
                // ⋯ C₇⁺ A₈ B₈+C₇⁻ 2²⁹
                limb_sub_borrow
                // ⋯ C₇⁺ 2²⁹ C₈⁻ A₈-(B₈+C₇⁻)
                OP_DUP
                OP_TOALTSTACK
                // ⋯ C₇⁺ 2²⁹ C₈⁻ A₈-(B₈+C₇⁻) | A₈-(B₈+C₇⁻)
                OP_ROT OP_TOALTSTACK
                // ⋯ C₇⁺ C₈⁻ A₈-(B₈+C₇⁻) | 2²⁹ A₈-(B₈+C₇⁻)
                OP_ROT { *Self::MODULUS_LIMBS.last().unwrap() }
                // ⋯ C₈⁻ (A₈-(B₈+C₇⁻)) C₇⁺ M₈
                OP_ADD OP_ADD
                // ⋯ C₈⁻ (A₈-(B₈+C₇⁻))+(C₇⁺+M₈)
                OP_FROMALTSTACK OP_2DUP OP_GREATERTHANOREQUAL
                OP_IF OP_SUB OP_ELSE OP_DROP OP_ENDIF
                OP_TOALTSTACK
                // ⋯ C₈⁻ | (A₈-(B₈+C₇⁻))+(C₇⁺+M)₈ A₈-(B₈+C₇⁻)
                OP_DUP
                // ⋯ C₈⁻ C₈⁻
                { script! {
                    OP_NOTIF
                        OP_FROMALTSTACK
                        OP_DROP
                    OP_ENDIF

                    OP_FROMALTSTACK
                    // ⋯ C₈⁻ A₈-(B₈+C₇⁻) | (A₇-(B₇+C₆⁻))+(C₆⁺+M₇)
                    // ⋯ C₈⁻ (A₈-(B₈+C₇⁻))+(C₇⁺+M₈) | (B₈+C₇⁻)+A₈
                    for _ in 0..Self::N_LIMBS-1 {
                        OP_FROMALTSTACK  OP_DROP
                        OP_FROMALTSTACK
                    }
                    // ⋯ C₈⁻ A₈-(B₈+C₇⁻) A₇-(B₇+C₆⁻) ... A₂-(B₂+C₁⁻) A₁-(B₁+C₀⁻) A₀+B₀
                    // ⋯ C₈⁻ (A₈-(B₈+C₇⁻))+(C₇⁺+M₈) ... (A₀+B₀)-M₀ | A₀+B₀
                    { Self::N_LIMBS }
                    OP_ROLL
                    OP_IF
                        OP_FROMALTSTACK
                        OP_DROP
                    OP_ENDIF
                }.add_stack_hint(-2, Self::N_LIMBS as i32 - 2).add_altstack_hint(-2 * Self::N_LIMBS as i32, -2 * Self::N_LIMBS as i32)}
                // ⋯ A₈-(B₈+C₇⁻) A₇-(B₇+C₆⁻) ... A₁-(B₁+C₀⁻) A₀+B₀
                // ⋯ (A₈-(B₈+C₇⁻))+(C₇⁺+M₈) ... (A₀-B₀)+M₀
            }
        });
        script! {
            { Self::zip(a, b) }
            { sub_script.clone() }
        }
    }

    fn double(a: u32) -> Script {
        script! {
            { Self::roll(a) }
            // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ A₁ A₀
            OP_DUP
            // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ A₁ A₀ A₀
            { 0x20000000 }
            // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ A₁ A₀ A₀ 2²⁹

            // A₀ + A₀
            limb_add_carry
            // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ A₁ 2²⁹ C₀⁺ 2⋅A₀
            OP_DUP
            OP_TOALTSTACK
            // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ A₁ 2²⁹ C₀⁺ 2⋅A₀ | 2⋅A₀
            OP_ROT
            // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ A₁ C₀⁺ 2⋅A₀ 2²⁹
            { Self::MODULUS_LIMBS[0] }
            OP_SWAP
            // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ A₁ C₀⁺ 2⋅A₀ M₀ 2²⁹
            limb_sub_borrow
            OP_TOALTSTACK
            // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ A₁ C₀⁺ 2²⁹ C₀⁻ | 2⋅A₀-M₀

            // from     A₁      + A₁        + carry_0
            //   to     A{N-2}  + A{N-2}    + carry_{N-3}
            for i in 1..Self::N_LIMBS-1 {
                // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ A₁ C₀⁺ 2²⁹ C₀⁻
                OP_SWAP OP_2SWAP
                // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ C₀⁻ 2²⁹ A₁ C₀⁺
                OP_OVER OP_ADD
                // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ C₀⁻ 2²⁹ A₁ A₁+C₀⁺
                OP_ROT
                // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ C₀⁻ A₁ A₁+C₀⁺ 2²⁹
                limb_add_carry
                OP_DUP
                OP_TOALTSTACK
                // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ C₀⁻ 2²⁹ C₁⁺ 2⋅A₁+C₀⁺ | 2⋅A₁+C₀⁺
                OP_ROT OP_TOALTSTACK OP_ROT
                // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ C₁⁺ 2⋅A₁+C₀⁺ C₀⁻ | 2²⁹
                { Self::MODULUS_LIMBS[i as usize] }
                // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ C₁⁺ 2⋅A₁+C₀⁺ C₀⁻ M₁
                OP_ADD
                // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ C₁⁺ 2⋅A₁+C₀⁺ C₀⁻+M₁
                OP_FROMALTSTACK
                // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ C₁⁺ 2⋅A₁+C₀⁺ C₀⁻+M₁ 2²⁹
                limb_sub_borrow
                OP_TOALTSTACK
                // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ C₁⁺ 2²⁹ C₁⁻ | (2⋅A₁+C₀⁺)-(C₀⁻+M₁)
            }
            // ⋯ A₈ C₇⁺ 2²⁹ C₇⁻
            OP_2SWAP
            // ⋯ 2²⁹ C₇⁻ A₈ C₇⁺
            OP_OVER OP_ADD
            // ⋯ 2²⁹ C₇⁻ A₈ A₈+C₇⁺
            OP_ADD
            // ⋯ 2²⁹ C₇⁻ 2⋅A₈+C₇⁺
            OP_DUP OP_TOALTSTACK
            // ⋯ 2²⁹ C₇⁻ 2⋅A₈+C₇⁺ | 2⋅A₈+C₇⁺
            OP_SWAP
            // ⋯ 2²⁹ 2⋅A₈+C₇⁺ C₇⁻
            { *Self::MODULUS_LIMBS.last().unwrap() }
            // ⋯ 2²⁹ 2⋅A₈+C₇⁺ C₇⁻ M₈
            OP_ADD
            OP_ROT
            // ⋯ 2⋅A₈+C₇⁺ C₇⁻+M₈ 2²⁹
            limb_sub_borrow
            OP_TOALTSTACK
            // ⋯ 2²⁹ C₈⁻ | (2⋅A₈+C₇⁺)-(C₇⁻+M₈)
            OP_NIP
            OP_DUP
            { script! {
                // ⋯ C₈⁻ C₈⁻
                OP_IF
                    OP_FROMALTSTACK
                    OP_DROP
                OP_ENDIF

                OP_FROMALTSTACK
                // ⋯ 2⋅A₈+C₇⁺ C₈⁻ | (2⋅A₇+C₆⁺)-(C₆⁻+M₇)
                // ⋯ (2⋅A₈+C₇⁺)-(C₇⁻+M₈) C₈⁻ | 2⋅A₈+C₇⁺
                for _ in 0..Self::N_LIMBS-1 {
                    OP_FROMALTSTACK  OP_DROP
                    OP_FROMALTSTACK
                }
                // ⋯ 2⋅A₈+C₇⁺ 2⋅A₇+C₆⁺ ... 2⋅A₂+C₁⁺ 2⋅A₁+C₀⁺ 2⋅A₀ C₈⁻
                // ⋯ (2⋅A₈+C₇⁺)-(C₇⁻+M₈) ... 2⋅A₀-M₀ C₈⁻ | 2⋅A₀
                { Self::N_LIMBS }
                OP_ROLL
                OP_NOTIF
                    OP_FROMALTSTACK
                    OP_DROP
                OP_ENDIF
            }.add_stack_hint(-2, Self::N_LIMBS as i32 - 2).add_altstack_hint(-2 * Self::N_LIMBS as i32, -2 * Self::N_LIMBS as i32)}
            // ⋯ 2⋅A₈+C₇⁺ 2⋅A₇+C₆⁺ ... 2⋅A₁+C₀⁺ 2⋅A₀
            // ⋯ (2⋅A₈+C₇⁺)-(C₇⁻+M₈) ... 2⋅A₀-M₀
        }
    }

    fn hinted_mul(mut a_depth: u32, mut a: ark_bn254::Fq, mut b_depth: u32, mut b: ark_bn254::Fq) -> (Script, Vec<Hint>) {
        assert_ne!(a_depth, b_depth);
        if a_depth > b_depth {
            (a_depth, b_depth) = (b_depth, a_depth);
            (a, b) = (b, a);
        }

        let mut hints = Vec::new();
        let x = BigInt::from_str(&a.to_string()).unwrap();
        let y = BigInt::from_str(&b.to_string()).unwrap();
        let modulus = &Fq::modulus_as_bigint();
        let q = (x * y) / modulus;

        let script = script!{
            for _ in 0..Self::N_LIMBS { 
                OP_DEPTH OP_1SUB OP_ROLL // hints
            }
            // { fq_push(ark_bn254::Fq::from_str(&q.to_string()).unwrap()) }
            { Fq::roll(a_depth + 1) }
            { Fq::roll(b_depth + 1) }
            { Fq::tmul() }
        };
        hints.push(Hint::Fq(ark_bn254::Fq::from_str(&q.to_string()).unwrap()));

        (script, hints)
    }

    // TODO: Optimize by using the constant feature
    fn hinted_mul_by_constant(a: ark_bn254::Fq, constant: &ark_bn254::Fq) -> (Script, Vec<Hint>) {
        let mut hints = Vec::new();
        let x = BigInt::from_str(&a.to_string()).unwrap();
        let y = BigInt::from_str(&constant.to_string()).unwrap();
        let modulus = &Fq::modulus_as_bigint();
        let q = (x * y) / modulus;

        let script = script!{
            for _ in 0..Self::N_LIMBS { 
                OP_DEPTH OP_1SUB OP_ROLL // hints
            }
            // { fq_push(ark_bn254::Fq::from_str(&q.to_string()).unwrap()) }
            { Fq::roll(1) }
            { fq_push_not_montgomery(*constant) }
            { Fq::tmul() }
        };
        hints.push(Hint::Fq(ark_bn254::Fq::from_str(&q.to_string()).unwrap()));

        (script, hints)
    }

    fn hinted_mul_keep_element(mut a_depth: u32, mut a: ark_bn254::Fq, mut b_depth: u32, mut b: ark_bn254::Fq) -> (Script, Vec<Hint>) {
        assert_ne!(a_depth, b_depth);
        if a_depth > b_depth {
            (a_depth, b_depth) = (b_depth, a_depth);
            (a, b) = (b, a);
        }

        let mut hints = Vec::new();
        let x = BigInt::from_str(&a.to_string()).unwrap();
        let y = BigInt::from_str(&b.to_string()).unwrap();
        let modulus = &Fq::modulus_as_bigint();
        let q = (x * y) / modulus;

        let script = script!{
            for _ in 0..Self::N_LIMBS { 
                OP_DEPTH OP_1SUB OP_ROLL // hints
            }
            // { fq_push(ark_bn254::Fq::from_str(&q.to_string()).unwrap()) }
            { Fq::copy(a_depth + 1) }
            { Fq::copy(b_depth + 2) }
            { Fq::tmul() }
        };
        hints.push(Hint::Fq(ark_bn254::Fq::from_str(&q.to_string()).unwrap()));

        (script, hints)
    }

    fn mul() -> Script {
        Self::MUL_ONCELOCK
            .get_or_init(|| {
                script! {
                    // a ⋅ b  →  ❨a ⋅ b❩ᵐᵒᵈ2²⁶¹ ⌊2⁻²⁶¹⋅❨a ⋅ b❩⌋
                    // ⋯ A₂₆₀…₀ B₂₆₀…₀
                    { u29x9_mul_karazuba(1, 0) }
                    // ⋯ ❨A₂₆₀…₀⋅B₂₆₀…₀❩₅₂₁…₂₆₁ ❨A₂₆₀…₀⋅B₂₆₀…₀❩₂₆₀…₀

                    // lo ⋅ p⁻¹
                    // lo  <=>  ❨a ⋅ b❩ᵐᵒᵈ2²⁶¹
                    { u29x9_mullo_karazuba_imm(Self::MODULUS_INV_261) }
                    // ⋯ ❨A₂₆₀…₀⋅B₂₆₀…₀❩₅₂₁…₂₆₁ ❨❨A₂₆₀…₀⋅B₂₆₀…₀❩₂₆₀…₀⋅P⁻¹₂₆₀…₀❩₂₆₀…₀

                    // ❨lo ⋅ p⁻¹❩ ⋅ p
                    { u29x9_mulhi_karazuba_imm(Self::MODULUS_LIMBS) }
                    // ⋯ ❨A₂₆₀…₀⋅B₂₆₀…₀❩₅₂₁…₂₆₁ ❨❨❨A₂₆₀…₀⋅B₂₆₀…₀❩₂₆₀…₀⋅P⁻¹₂₆₀…₀❩₂₆₀…₀⋅P₂₆₀…₀❩₅₂₁…₂₆₁

                    // hi - ❨lo ⋅ p⁻¹❩ ⋅ p
                    // hi  <=>  ⌊2⁻²⁶¹⋅❨a ⋅ b❩⌋
                    { Self::sub(1, 0) }
                    // ⋯ ❨A₂₆₀…₀⋅B₂₆₀…₀⋅2⁻²⁶¹❩₂₆₀…₀
                }
            })
            .clone()
    }

    // create table for top item on the stack
    fn init_table(window: u32) -> Script {
        assert!(
            1 <= window && window <= 6,
            "expected 1<=window<=6; got window={}",
            window
        );
        script! {
            for i in 2..=window {
                for j in 1 << (i - 1)..1 << i {
                    if j % 2 == 0 {
                        { U254::copy(j/2 - 1) }
                        { U254::double(0) }
                    } else {
                        { U254::copy(0) }
                        { U254::copy(j - 1) }
                        { U254::add(1, 0) }
                    }
                }
            }
        }
    }

    fn mul_bucket() -> Script {
        let q_big = BigUint::from_str_radix(Fq::MODULUS, 16).unwrap();
        let q_limbs = fq_to_bits(ark_ff::BigInt::<4>::from_str(&q_big.to_str_radix(10)).unwrap(), 4);

        script! {
                // stack: {a} {b} {p}
                { U254::roll(1) } // {a} {p} {b}
                { U254::toaltstack() }
                { U254::toaltstack() }
                { U254::toaltstack() }

                // keep the window size is 16 = 1 << 4
                { U254::push_zero() }
                { U254::fromaltstack() }
                { Self::init_table(4) }
                // keep the window size is 16 = 1 << 4
                { U254::push_zero() }
                { U254::fromaltstack() }
                { Self::init_table(4) }

                { U254::fromaltstack() }
                { Fq::convert_to_be_u4().clone() }

                // {a_table} {q_table} {b} {q}
                for i in 0..64 {

                    { 16 }
                    { q_limbs[63 - i]}
                    OP_SUB
                    // cal offset: index * 9 + 64
                    OP_DUP
                    OP_DUP
                    OP_ADD // 2 * index
                    OP_DUP
                    OP_ADD // 4 * index
                    OP_DUP
                    OP_ADD // 8 * index
                    OP_ADD // 9 * index
                    { 63 - i}
                    OP_ADD

                    // TO ALTSTACK
                    OP_DUP
                    OP_DUP
                    OP_DUP
                    OP_DUP
                    OP_DUP
                    OP_DUP
                    OP_DUP
                    OP_DUP
                    OP_TOALTSTACK
                    OP_TOALTSTACK
                    OP_TOALTSTACK
                    OP_TOALTSTACK
                    OP_TOALTSTACK
                    OP_TOALTSTACK
                    OP_TOALTSTACK
                    OP_TOALTSTACK

                    // get target bucket
                    OP_PICK

                    for _ in 0..8 {
                        OP_FROMALTSTACK
                        OP_PICK
                    }

                    // push bucket element to element
                    // | y_0 * x
                    { U254::toaltstack() }

                    // 32 - stack
                    { 16 }
                    OP_SWAP
                    OP_SUB
                    // cal offset: index * 9 + 64
                    OP_DUP
                    OP_DUP
                    OP_ADD // 2 * index
                    OP_DUP
                    OP_ADD // 4 * index
                    OP_DUP
                    OP_ADD // 8 * index
                    OP_ADD // 9 * index
                    { 63 - i + 144 - 1 } // 16 * 9 = 144
                    OP_ADD

                    // TO ALTSTACK
                    OP_DUP
                    OP_DUP
                    OP_DUP
                    OP_DUP
                    OP_DUP
                    OP_DUP
                    OP_DUP
                    OP_DUP
                    OP_TOALTSTACK
                    OP_TOALTSTACK
                    OP_TOALTSTACK
                    OP_TOALTSTACK
                    OP_TOALTSTACK
                    OP_TOALTSTACK
                    OP_TOALTSTACK
                    OP_TOALTSTACK

                    // get target bucket
                    OP_PICK

                    for _ in 0..8 {
                        OP_FROMALTSTACK
                        OP_PICK
                    }

                    { U254::fromaltstack() }

                    { U254::sub(1, 0) }

                    if i == 0 {
                        { U254::toaltstack() }
                    } else {
                        { U254::fromaltstack() }
                        { U254::double_allow_overflow() }
                        { U254::double_allow_overflow() }
                        { U254::double_allow_overflow() }
                        { U254::double_allow_overflow() }
                        { U254::add(1, 0)}
                        { U254::toaltstack() }
                    }
                }
                // {a_tablr} {q_table} | bi * a - p_i * q (i = 0~50)
                // drop table
                for _ in 0..16 {
                    { U254::drop() }
                }

                for _ in 0..16 {
                    { U254::drop() }
                }
                { U254::fromaltstack() }

        }
    }

    fn mul_by_constant_bucket(constant: &Self::ConstantType) -> Script {
        let q_big = BigUint::from_str_radix(Fq::MODULUS, 16).unwrap();
        let q_limbs = fq_to_bits(ark_ff::BigInt::<4>::from_str(&q_big.to_str_radix(10)).unwrap(), 4);

        let b = constant.to_string();
        let b_big = BigUint::from_str_radix(&b, 10).unwrap();
        let b_limbs = fq_to_bits(ark_ff::BigInt::<4>::from_str(&b_big.to_str_radix(10)).unwrap(), 4);
        script! {
                // stack: {a} {p}
                { U254::toaltstack() }
                { U254::toaltstack() }

                // keep the window size is 16 = 1 << 4
                { U254::push_zero() }
                { U254::fromaltstack() }
                { Self::init_table(4) }
                // keep the window size is 16 = 1 << 4
                { U254::push_zero() }
                { U254::fromaltstack() }
                { Self::init_table(4) }

                // {a_table} {q_table}
                for i in 0..64 {

                    { 16 }
                    { q_limbs[63 - i] }
                    //OP_SWAP
                    OP_SUB
                    // cal offset: index * 9 + 64
                    OP_DUP
                    OP_DUP
                    OP_ADD // 2 * index
                    OP_DUP
                    OP_ADD // 4 * index
                    OP_DUP
                    OP_ADD // 8 * index
                    OP_ADD // 9 * index
                    //{ 63 - i + 64 - i - 1}
                    OP_1SUB

                    // TO ALTSTACK
                    OP_DUP
                    OP_DUP
                    OP_DUP
                    OP_DUP
                    OP_DUP
                    OP_DUP
                    OP_DUP
                    OP_DUP
                    OP_TOALTSTACK
                    OP_TOALTSTACK
                    OP_TOALTSTACK
                    OP_TOALTSTACK
                    OP_TOALTSTACK
                    OP_TOALTSTACK
                    OP_TOALTSTACK
                    OP_TOALTSTACK

                    // get target bucket
                    OP_PICK

                    for _ in 0..8 {
                        OP_FROMALTSTACK
                        OP_PICK
                    }

                    // push bucket element to element
                    // | y_0 * x
                    { U254::toaltstack() }

                    // 32 - stack
                    { 16 }
                    { b_limbs[63 - i] }
                    OP_SUB
                    // cal offset: index * 9 + 64
                    OP_DUP
                    OP_DUP
                    OP_ADD // 2 * index
                    OP_DUP
                    OP_ADD // 4 * index
                    OP_DUP
                    OP_ADD // 8 * index
                    OP_ADD // 9 * index
                    //{ 63 - i + 63 - i + 144 - 1 } // 16 * 9 = 144
                    { 144 - 1 }
                    OP_ADD

                    // TO ALTSTACK
                    OP_DUP
                    OP_DUP
                    OP_DUP
                    OP_DUP
                    OP_DUP
                    OP_DUP
                    OP_DUP
                    OP_DUP
                    OP_TOALTSTACK
                    OP_TOALTSTACK
                    OP_TOALTSTACK
                    OP_TOALTSTACK
                    OP_TOALTSTACK
                    OP_TOALTSTACK
                    OP_TOALTSTACK
                    OP_TOALTSTACK

                    // get target bucket
                    OP_PICK

                    for _ in 0..8 {
                        OP_FROMALTSTACK
                        OP_PICK
                    }

                    { U254::fromaltstack() }

                    { U254::sub(1, 0) }

                    if i == 0 {
                        { U254::toaltstack() }
                    } else {
                        { U254::fromaltstack() }
                        { U254::double_allow_overflow() }
                        { U254::double_allow_overflow() }
                        { U254::double_allow_overflow() }
                        { U254::double_allow_overflow() }
                        { U254::add(1, 0)}
                        { U254::toaltstack() }
                    }
                }
                // {a_tablr} {q_table} | bi * a - p_i * q (i = 0~50)
                // drop table
                for _ in 0..16 {
                    { U254::drop() }
                }

                for _ in 0..16 {
                    { U254::drop() }
                }
                { U254::fromaltstack() }

        }
    }

    fn is_zero(a: u32) -> Script { U254::is_zero(a) }

    fn is_zero_keep_element(a: u32) -> Script { U254::is_zero_keep_element(a) }

    fn is_one_keep_element(a: u32) -> Script {
        script! {
            { Self::copy(a) }
            { Self::is_one(0) }
        }
    }

    fn is_one_keep_element_not_montgomery(a: u32) -> Script {
        script! {
            { Self::copy(a) }
            { Self::is_one_not_montgomery() }
        }
    }

    fn is_one_not_montgomery() -> Script {
        script! {
            { Self::push_one_not_montgomery() }
            { Self::equal(1, 0) }
        }
    }

    fn is_one(a: u32) -> Script {
        let mut u29x9_one = [0u32; 9];
        let montgomery_one = BigUint::from_str_radix(Self::MONTGOMERY_ONE, 16).unwrap();
        for i in 0..9 {
            u29x9_one[i] = *montgomery_one
                .clone()
                .div(BigUint::one().shl(29 * i) as BigUint)
                .rem(BigUint::one().shl(29) as BigUint)
                .to_u32_digits()
                .first()
                .unwrap_or(&0);
        }
        script! {
            { Self::roll(a) }
            // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ A₁ A₀
            { *u29x9_one.first().unwrap() } OP_EQUAL OP_SWAP
            // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ A₁ A₀=1₀ A₁
            for i in 1..Self::N_LIMBS as usize - 1 {
                // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ A₀=1₀ A₁
                { u29x9_one[i] } OP_EQUAL
                // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ A₀=1₀ A₁=1₁
                OP_BOOLAND OP_SWAP
                // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ (A₀=1₀)∧(A₁=1₁) A₂
            }
            // ⋯ (A₀=1₀)∧⋯∧(A₇=1₇) A₈
            { *u29x9_one.last().unwrap() } OP_EQUAL
            // ⋯ (A₀=1₀)∧⋯∧(A₇=1₇) A₈=1₈
            OP_BOOLAND
            // ⋯ (A₀=1₀)∧⋯∧(A₈=1₈)
        }
    }

    fn is_field() -> Script {
        script! {
            // Each limb must not be negative
            for i in 0..Self::N_LIMBS - 1 {
                { i } OP_PICK
                0 OP_GREATERTHANOREQUAL OP_TOALTSTACK
            }
            { Self::N_LIMBS - 1 } OP_PICK
            0 OP_GREATERTHANOREQUAL
            for _ in 0..Self::N_LIMBS - 1 {
                OP_FROMALTSTACK OP_BOOLAND
            }
            OP_TOALTSTACK

            { Self::push_modulus() }
            { U254::lessthan(1, 0) }

            OP_FROMALTSTACK OP_BOOLAND
        }
    }

    fn square() -> Script {
        script! {
            // a ⋅ a  →  ❨a ⋅ a❩ᵐᵒᵈ2²⁶¹ ⌊2⁻²⁶¹⋅❨a ⋅ a❩⌋
            // ⋯ A₂₆₀…₀
            { u29x9_square(0) }
            // ⋯ ❨A₂₆₀…₀⋅A₂₆₀…₀❩₅₂₁…₂₆₁ ❨A₂₆₀…₀⋅A₂₆₀…₀❩₂₆₀…₀

            // lo ⋅ p⁻¹
            // lo  <=>  ❨a ⋅ a❩ᵐᵒᵈ2²⁶¹
            { u29x9_mullo_karazuba_imm(Self::MODULUS_INV_261) }
            // ⋯ ❨A₂₆₀…₀⋅A₂₆₀…₀❩₅₂₁…₂₆₁ ❨❨A₂₆₀…₀⋅A₂₆₀…₀❩₂₆₀…₀⋅P⁻¹₂₆₀…₀❩₂₆₀…₀

            // ❨lo ⋅ p⁻¹❩ ⋅ p
            { u29x9_mulhi_karazuba_imm(Self::MODULUS_LIMBS) }
            // ⋯ ❨A₂₆₀…₀⋅A₂₆₀…₀❩₅₂₁…₂₆₁ ❨❨❨A₂₆₀…₀⋅A₂₆₀…₀❩₂₆₀…₀⋅P⁻¹₂₆₀…₀❩₂₆₀…₀⋅P₂₆₀…₀❩₅₂₁…₂₆₁

            // hi - ❨lo ⋅ p⁻¹❩ ⋅ p
            // hi  <=>  ⌊2⁻²⁶¹⋅❨a ⋅ b❩⌋
            { Self::sub(1, 0) }
            // ⋯ ❨A₂₆₀…₀⋅A₂₆₀…₀⋅2⁻²⁶¹❩₂₆₀…₀
        }
    }

    // TODO: Optimize using the sqaure feature
    fn hinted_square(a: ark_bn254::Fq) -> (Script, Vec<Hint>) {
        let mut hints = Vec::new();
        let x = &BigInt::from_str(&a.to_string()).unwrap();
        let modulus = &Fq::modulus_as_bigint();
        let q = (x * x) / modulus;
        let script = script! {
            for _ in 0..Self::N_LIMBS { 
                OP_DEPTH OP_1SUB OP_ROLL // hints
            }
            // { fq_push(ark_bn254::Fq::from_str(&q.to_string()).unwrap()) }
            { Fq::roll(1) }
            { Fq::copy(0) }
            { Fq::tmul() }
        };
        hints.push(Hint::Fq(ark_bn254::Fq::from_str(&q.to_string()).unwrap()));
        (script, hints)
    }

    fn inv() -> Script {
        let r = BigUint::from_str_radix(Self::MONTGOMERY_ONE, 16).unwrap();
        let p = BigUint::from_str_radix(Self::MODULUS, 16).unwrap();
        script! {
            { Self::push_modulus() }
            { Self::roll(1) }
            { U254::inv_stage1() }
            { U254::inv_stage2(Self::MODULUS) }
            { Self::mul() }
            { Self::mul_by_constant(&Self::ConstantType::from(r.pow(3).rem(p))) }
        }
    }

    fn hinted_inv(a: ark_bn254::Fq) -> (Script, Vec<Hint>) {
        let mut hints = Vec::new();
        let x = &BigInt::from_str(&a.to_string()).unwrap();
        let modulus = &Fq::modulus_as_bigint();
        let y = &x.modinv(modulus).unwrap();
        let q = (x * y) / modulus;
        let script = script! {
            for _ in 0..Self::N_LIMBS { 
                OP_DEPTH OP_1SUB OP_ROLL // hints
            }
            for _ in 0..Self::N_LIMBS { 
                OP_DEPTH OP_1SUB OP_ROLL // hints
            }
            // { fq_push(ark_bn254::Fq::from_str(&y.to_string()).unwrap()) }
            // { fq_push(ark_bn254::Fq::from_str(&q.to_string()).unwrap()) }
            // x, y, q
            { Fq::roll(2) }
            { Fq::copy(2) }
            // y, q, x, y
            { Fq::tmul() }
            // y, 1
            { Fq::push_one_not_montgomery() }
            { Fq::equalverify(1, 0) }
        };
        hints.push(Hint::Fq(ark_bn254::Fq::from_str(&y.to_string()).unwrap()));
        hints.push(Hint::Fq(ark_bn254::Fq::from_str(&q.to_string()).unwrap()));
        (script, hints)
    }

    fn mul_by_constant(constant: &Self::ConstantType) -> Script {
        // Convert `PrimeField` to `[u29; 9]` in Montgomery form:
        let mut u29x9_montgomery = [0u32; 9];
        {
            let constant = BigUint::from_bytes_be(&constant.into_bigint().to_bytes_be())
                .mul(BigUint::from_str_radix(Self::MONTGOMERY_ONE, 16).unwrap())
                .rem(BigUint::from_str_radix(Self::MODULUS, 16).unwrap());

            for i in 0..9 {
                u29x9_montgomery[i] = *constant
                    .clone()
                    .div(BigUint::one().shl(29 * i) as BigUint)
                    .rem(BigUint::one().shl(29) as BigUint)
                    .to_u32_digits()
                    .first()
                    .unwrap_or(&0);
            }
        }

        script! {
            // a ⋅ b  →  ❨a ⋅ b❩ᵐᵒᵈ2²⁶¹ ⌊2⁻²⁶¹⋅❨a ⋅ b❩⌋
            // ⋯ A₂₆₀…₀
            { u29x9_mul_karazuba_imm(u29x9_montgomery) }
            // ⋯ ❨A₂₆₀…₀⋅B₂₆₀…₀❩₅₂₁…₂₆₁ ❨A₂₆₀…₀⋅B₂₆₀…₀❩₂₆₀…₀

            // lo ⋅ p⁻¹
            // lo  <=>  ❨a ⋅ b❩ᵐᵒᵈ2²⁶¹
            { u29x9_mullo_karazuba_imm(Self::MODULUS_INV_261) }
            // ⋯ ❨A₂₆₀…₀⋅B₂₆₀…₀❩₅₂₁…₂₆₁ ❨❨A₂₆₀…₀⋅B₂₆₀…₀❩₂₆₀…₀⋅P⁻¹₂₆₀…₀❩₂₆₀…₀

            // ❨lo ⋅ p⁻¹❩ ⋅ p
            { u29x9_mulhi_karazuba_imm(Self::MODULUS_LIMBS) }
            // ⋯ ❨A₂₆₀…₀⋅B₂₆₀…₀❩₅₂₁…₂₆₁ ❨❨❨A₂₆₀…₀⋅B₂₆₀…₀❩₂₆₀…₀⋅P⁻¹₂₆₀…₀❩₂₆₀…₀⋅P₂₆₀…₀❩₅₂₁…₂₆₁

            // hi - ❨lo ⋅ p⁻¹❩ ⋅ p
            // hi  <=>  ⌊2⁻²⁶¹⋅❨a ⋅ b❩⌋
            { Self::sub(1, 0) }
            // ⋯ ❨A₂₆₀…₀⋅B₂₆₀…₀⋅2⁻²⁶¹❩₂₆₀…₀
        }
    }

    fn div2() -> Script {
        script! {
            { U254::div2rem() }
            OP_IF
                { U254::push_hex(Self::P_PLUS_ONE_DIV2) }
                { Self::add(1, 0) }
            OP_ENDIF
        }
    }

    fn div3() -> Script {
        script! {
            { U254::div3rem() }
            OP_DUP
            0 OP_GREATERTHAN
            OP_IF
                OP_1SUB
                OP_IF
                    { U254::push_hex(Self::P_PLUS_TWO_DIV3) }
                    { Self::add(1, 0) }
                OP_ELSE
                    { U254::push_hex(Self::TWO_P_PLUS_ONE_DIV3) }
                    { Self::add(1, 0) }
                OP_ENDIF
            OP_ELSE
                OP_DROP
            OP_ENDIF
        }
    }

    //            2⁰⋅B₀  + 2⁸⋅B₁   + 2¹⁶⋅B₂ + 2²⁴⋅❨B₃ᵐᵒᵈ2⁵❩
    //  ⌊2⁻⁵⋅B₃⌋ + 2³⋅B₄  + 2¹¹⋅B₅  + 2¹⁹⋅B₆ + 2²⁷⋅❨B₇ᵐᵒᵈ2²❩
    //  ⌊2⁻²⋅B₇⌋ + 2⁶⋅B₈  + 2¹⁴⋅B₉  + 2²²⋅❨B₁₀ᵐᵒᵈ2⁷❩
    // ⌊2⁻⁷⋅B₁₀⌋ + 2¹⋅B₁₁ + 2⁹⋅B₁₂  + 2¹⁷⋅B₁₃ + 2²⁵⋅❨B₁₄ᵐᵒᵈ2⁴❩
    // ⌊2⁻⁴⋅B₁₄⌋ + 2⁴⋅B₁₅ + 2¹²⋅B₁₆ + 2²⁰⋅B₁₇ + 2²⁸⋅❨B₁₈ᵐᵒᵈ2¹❩
    // ⌊2⁻¹⋅B₁₈⌋ + 2⁷⋅B₁₉ + 2¹⁵⋅B₂₀ + 2²³⋅❨B₂₁ᵐᵒᵈ2⁶❩
    // ⌊2⁻⁶⋅B₂₁⌋ + 2²⋅B₂₂ + 2¹⁰⋅B₂₃ + 2¹⁸⋅B₂₄ + 2²⁶⋅❨B₂₅ᵐᵒᵈ2³❩
    // ⌊2⁻³⋅B₂₅⌋ + 2⁵⋅B₂₆ + 2¹³⋅B₂₇ + 2²¹⋅B₂₈
    //            2⁰⋅B₂₉ + 2⁸⋅B₃₀  + 2¹⁶⋅B₃₁

    fn from_hash() -> Script {
        let modulus = BigUint::from_str_radix(Self::MODULUS, 16).unwrap();
        let a: BigUint = BigUint::one().shl(253);
        let b: BigUint = BigUint::one().shl(254);
        let c: BigUint = BigUint::one().shl(255);

        script! {

            //  2⁰⋅B₀ + 2⁸⋅B₁ + 2¹⁶⋅B₂ + 2²⁴⋅❨B₃ᵐᵒᵈ2⁵❩
            // ⋯ B₀ B₁ B₂ B₃
            { 0x80 } OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_4 OP_ELSE OP_DROP OP_0 OP_ENDIF OP_TOALTSTACK
            { 0x40 } OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_2 OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_ELSE OP_DROP OP_ENDIF
            { 0x20 } OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_1 OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_ELSE OP_DROP OP_ENDIF
            // ⋯ B₀ B₁ B₂ B₃ᵐᵒᵈ2⁵ | ⌊2⁻⁵⋅B₃⌋
            OP_256MUL OP_ADD
            // ⋯ B₀ B₁ B₂+2⁸⋅❨B₃ᵐᵒᵈ2⁵❩
            OP_256MUL OP_ADD
            // ⋯ B₀ B₁+2⁸⋅B₂+2¹⁶⋅❨B₃ᵐᵒᵈ2⁵❩
            OP_256MUL OP_ADD
            // ⋯ B₀+2⁸⋅B₁+2¹⁶⋅B₂+2²⁴⋅❨B₃ᵐᵒᵈ2⁵❩
            OP_FROMALTSTACK OP_SWAP OP_TOALTSTACK
            // ⋯ ⌊2⁻⁵⋅B₃⌋ | B₀+2⁸⋅B₁+2¹⁶⋅B₂+2²⁴⋅❨B₃ᵐᵒᵈ2⁵❩


            //  ⌊2⁻⁵⋅B₃⌋ + 2³⋅B₄ + 2¹¹⋅B₅ + 2¹⁹⋅B₆ + 2²⁷⋅❨B₇ᵐᵒᵈ2²❩
            // ⋯ B₄ B₅ B₆ B₇ ⌊2⁻⁵⋅B₃⌋
            OP_TOALTSTACK
            // ⋯ B₄ B₅ B₆ B₇ | ⌊2⁻⁵⋅B₃⌋ ⋯
            { 0x80 } OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB { 32 } OP_ELSE OP_DROP OP_0 OP_ENDIF OP_TOALTSTACK
            { 0x40 } OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_16 OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_ELSE OP_DROP OP_ENDIF
            { 0x20 } OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_8 OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_ELSE OP_DROP OP_ENDIF
            OP_16 OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_4 OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_ELSE OP_DROP OP_ENDIF
            OP_8 OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_2 OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_ELSE OP_DROP OP_ENDIF
            OP_4 OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_1 OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_ELSE OP_DROP OP_ENDIF
            // ⋯ B₄ B₅ B₆ B₇ᵐᵒᵈ2² | ⌊2⁻²⋅B₇⌋ ⌊2⁻⁵⋅B₃⌋ ⋯
            OP_FROMALTSTACK OP_FROMALTSTACK OP_SWAP OP_TOALTSTACK OP_TOALTSTACK
            // ⋯ B₄ B₅ B₆ B₇ᵐᵒᵈ2² | ⌊2⁻⁵⋅B₃⌋ ⌊2⁻²⋅B₇⌋ ⋯
            OP_256MUL OP_ADD
            // ⋯ B₄ B₅ B₆+2⁸⋅❨B₇ᵐᵒᵈ2²❩
            OP_256MUL OP_ADD
            // ⋯ B₄ B₅+2⁸⋅B₆+2¹⁶⋅❨B₇ᵐᵒᵈ2²❩
            OP_256MUL OP_ADD
            // ⋯ B₄+2⁸⋅B₅+2¹⁶⋅B₆+2²⁴⋅❨B₇ᵐᵒᵈ2²❩
            for _ in 5..8 { OP_DUP OP_ADD }
            // ⋯ 2³⋅B₄+2¹¹⋅B₅+2¹⁹⋅B₆+2²⁷⋅❨B₇ᵐᵒᵈ2²❩
            OP_FROMALTSTACK OP_ADD
            // ⋯ ⌊2⁻⁵⋅B₃⌋+2³⋅B₄+2¹¹⋅B₅+2¹⁹⋅B₆+2²⁷⋅❨B₇ᵐᵒᵈ2²❩ | ⌊2⁻²⋅B₇⌋ ⋯
            OP_FROMALTSTACK OP_SWAP OP_TOALTSTACK
            // ⋯ ⌊2⁻²⋅B₇⌋ | ⌊2⁻⁵⋅B₃⌋+2³⋅B₄+2¹¹⋅B₅+2¹⁹⋅B₆+2²⁷⋅❨B₇ᵐᵒᵈ2²❩ ⋯


            //  ⌊2⁻²⋅B₇⌋ + 2⁶⋅B₈ + 2¹⁴⋅B₉ + 2²²⋅❨B₁₀ᵐᵒᵈ2⁷❩
            // ⋯ B₈ B₉ B₁₀ B₁₁ ⌊2⁻²⋅B₇⌋
            OP_TOALTSTACK
            // ⋯ B₈ B₉ B₁₀ B₁₁ | ⌊2⁻²⋅B₇⌋ ⋯
            OP_SWAP OP_2SWAP OP_ROT
            // ⋯ B₁₁ B₈ B₉ B₁₀
            { 0x80 } OP_2DUP OP_GREATERTHANOREQUAL OP_FROMALTSTACK OP_OVER OP_TOALTSTACK OP_TOALTSTACK OP_IF OP_SUB OP_ELSE OP_DROP OP_ENDIF
            // ⋯ B₁₁ B₈ B₉ B₁₀ᵐᵒᵈ2⁷ | ⌊2⁻²⋅B₇⌋ ⌊2⁻⁷⋅B₁₀⌋ ⋯
            OP_256MUL OP_ADD
            // ⋯ B₁₁ B₈ B₉+2⁸⋅❨B₁₀ᵐᵒᵈ2⁷❩
            OP_256MUL OP_ADD
            // ⋯ B₁₁ B₈+2⁸⋅B₉+2¹⁶⋅❨B₁₀ᵐᵒᵈ2⁷❩
            for _ in 2..8 { OP_DUP OP_ADD }
            // ⋯ B₁₁ 2⁶⋅B₈+2¹⁴⋅B₉+2²²⋅❨B₁₀ᵐᵒᵈ2⁷❩
            OP_FROMALTSTACK OP_ADD
            // ⋯ B₁₁ ⌊2⁻²⋅B₇⌋+2⁶⋅B₈+2¹⁴⋅B₉+2²²⋅❨B₁₀ᵐᵒᵈ2⁷❩ | ⌊2⁻⁷⋅B₁₀⌋ ⋯
            OP_FROMALTSTACK OP_SWAP OP_TOALTSTACK
            // ⋯ B₁₁ ⌊2⁻⁷⋅B₁₀⌋ | ⌊2⁻²⋅B₇⌋+2⁶⋅B₈+2¹⁴⋅B₉+2²²⋅❨B₁₀ᵐᵒᵈ2⁷❩ ⋯


            //  ⌊2⁻⁷⋅B₁₀⌋ + 2¹⋅B₁₁ + 2⁹⋅B₁₂ + 2¹⁷⋅B₁₃ + 2²⁵⋅❨B₁₄ᵐᵒᵈ2⁴❩
            // ⋯ B₁₂ B₁₃ B₁₄ B₁₅ B₁₁ ⌊2⁻⁷⋅B₁₀⌋
            OP_TOALTSTACK
            // ⋯ B₁₂ B₁₃ B₁₄ B₁₅ B₁₁ | ⌊2⁻⁷⋅B₁₀⌋ ⋯
            OP_4 OP_ROLL
            // ⋯ B₁₃ B₁₄ B₁₅ B₁₁ B₁₂
            OP_4 OP_ROLL
            // ⋯ B₁₄ B₁₅ B₁₁ B₁₂ B₁₃
            OP_4 OP_ROLL
            // ⋯ B₁₅ B₁₁ B₁₂ B₁₃ B₁₄
            { 0x80 } OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_8 OP_ELSE OP_DROP OP_0 OP_ENDIF OP_TOALTSTACK
            { 0x40 } OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_4 OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_ELSE OP_DROP OP_ENDIF
            { 0x20 } OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_2 OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_ELSE OP_DROP OP_ENDIF
            OP_16 OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_1 OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_ELSE OP_DROP OP_ENDIF
            // ⋯ B₁₅ B₁₁ B₁₂ B₁₃ B₁₄ᵐᵒᵈ2⁴ | ⌊2⁻⁴⋅B₁₄⌋ ⌊2⁻⁷⋅B₁₀⌋ ⋯
            OP_FROMALTSTACK OP_FROMALTSTACK OP_SWAP OP_TOALTSTACK OP_TOALTSTACK
            // ⋯ B₁₅ B₁₁ B₁₂ B₁₃ B₁₄ᵐᵒᵈ2⁴ | ⌊2⁻⁷⋅B₁₀⌋ ⌊2⁻⁴⋅B₁₄⌋ ⋯
            OP_256MUL OP_ADD
            // ⋯ B₁₅ B₁₁ B₁₂ B₁₃+2⁸⋅❨B₁₄ᵐᵒᵈ2⁴❩
            OP_256MUL OP_ADD
            // ⋯ B₁₅ B₁₁ B₁₂+2⁸⋅B₁₃+2¹⁶⋅❨B₁₄ᵐᵒᵈ2⁴❩
            OP_256MUL OP_ADD
            // ⋯ B₁₅ B₁₁+2⁸⋅B₁₂+2¹⁶⋅B₁₃+2²⁴⋅❨B₁₄ᵐᵒᵈ2⁴❩
            for _ in 7..8 { OP_DUP OP_ADD }
            // ⋯ B₁₅ 2¹⋅B₁₁+2⁹⋅B₁₂+2¹⁷⋅B₁₃+2²⁵⋅❨B₁₄ᵐᵒᵈ2⁴❩
            OP_FROMALTSTACK OP_ADD
            // ⋯ B₁₅ ⌊2⁻⁷⋅B₁₀⌋+2¹⋅B₁₁+2⁹⋅B₁₂+2¹⁷⋅B₁₃+2²⁵⋅❨B₁₄ᵐᵒᵈ2⁴❩ | ⌊2⁻⁴⋅B₁₄⌋ ⋯
            OP_FROMALTSTACK OP_SWAP OP_TOALTSTACK
            // ⋯ B₁₅ ⌊2⁻⁴⋅B₁₄⌋ | ⌊2⁻⁷⋅B₁₀⌋+2¹⋅B₁₁+2⁹⋅B₁₂+2¹⁷⋅B₁₃+2²⁵⋅❨B₁₄ᵐᵒᵈ2⁴❩ ⋯


            //  ⌊2⁻⁴⋅B₁₄⌋ + 2⁴⋅B₁₅ + 2¹²⋅B₁₆ + 2²⁰⋅B₁₇ + 2²⁸⋅❨B₁₈ᵐᵒᵈ2¹❩
            // ⋯ B₁₆ B₁₇ B₁₈ B₁₉ B₁₅ ⌊2⁻⁴⋅B₁₄⌋
            OP_TOALTSTACK
            // ⋯ B₁₆ B₁₇ B₁₈ B₁₉ B₁₅ | ⌊2⁻⁴⋅B₁₄⌋ ⋯
            OP_4 OP_ROLL
            // ⋯ B₁₇ B₁₈ B₁₉ B₁₅ B₁₆
            OP_4 OP_ROLL
            // ⋯ B₁₈ B₁₉ B₁₅ B₁₆ B₁₇
            OP_4 OP_ROLL
            // ⋯ B₁₉ B₁₅ B₁₆ B₁₇ B₁₈
            { 0x80 } OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB { 64 } OP_ELSE OP_DROP OP_0 OP_ENDIF OP_TOALTSTACK
            { 0x40 } OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB { 32 } OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_ELSE OP_DROP OP_ENDIF
            { 0x20 } OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_16 OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_ELSE OP_DROP OP_ENDIF
            OP_16 OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_8 OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_ELSE OP_DROP OP_ENDIF
            OP_8 OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_4 OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_ELSE OP_DROP OP_ENDIF
            OP_4 OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_2 OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_ELSE OP_DROP OP_ENDIF
            OP_2 OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_1 OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_ELSE OP_DROP OP_ENDIF
            // ⋯ B₁₉ B₁₅ B₁₆ B₁₇ B₁₈ᵐᵒᵈ2¹ | ⌊2⁻¹⋅B₁₈⌋ ⌊2⁻⁴⋅B₁₄⌋ ⋯
            OP_FROMALTSTACK OP_FROMALTSTACK OP_SWAP OP_TOALTSTACK OP_TOALTSTACK
            // ⋯ B₁₉ B₁₅ B₁₆ B₁₇ B₁₈ᵐᵒᵈ2¹ | ⌊2⁻⁴⋅B₁₄⌋ ⌊2⁻¹⋅B₁₈⌋ ⋯
            OP_256MUL OP_ADD
            // ⋯ B₁₉ B₁₅ B₁₆ B₁₇+2⁸⋅❨B₁₈ᵐᵒᵈ2¹❩
            OP_256MUL OP_ADD
            // ⋯ B₁₉ B₁₅ B₁₆+2⁸⋅B₁₇+2¹⁶⋅❨B₁₈ᵐᵒᵈ2¹❩
            OP_256MUL OP_ADD
            // ⋯ B₁₉ B₁₅+2⁸⋅B₁₆+2¹⁶⋅B₁₇+2²⁴⋅❨B₁₈ᵐᵒᵈ2¹❩
            for _ in 4..8 { OP_DUP OP_ADD }
            // ⋯ B₁₉ 2⁴⋅B₁₅+2¹²⋅B₁₆+2²⁰⋅B₁₇+2²⁸⋅❨B₁₈ᵐᵒᵈ2¹❩
            OP_FROMALTSTACK OP_ADD
            // ⋯ B₁₉ ⌊2⁻⁴⋅B₁₄⌋+2⁴⋅B₁₅+2¹²⋅B₁₆+2²⁰⋅B₁₇+2²⁸⋅❨B₁₈ᵐᵒᵈ2¹❩ | ⌊2⁻¹⋅B₁₈⌋ ⋯
            OP_FROMALTSTACK OP_SWAP OP_TOALTSTACK
            // ⋯ B₁₉ ⌊2⁻¹⋅B₁₈⌋ | ⌊2⁻⁴⋅B₁₄⌋+2⁴⋅B₁₅+2¹²⋅B₁₆+2²⁰⋅B₁₇+2²⁸⋅❨B₁₈ᵐᵒᵈ2¹❩ ⋯


            //  ⌊2⁻¹⋅B₁₈⌋ + 2⁷⋅B₁₉ + 2¹⁵⋅B₂₀ + 2²³⋅❨B₂₁ᵐᵒᵈ2⁶❩
            // ⋯ B₂₀ B₂₁ B₂₂ B₂₃ B₁₉ ⌊2⁻¹⋅B₁₈⌋
            OP_TOALTSTACK
            // ⋯ B₂₀ B₂₁ B₂₂ B₂₃ B₁₉ | ⌊2⁻¹⋅B₁₈⌋ ⋯
            OP_4 OP_ROLL
            // ⋯ B₂₁ B₂₂ B₂₃ B₁₉ B₂₀
            OP_4 OP_ROLL
            // ⋯ B₂₂ B₂₃ B₁₉ B₂₀ B₂₁
            { 0x80 } OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_2 OP_ELSE OP_DROP OP_0 OP_ENDIF OP_TOALTSTACK
            { 0x40 } OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_1 OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_ELSE OP_DROP OP_ENDIF
            // ⋯ B₂₂ B₂₃ B₁₉ B₂₀ B₂₁ | ⌊2⁻⁶⋅B₂₁⌋ ⌊2⁻¹⋅B₁₈⌋ ⋯
            OP_FROMALTSTACK OP_FROMALTSTACK OP_SWAP OP_TOALTSTACK OP_TOALTSTACK
            // ⋯ B₂₂ B₂₃ B₁₉ B₂₀ B₂₁ᵐᵒᵈ2⁶ | ⌊2⁻¹⋅B₁₈⌋ ⌊2⁻⁶⋅B₂₁⌋ ⋯
            OP_256MUL OP_ADD
            // ⋯ B₂₂ B₂₃ B₁₉ B₂₀+2⁸⋅❨B₂₁ᵐᵒᵈ2⁶❩
            OP_256MUL OP_ADD
            // ⋯ B₂₂ B₂₃ B₁₉+2⁸⋅B₂₀+2¹⁶⋅❨B₂₁ᵐᵒᵈ2⁶❩
            for _ in 1..8 { OP_DUP OP_ADD }
            // ⋯ B₂₂ B₂₃ 2⁷⋅B₁₉+2¹⁵⋅B₂₀+2²³⋅❨B₂₁ᵐᵒᵈ2⁶❩
            OP_FROMALTSTACK OP_ADD
            // ⋯ B₂₂ B₂₃ ⌊2⁻¹⋅B₁₈⌋+2⁷⋅B₁₉+2¹⁵⋅B₂₀+2²³⋅❨B₂₁ᵐᵒᵈ2⁶❩ | ⌊2⁻⁶⋅B₂₁⌋ ⋯
            OP_FROMALTSTACK OP_SWAP OP_TOALTSTACK
            // ⋯ B₂₂ B₂₃ ⌊2⁻⁶⋅B₂₁⌋ | ⌊2⁻¹⋅B₁₈⌋+2⁷⋅B₁₉+2¹⁵⋅B₂₀+2²³⋅❨B₂₁ᵐᵒᵈ2⁶❩ ⋯


            //  ⌊2⁻⁶⋅B₂₁⌋ + 2²⋅B₂₂ + 2¹⁰⋅B₂₃ + 2¹⁸⋅B₂₄ + 2²⁶⋅❨B₂₅ᵐᵒᵈ2³❩
            // ⋯ B₂₄ B₂₅ B₂₆ B₂₇ B₂₂ B₂₃ ⌊2⁻⁶⋅B₂₁⌋
            OP_TOALTSTACK
            // ⋯ B₂₄ B₂₅ B₂₆ B₂₇ B₂₂ B₂₃ | ⌊2⁻⁶⋅B₂₁⌋ ⋯
            OP_5 OP_ROLL
            // ⋯ B₂₅ B₂₆ B₂₇ B₂₂ B₂₃ B₂₄
            OP_5 OP_ROLL
            // ⋯ B₂₆ B₂₇ B₂₂ B₂₃ B₂₄ B₂₅
            { 0x80 } OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_16 OP_ELSE OP_DROP OP_0 OP_ENDIF OP_TOALTSTACK
            { 0x40 } OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_8 OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_ELSE OP_DROP OP_ENDIF
            { 0x20 } OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_4 OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_ELSE OP_DROP OP_ENDIF
            OP_16 OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_2 OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_ELSE OP_DROP OP_ENDIF
            OP_8 OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_1 OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_ELSE OP_DROP OP_ENDIF
            // ⋯ B₂₆ B₂₇ B₂₂ B₂₃ B₂₄ B₂₅ᵐᵒᵈ2³ | ⌊2⁻³⋅B₂₅⌋ ⌊2⁻⁶⋅B₂₁⌋ ⋯
            OP_FROMALTSTACK OP_FROMALTSTACK OP_SWAP OP_TOALTSTACK OP_TOALTSTACK
            // ⋯ B₂₆ B₂₇ B₂₂ B₂₃ B₂₄ B₂₅ᵐᵒᵈ2³ | ⌊2⁻⁶⋅B₂₁⌋ ⌊2⁻³⋅B₂₅⌋ ⋯
            OP_256MUL OP_ADD
            // ⋯ B₂₆ B₂₇ B₂₂ B₂₃ B₂₄+2⁸⋅❨B₂₅ᵐᵒᵈ2³❩
            OP_256MUL OP_ADD
            // ⋯ B₂₆ B₂₇ B₂₂ B₂₃+2⁸⋅B₂₄+2¹⁶⋅❨B₂₅ᵐᵒᵈ2³❩
            OP_256MUL OP_ADD
            // ⋯ B₂₆ B₂₇ B₂₂+2⁸⋅B₂₃+2¹⁶⋅B₂₄+2²⁴⋅❨B₂₅ᵐᵒᵈ2³❩
            for _ in 6..8 { OP_DUP OP_ADD }
            // ⋯ B₂₆ B₂₇ 2²⋅B₂₂+2¹⁰⋅B₂₃+2¹⁸⋅B₂₄+2²⁶⋅❨B₂₅ᵐᵒᵈ2³❩
            OP_FROMALTSTACK OP_ADD
            // ⋯ B₂₆ B₂₇ ⌊2⁻⁶⋅B₂₁⌋+2²⋅B₂₂+2¹⁰⋅B₂₃+2¹⁸⋅B₂₄+2²⁶⋅❨B₂₅ᵐᵒᵈ2³❩ | ⌊2⁻³⋅B₂₅⌋ ⋯
            OP_FROMALTSTACK OP_SWAP OP_TOALTSTACK
            // ⋯ B₂₆ B₂₇ ⌊2⁻³⋅B₂₅⌋ | ⌊2⁻⁶⋅B₂₁⌋+2²⋅B₂₂+2¹⁰⋅B₂₃+2¹⁸⋅B₂₄+2²⁶⋅❨B₂₅ᵐᵒᵈ2³❩ ⋯

            //  ⌊2⁻³⋅B₂₅⌋ + 2⁵⋅B₂₆ + 2¹³⋅B₂₇ + 2²¹⋅B₂₈
            // ⋯ B₂₈ B₂₉ B₃₀ B₃₁ B₂₆ B₂₇ ⌊2⁻³⋅B₂₅⌋
            OP_TOALTSTACK
            // ⋯ B₂₈ B₂₉ B₃₀ B₃₁ B₂₆ B₂₇ | ⌊2⁻³⋅B₂₅⌋ ⋯
            OP_5 OP_ROLL
            // ⋯ B₂₉ B₃₀ B₃₁ B₂₆ B₂₇ B₂₈
            OP_256MUL OP_ADD
            // ⋯ B₂₉ B₃₀ B₃₁ B₂₆ B₂₇+2⁸⋅B₂₈
            OP_256MUL OP_ADD
            // ⋯ B₂₉ B₃₀ B₃₁ B₂₆+2⁸⋅B₂₇+2¹⁶⋅B₂₈
            for _ in 3..8 { OP_DUP OP_ADD }
            // ⋯ B₂₉ B₃₀ B₃₁ 2⁵⋅B₂₆+2¹³⋅B₂₇+2²¹⋅B₂₈
            OP_FROMALTSTACK OP_ADD OP_TOALTSTACK // 29
            // ⋯ B₂₉ B₃₀ B₃₁ | ⌊2⁻³⋅B₂₅⌋+2⁵⋅B₂₆+2¹³⋅B₂₇+2²¹⋅B₂₈ ⋯

            //  2⁰⋅B₂₉ + 2⁸⋅B₃₀ + 2¹⁶⋅B₃₁
            // ⋯ B₂₉ B₃₀ B₃₁
            { 0x80 } OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_4 OP_ELSE OP_DROP OP_0 OP_ENDIF OP_TOALTSTACK
            { 0x40 } OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_2 OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_ELSE OP_DROP OP_ENDIF
            { 0x20 } OP_2DUP OP_GREATERTHANOREQUAL OP_IF OP_SUB OP_1 OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_ELSE OP_DROP OP_ENDIF
            // ⋯ B₂₉ B₃₀ B₃₁ᵐᵒᵈ2⁵ | ⌊2⁻⁵⋅B₃₁⌋ ⋯
            OP_256MUL OP_ADD
            // ⋯ B₂₉ B₃₀+2⁸⋅❨B₃₁ᵐᵒᵈ2⁵❩
            OP_256MUL OP_ADD
            // ⋯ B₂₉+2⁸⋅B₃₀+2¹⁶⋅❨B₃₁ᵐᵒᵈ2⁵❩
            OP_FROMALTSTACK OP_SWAP
            // ⋯ ⌊2⁻⁵⋅B₃₁⌋  B₂₉+2⁸⋅B₃₀+2¹⁶⋅❨B₃₁ᵐᵒᵈ2⁵❩ | ⌊2⁻³⋅B₂₅⌋+2⁵⋅B₂₆+2¹³⋅B₂₇+2²¹⋅B₂₈ ⋯
            OP_FROMALTSTACK
            // ⋯ ⌊2⁻³⋅B₂₅⌋+2⁵⋅B₂₆+2¹³⋅B₂₇+2²¹⋅B₂₈ | ⌊2⁻⁶⋅B₂₁⌋+2²⋅B₂₂+2¹⁰⋅B₂₃+2¹⁸⋅B₂₄+2²⁶⋅❨B₂₅ᵐᵒᵈ2³❩ ⋯
            OP_FROMALTSTACK
            // ⋯ ⌊2⁻⁶⋅B₂₁⌋+2²⋅B₂₂+2¹⁰⋅B₂₃+2¹⁸⋅B₂₄+2²⁶⋅❨B₂₅ᵐᵒᵈ2³❩ | ⌊2⁻¹⋅B₁₈⌋+2⁷⋅B₁₉+2¹⁵⋅B₂₀+2²³⋅❨B₂₁ᵐᵒᵈ2⁶❩ ⋯
            OP_FROMALTSTACK
            // ⋯ ⌊2⁻¹⋅B₁₈⌋+2⁷⋅B₁₉+2¹⁵⋅B₂₀+2²³⋅❨B₂₁ᵐᵒᵈ2⁶❩ | ⌊2⁻⁴⋅B₁₄⌋+2⁴⋅B₁₅+2¹²⋅B₁₆+2²⁰⋅B₁₇+2²⁸⋅❨B₁₈ᵐᵒᵈ2¹❩ ⋯
            OP_FROMALTSTACK
            // ⋯ ⌊2⁻⁴⋅B₁₄⌋+2⁴⋅B₁₅+2¹²⋅B₁₆+2²⁰⋅B₁₇+2²⁸⋅❨B₁₈ᵐᵒᵈ2¹❩ | ⌊2⁻⁷⋅B₁₀⌋+2¹⋅B₁₁+2⁹⋅B₁₂+2¹⁷⋅B₁₃+2²⁵⋅❨B₁₄ᵐᵒᵈ2⁴❩ ⋯
            OP_FROMALTSTACK
            // ⋯ ⌊2⁻⁷⋅B₁₀⌋+2¹⋅B₁₁+2⁹⋅B₁₂+2¹⁷⋅B₁₃+2²⁵⋅❨B₁₄ᵐᵒᵈ2⁴❩ | ⌊2⁻²⋅B₇⌋+2⁶⋅B₈+2¹⁴⋅B₉+2²²⋅❨B₁₀ᵐᵒᵈ2⁷❩ ⋯
            OP_FROMALTSTACK
            // ⋯ ⌊2⁻²⋅B₇⌋+2⁶⋅B₈+2¹⁴⋅B₉+2²²⋅❨B₁₀ᵐᵒᵈ2⁷❩ | ⌊2⁻⁵⋅B₃⌋+2³⋅B₄+2¹¹⋅B₅+2¹⁹⋅B₆+2²⁷⋅❨B₇ᵐᵒᵈ2²❩ ⋯
            OP_FROMALTSTACK
            // ⋯ ⌊2⁻⁵⋅B₃⌋+2³⋅B₄+2¹¹⋅B₅+2¹⁹⋅B₆+2²⁷⋅❨B₇ᵐᵒᵈ2²❩ | B₀+2⁸⋅B₁+2¹⁶⋅B₂+2²⁴⋅❨B₃ᵐᵒᵈ2⁵❩ ⋯
            OP_FROMALTSTACK
            // ⋯ B₀+2⁸⋅B₁+2¹⁶⋅B₂+2²⁴⋅❨B₃ᵐᵒᵈ2⁵❩

            // encode montgomery
            { Self::mul_by_constant(&Self::ConstantType::from(BigUint::from_str_radix(Self::MONTGOMERY_ONE, 16).unwrap())) }

            // ⌊2⁻⁵⋅B₃₁⌋
            OP_9 OP_PICK OP_7 OP_NUMEQUAL
            OP_IF
                { Self::push_u32_le(&c.clone().add(b.clone()).add(a.clone()).rem(modulus.clone()).to_u32_digits()) }
            OP_ELSE
                OP_9 OP_PICK OP_6 OP_NUMEQUAL
                OP_IF
                    { Self::push_u32_le(&c.clone().add(b.clone()).rem(modulus.clone()).to_u32_digits()) }
                OP_ELSE
                    OP_9 OP_PICK OP_5 OP_NUMEQUAL
                    OP_IF
                        { Self::push_u32_le(&c.clone().add(a.clone()).rem(modulus.clone()).to_u32_digits()) }
                    OP_ELSE
                        OP_9 OP_PICK OP_4 OP_NUMEQUAL
                        OP_IF
                            { Self::push_u32_le(&c.clone().rem(modulus.clone()).to_u32_digits()) }
                        OP_ELSE
                            OP_9 OP_PICK OP_3 OP_NUMEQUAL
                            OP_IF
                                { Self::push_u32_le(&a.clone().add(b.clone()).rem(modulus.clone()).to_u32_digits()) }
                            OP_ELSE
                                OP_9 OP_PICK OP_2 OP_NUMEQUAL
                                OP_IF
                                    { Self::push_u32_le(&b.clone().rem(modulus.clone()).to_u32_digits()) }
                                OP_ELSE
                                    OP_9 OP_PICK OP_1 OP_NUMEQUAL
                                    OP_IF
                                        { Self::push_u32_le(&a.clone().rem(modulus.clone()).to_u32_digits()) }
                                    OP_ELSE
                                        { Self::push_zero() }
                                    OP_ENDIF
                                OP_ENDIF
                            OP_ENDIF
                        OP_ENDIF
                    OP_ENDIF
                OP_ENDIF
            OP_ENDIF

            { Self::add(1, 0) }

            OP_9 OP_ROLL OP_DROP

        }
    }

    fn convert_to_be_bytes() -> Script {
        let build_u8_from_be_bits = |i| {
            script! {
                for _ in 0..(i - 1) {
                    OP_DUP OP_ADD OP_ADD
                }
            }
        };

        script! {
            { Self::decode_montgomery() }
            // start with the top limb
            // 30 bits => 6 + 8 bytes
            { Self::N_LIMBS - 1 } OP_ROLL
            { limb_to_be_bits(22) }
            { build_u8_from_be_bits(6) } OP_TOALTSTACK
            { build_u8_from_be_bits(8) } OP_TOALTSTACK
            { build_u8_from_be_bits(8) } OP_TOALTSTACK

            // second limb, 30 bits => 3 bytes + 6 leftover bits
            { Self::N_LIMBS - 2 } OP_ROLL
            { limb_to_be_bits(29) }
            { build_u8_from_be_bits(8) } OP_TOALTSTACK
            { build_u8_from_be_bits(8) } OP_TOALTSTACK
            { build_u8_from_be_bits(8) } OP_TOALTSTACK
            { build_u8_from_be_bits(5) } OP_TOALTSTACK

            // third limb, 30 bits = 2 bits borrow + 3 bytes + 4 leftover bits
            { Self::N_LIMBS - 3 } OP_ROLL
            { limb_to_be_bits(29) }
            OP_FROMALTSTACK
            { build_u8_from_be_bits(4) } OP_TOALTSTACK
            { build_u8_from_be_bits(8) } OP_TOALTSTACK
            { build_u8_from_be_bits(8) } OP_TOALTSTACK
            { build_u8_from_be_bits(8) } OP_TOALTSTACK
            { build_u8_from_be_bits(2) } OP_TOALTSTACK

            // fourth limb, 30 bits = 4 bits borrow + 3 bytes + 2 leftover bits
            { Self::N_LIMBS - 4 } OP_ROLL
            { limb_to_be_bits(29) }
            OP_FROMALTSTACK
            { build_u8_from_be_bits(7) } OP_TOALTSTACK
            { build_u8_from_be_bits(8) } OP_TOALTSTACK
            { build_u8_from_be_bits(8) } OP_TOALTSTACK
            { build_u8_from_be_bits(7) } OP_TOALTSTACK

            // fifth limb, 30 bits = 6 bits borrow + 3 bytes
            { Self::N_LIMBS - 5 } OP_ROLL
            { limb_to_be_bits(29) }
            OP_FROMALTSTACK
            { build_u8_from_be_bits(2) } OP_TOALTSTACK
            { build_u8_from_be_bits(8) } OP_TOALTSTACK
            { build_u8_from_be_bits(8) } OP_TOALTSTACK
            { build_u8_from_be_bits(8) } OP_TOALTSTACK
            { build_u8_from_be_bits(4) } OP_TOALTSTACK

            // sixth limb, 30 bits => 3 bytes + 6 leftover bits
            { Self::N_LIMBS - 6 } OP_ROLL
            { limb_to_be_bits(29) }
            OP_FROMALTSTACK
            { build_u8_from_be_bits(5) } OP_TOALTSTACK
            { build_u8_from_be_bits(8) } OP_TOALTSTACK
            { build_u8_from_be_bits(8) } OP_TOALTSTACK
            { build_u8_from_be_bits(8) } OP_TOALTSTACK
            { build_u8_from_be_bits(1) } OP_TOALTSTACK

            // seventh limb, 30 bits = 2 bits borrow + 3 bytes + 4 leftover bits
            { Self::N_LIMBS - 7 } OP_ROLL
            { limb_to_be_bits(29) }
            OP_FROMALTSTACK
            { build_u8_from_be_bits(8) } OP_TOALTSTACK
            { build_u8_from_be_bits(8) } OP_TOALTSTACK
            { build_u8_from_be_bits(8) } OP_TOALTSTACK
            { build_u8_from_be_bits(6) } OP_TOALTSTACK

            // eighth limb, 30 bits = 4 bits borrow + 3 bytes + 2 leftover bits
            { Self::N_LIMBS - 8 } OP_ROLL
            { limb_to_be_bits(29) }
            OP_FROMALTSTACK
            { build_u8_from_be_bits(3) } OP_TOALTSTACK
            { build_u8_from_be_bits(8) } OP_TOALTSTACK
            { build_u8_from_be_bits(8) } OP_TOALTSTACK
            { build_u8_from_be_bits(8) } OP_TOALTSTACK
            { build_u8_from_be_bits(3) } OP_TOALTSTACK

            // ninth limb, 30 bits = 6 bits borrow + 3 bytes
            { Self::N_LIMBS - 9 } OP_ROLL
            { limb_to_be_bits(29) }
            OP_FROMALTSTACK
            { build_u8_from_be_bits(6) } OP_TOALTSTACK
            { build_u8_from_be_bits(8) } OP_TOALTSTACK
            { build_u8_from_be_bits(8) } OP_TOALTSTACK
            { build_u8_from_be_bits(8) }

            for _ in 0..31 {
                OP_FROMALTSTACK
            }
        }
    }

    fn convert_to_be_u4() -> Script {
        let build_u8_from_be_bits = |i| {
            script! {
                for _ in 0..(i - 1) {
                    OP_DUP OP_ADD OP_ADD
                }
            }
        };

        script! {
            // { Self::decode_montgomery() }
            // start with the top limb
            // 22 bits => 2 + 5 u4
            { Self::N_LIMBS - 1 } OP_ROLL
            { limb_to_be_bits(22) }
            { build_u8_from_be_bits(2) } OP_TOALTSTACK
            for _ in 0..5 {
                { build_u8_from_be_bits(4) } OP_TOALTSTACK
            }

            // second limb, 29 bits => 7 u4 + 1 leftover bits
            { Self::N_LIMBS - 2 } OP_ROLL
            { limb_to_be_bits(29) }
            for _ in 0..7 {
                { build_u8_from_be_bits(4) } OP_TOALTSTACK
            }
            { build_u8_from_be_bits(1) } OP_TOALTSTACK

            // third limb, 29 bits = 3 bits borrow + 6 u4 + 2 leftover bits
            { Self::N_LIMBS - 3 } OP_ROLL
            { limb_to_be_bits(29) }
            OP_FROMALTSTACK
            { build_u8_from_be_bits(4) } OP_TOALTSTACK
            for _ in 0..6 {
                { build_u8_from_be_bits(4) } OP_TOALTSTACK
            }
            { build_u8_from_be_bits(2) } OP_TOALTSTACK

            // fourth limb, 29 bits = 2 bits borrow + 6 u4 + 3 leftover bits
            { Self::N_LIMBS - 4 } OP_ROLL
            { limb_to_be_bits(29) }
            OP_FROMALTSTACK
            { build_u8_from_be_bits(3) } OP_TOALTSTACK
            for _ in 0..6 {
                { build_u8_from_be_bits(4) } OP_TOALTSTACK
            }
            { build_u8_from_be_bits(3) } OP_TOALTSTACK

            // fifth limb, 30 bits = 1 bits borrow + 7 u4
            { Self::N_LIMBS - 5 } OP_ROLL
            { limb_to_be_bits(29) }
            OP_FROMALTSTACK
            { build_u8_from_be_bits(2) } OP_TOALTSTACK
            for _ in 0..7 {
                { build_u8_from_be_bits(4) } OP_TOALTSTACK
            }

            // sixth limb, 30 bits => 7 u4 + 1 leftover bits
            { Self::N_LIMBS - 6 } OP_ROLL
            { limb_to_be_bits(29) }
            for _ in 0..7 {
                { build_u8_from_be_bits(4) } OP_TOALTSTACK
            }
            { build_u8_from_be_bits(1) } OP_TOALTSTACK

            // seventh limb, 30 bits = 3 bits borrow + 6 u4 + 2 leftover bits
            { Self::N_LIMBS - 7 } OP_ROLL
            { limb_to_be_bits(29) }
            OP_FROMALTSTACK
            { build_u8_from_be_bits(4) } OP_TOALTSTACK
            for _ in 0..6 {
                { build_u8_from_be_bits(4) } OP_TOALTSTACK
            }
            { build_u8_from_be_bits(2) } OP_TOALTSTACK

            // eighth limb, 30 bits = 2 bits borrow + 6 u4 + 3 leftover bits
            { Self::N_LIMBS - 8 } OP_ROLL
            { limb_to_be_bits(29) }
            OP_FROMALTSTACK
            { build_u8_from_be_bits(3) } OP_TOALTSTACK
            for _ in 0..6 {
                { build_u8_from_be_bits(4) } OP_TOALTSTACK
            }
            { build_u8_from_be_bits(3) } OP_TOALTSTACK

            // ninth limb, 29 bits = 1 bits borrow + 7 u4
            { Self::N_LIMBS - 9 } OP_ROLL
            { limb_to_be_bits(29) }
            OP_FROMALTSTACK
            { build_u8_from_be_bits(2) } OP_TOALTSTACK
            for _ in 0..6 {
                { build_u8_from_be_bits(4) } OP_TOALTSTACK
            }
            { build_u8_from_be_bits(4) }

            for _ in 0..63 {
                OP_FROMALTSTACK
            }
        }
    }

    fn toaltstack() -> Script { U254::toaltstack() }

    fn fromaltstack() -> Script { U254::fromaltstack() }
}
