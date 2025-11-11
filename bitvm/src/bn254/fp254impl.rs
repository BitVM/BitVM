use crate::bigint::add::limb_add_carry;
use crate::bigint::sub::limb_sub_borrow;
use crate::bigint::U254;
use crate::treepp::*;
use ark_ff::PrimeField;
use bitcoin_script::script;
use num_bigint::{BigInt, BigUint};
use num_traits::Num;
use std::sync::OnceLock;

#[allow(clippy::declare_interior_mutable_const)]
pub trait Fp254Impl {
    const N_LIMBS: u32 = U254::N_LIMBS;
    const N_BITS: u32 = U254::N_BITS;

    const MODULUS: &'static str;
    const MODULUS_LIMBS: [u32; U254::N_LIMBS as usize];

    const P_PLUS_ONE_DIV2: &'static str;
    const TWO_P_PLUS_ONE_DIV3: &'static str;
    const P_PLUS_TWO_DIV3: &'static str;

    const ADD_ONCELOCK: OnceLock<Script> = OnceLock::new();
    const SUB_ONCELOCK: OnceLock<Script> = OnceLock::new();

    type ConstantType: PrimeField;

    fn modulus_as_bigint() -> BigInt {
        BigInt::from_str_radix(Self::MODULUS, 16).unwrap()
    }

    #[inline]
    fn copy(a: u32) -> Script {
        U254::copy(a)
    }

    #[inline]
    fn roll(a: u32) -> Script {
        U254::roll(a)
    }

    #[inline]
    fn drop() -> Script {
        U254::drop()
    }

    #[inline]
    fn toaltstack() -> Script {
        U254::toaltstack()
    }

    #[inline]
    fn fromaltstack() -> Script {
        U254::fromaltstack()
    }

    #[inline]
    fn zip(a: u32, b: u32) -> Script {
        U254::zip(a, b)
    }

    #[inline]
    fn push_modulus() -> Script {
        U254::push_hex(Self::MODULUS)
    }

    #[inline]
    fn push_zero() -> Script {
        U254::push_zero()
    }

    #[inline]
    fn push_one() -> Script {
        U254::push_one()
    }

    #[inline]
    fn push_u32_le(v: &[u32]) -> Script {
        script! {
            { U254::push_u32_le(&BigUint::from_slice(v).to_u32_digits()) }
        }
    }

    #[inline]
    fn read_u32_le(witness: Vec<Vec<u8>>) -> Vec<u32> {
        U254::read_u32_le(witness)
    }

    #[inline]
    fn push_dec(dec_string: &str) -> Script {
        let v = BigUint::from_str_radix(dec_string, 10).unwrap();
        script! {
            { U254::push_u32_le(&v.to_u32_digits()) }
        }
    }

    #[inline]
    fn push_hex(hex_string: &str) -> Script {
        let v = BigUint::from_str_radix(hex_string, 16).unwrap();
        script! {
            { U254::push_u32_le(&v.to_u32_digits()) }
        }
    }

    #[inline]
    fn equal(a: u32, b: u32) -> Script {
        U254::equal(a, b)
    }

    #[inline]
    fn equal_keep_elements(a: u32, b: u32) -> Script {
        U254::equal_keep_elements(a, b)
    }

    #[inline]
    fn equalverify(a: u32, b: u32) -> Script {
        U254::equalverify(a, b)
    }

    fn is_zero(a: u32) -> Script {
        U254::is_zero(a)
    }

    fn is_zero_keep_element(a: u32) -> Script {
        U254::is_zero_keep_element(a)
    }

    fn is_one() -> Script {
        script! {
            { Self::push_one() }
            { Self::equal(1, 0) }
        }
    }

    fn is_one_verify() -> Script {
        script! {
            OP_1
            OP_EQUALVERIFY
            for _ in 0..Self::N_LIMBS-1 {
                OP_NOT OP_VERIFY
            }
        }
    }

    fn is_one_keep_element(a: u32) -> Script {
        script! {
            { Self::copy(a) }
            { Self::is_one() }
        }
    }

    #[inline]
    fn convert_to_le_bits_toaltstack() -> Script {
        U254::convert_to_le_bits_toaltstack()
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
                    OP_SWAP
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
            { Self::is_zero_keep_element(0) }
            OP_NOTIF
                for i in 0..Self::N_LIMBS-1 {
                    { Self::MODULUS_LIMBS[i as usize] } OP_SWAP
                    if i == 0 {
                        { 2_usize.pow(U254::LIMB_SIZE) }
                    } else {
                        OP_ROT
                    }
                    limb_sub_borrow OP_TOALTSTACK
                    if i == Self::N_LIMBS-2 {
                        OP_NIP
                    } else {
                        OP_ROT
                    }
                    OP_ADD
                }
                { Self::MODULUS_LIMBS[Self::N_LIMBS as usize - 1] } OP_SWAP OP_SUB
                for _ in 0..Self::N_LIMBS-1 {
                    OP_FROMALTSTACK
                }
            OP_ENDIF
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
            // ⋯ 2⋅A₈+C₇⁺ 2⋅A₇+C₆⁺ ... 2⋅A₁+C₀⁺ 2⋅A₀
            // ⋯ (2⋅A₈+C₇⁺)-(C₇⁻+M₈) ... 2⋅A₀-M₀
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

    // verifies that the element at the top of the stack is less than the modulo and valid (limbs are in range)
    // doesn't consume the element, instead sends it to the altstack
    fn check_validity() -> Script {
        let limbs_of_c = U254::biguint_to_limbs(Self::modulus_as_bigint().to_biguint().unwrap());
        script! {
            // (Assuming limbs are numbered big endian)
            // Number A is greater than number B <=> there exists a limb i, s.t. (A_i > B_i OR (A_i >= B_i and i is the first limb)) and there's no limb j > i satisfying A_i < B_i
            // Script below maintains if such state exists for each i behind the foremost limb, combining the results and negating them if there is such j
            for i in 0..(Self::N_LIMBS as usize) {
                OP_DUP OP_DUP OP_TOALTSTACK
                { 0 } { 1 << U254::LIMB_SIZE } OP_WITHIN OP_VERIFY
                if i == 0 {
                    { limbs_of_c[i] }
                    OP_GREATERTHANOREQUAL
                } else {
                    { limbs_of_c[i] } OP_2DUP
                    OP_GREATERTHAN OP_TOALTSTACK
                    OP_GREATERTHANOREQUAL
                    OP_BOOLAND
                    OP_FROMALTSTACK OP_BOOLOR
                }
                if i == (Self::N_LIMBS as usize) - 1 {
                    OP_NOT OP_VERIFY //This OP_NOT can be negated, but it probably isn't necessary
                } else {
                    OP_SWAP
                }
            }
        }
    }

    fn check_validity_and_keep_element() -> Script {
        script! {
            { Self::check_validity() }
            for _ in 0..Self::N_LIMBS {
                OP_FROMALTSTACK
            }
        }
    }

    // finds if the element at the top of the stack is less than the modulo and valid (limbs are in range)
    // consumes the element, leaves the result at the topstack
    fn is_valid() -> Script {
        let limbs_of_c = U254::biguint_to_limbs(Self::modulus_as_bigint().to_biguint().unwrap());
        script! {
            // (Assuming limbs are numbered big endian)
            // Number A is greater than number B <=> there exists a limb i, s.t. (A_i > B_i OR (A_i >= B_i and i is the first limb)) and there's no limb j > i satisfying A_i < B_i
            // Script below maintains if such state exists for each i behind the foremost limb, combining the results and negating them if there is such j
            for i in 0..(Self::N_LIMBS as usize) {
                OP_DUP
                { 0 } { 1 << U254::LIMB_SIZE } OP_WITHIN
                if i == 0 {
                    OP_TOALTSTACK //u254 validity check

                    { limbs_of_c[i] }
                    OP_GREATERTHANOREQUAL
                } else {
                    OP_FROMALTSTACK OP_BOOLAND OP_TOALTSTACK //u254 validity check

                    { limbs_of_c[i] } OP_2DUP
                    OP_GREATERTHAN OP_TOALTSTACK
                    OP_GREATERTHANOREQUAL
                    OP_BOOLAND
                    OP_FROMALTSTACK OP_BOOLOR
                }
                if i == (Self::N_LIMBS as usize) - 1 {
                    OP_NOT //This OP_NOT can be negated, but it probably isn't necessary
                    OP_FROMALTSTACK
                    OP_BOOLAND
                } else {
                    OP_SWAP
                }
            }
        }
    }
}
