use crate::bigint::add::limb_add_carry;
use crate::bigint::bits::{limb_to_be_bits, limb_to_be_bits_toaltstack};
use crate::bigint::sub::limb_sub_borrow;
use crate::bigint::U254;
use crate::bn254::fq::fq_mul_montgomery;
use crate::pseudo::OP_256MUL;
use crate::treepp::*;
use ark_ff::PrimeField;
use bitcoin_script::script;
use num_bigint::BigUint;
use num_traits::{Num, One};
use std::ops::{Rem, Shl};
use std::sync::OnceLock;

use std::ops::Mul;

pub trait Fp254Impl {
    const MODULUS: &'static str;
    const N_LIMBS: u32 = U254::N_LIMBS;
    const N_BITS: u32 = U254::N_BITS;

    // Modulus as 30-bit limbs
    const MODULUS_LIMBS: [u32; U254::N_LIMBS as usize];

    const P_PLUS_ONE_DIV2: &'static str;
    const TWO_P_PLUS_ONE_DIV3: &'static str;
    const P_PLUS_TWO_DIV3: &'static str;

    const ADD_ONCELOCK: OnceLock<Script> = OnceLock::new();
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
    fn push_u32_le(v: &[u32]) -> Script { U254::push_u32_le(v) }

    #[inline]
    fn equal(a: u32, b: u32) -> Script { U254::equal(a, b) }

    #[inline]
    fn equalverify(a: u32, b: u32) -> Script { U254::equalverify(a, b) }

    #[inline]
    fn push_dec(dec_string: &str) -> Script { U254::push_dec(dec_string) }

    #[inline]
    fn push_hex(hex_string: &str) -> Script { U254::push_hex(hex_string) }

    #[inline]
    fn convert_to_be_bits() -> Script { U254::convert_to_be_bits() }

    #[inline]
    fn convert_to_be_bits_toaltstack() -> Script { U254::convert_to_be_bits_toaltstack() }

    #[inline]
    fn convert_to_le_bits() -> Script { U254::convert_to_le_bits() }

    #[inline]
    fn convert_to_le_bits_toaltstack() -> Script { U254::convert_to_le_bits_toaltstack() }

    #[inline]
    fn push_modulus() -> Script { Self::push_hex(Self::MODULUS) }

    #[inline]
    fn push_zero() -> Script { U254::push_zero() }

    // #[inline]
    // fn push_one() -> Script { U254::push_one() }
    fn push_one() -> Script;

    // A + B mod M
    // Ci⁺ overflow carry bit (A+B)
    // Ci⁻ overflow carry bit (A-B)
    fn add(a: u32, b: u32) -> Script {
        let binding = Self::ADD_ONCELOCK;
        let add_script = binding.get_or_init(|| {
            script! {
                { 1 << 29 }
                // A₀ + B₀
                limb_add_carry
                // A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ B₁ 2³⁰ C₀⁺ A₀+B₀
                OP_DUP
                OP_TOALTSTACK
                // A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ B₁ 2³⁰ C₀⁺ A₀+B₀ | A₀+B₀
                OP_ROT
                // A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ B₁ C₀⁺ A₀+B₀ 2³⁰
                { Self::MODULUS_LIMBS[0] }
                OP_SWAP
                // A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ B₁ C₀⁺ A₀+B₀ M₀ 2³⁰
                limb_sub_borrow
                OP_TOALTSTACK
                // A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ B₁ C₀⁺ 2³⁰ C₀⁻ | (A₀+B₀)-M₀

                // from     A₁      + B₁        + carry_0
                //   to     A{N-2}  + B{N-2}    + carry_{N-3}
                for i in 1..Self::N_LIMBS-1 {
                    OP_2SWAP
                    // A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ 2³⁰ C₀⁻ B₁ C₀⁺
                    OP_ADD
                    // A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ 2³⁰ C₀⁻ B₁+C₀⁺
                    OP_2SWAP
                    // A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ C₀⁻ B₁+C₀⁺ A₁ 2³⁰
                    limb_add_carry
                    OP_DUP
                    OP_TOALTSTACK
                    // A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ C₀⁻ 2³⁰ C₁⁺ (B₁+C₀)+A₁ | (B₁+C₀)+A₁
                    OP_2SWAP
                    OP_SWAP
                    // A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ C₁⁺ (B₁+C₀)+A₁ 2³⁰ C₀⁻
                    { Self::MODULUS_LIMBS[i as usize] }
                    // A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ C₁⁺ (B₁+C₀)+A₁ 2³⁰ C₀⁻ M₁
                    OP_ADD
                    // A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ C₁⁺ (B₁+C₀)+A₁ 2³⁰ C₀⁻+M₁
                    OP_ROT
                    OP_SWAP
                    OP_ROT
                    // A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ C₁⁺ (B₁+C₀)+A₁ C₀⁻+M₁ 2³⁰
                    limb_sub_borrow
                    OP_TOALTSTACK
                    // A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ C₁⁺ 2³⁰ C₁⁻ | ((B₁+C₀)+A₁)-(C₀⁻+M₁)
                }
                // A₈ B₈ C₇⁺ 2³⁰ C₇⁻
                OP_2SWAP
                OP_ADD
                // A₈ 2³⁰ C₇⁻ B₈+C₇⁺
                OP_2SWAP
                OP_ROT
                OP_ROT
                // C₇⁻ 2³⁰ B₈+C₇⁺ A₈
                OP_ADD
                // C₇⁻ 2³⁰ (B₈+C₇⁺)+A₈
                OP_DUP
                OP_TOALTSTACK
                OP_ROT
                // 2³⁰ (B₈+C₇⁺)+A₈ C₇⁻
                { *Self::MODULUS_LIMBS.last().unwrap() }
                // 2³⁰ (B₈+C₇⁺)+A₈ C₇⁻ M₈
                OP_ADD
                OP_ROT
                // (B₈+C₇⁺)+A₈ C₇⁻+M₈ 2³⁰
                limb_sub_borrow
                OP_TOALTSTACK
                // 2³⁰ C₈⁻ | ((B₈+C₇⁺)+A₈)-(C₇⁻+M₈)
                OP_NIP
                OP_DUP
                // C₈⁻ C₈⁻
                OP_IF
                    OP_FROMALTSTACK
                    OP_DROP
                OP_ENDIF

                OP_FROMALTSTACK
                // (B₈+C₇⁺)+A₈ C₈⁻ | ((B₇+C₆⁺)+A₇)-(C₆⁻+M₇)
                // ((B₈+C₇⁺)+A₈)-(C₇⁻+M₈) C₈⁻ | (B₈+C₇⁺)+A₈
                for _ in 0..Self::N_LIMBS-1 {
                    OP_FROMALTSTACK  OP_DROP
                    OP_FROMALTSTACK
                }
                // (B₈+C₇⁺)+A₈ (B₇+C₆⁺)+A₇ ... (B₂+C₁⁺)+A₂ (B₁+C₀⁺)+A₁ A₀+B₀ C₈⁻
                // ((B₈+C₇⁺)+A₈)-(C₇⁻+M₈) ... (A₀+B₀)-M₀ C₈⁻ | A₀+B₀
                { Self::N_LIMBS }
                OP_ROLL
                OP_NOT
                OP_IF
                    OP_FROMALTSTACK
                    OP_DROP
                OP_ENDIF
                // (B₈+C₇⁺)+A₈ (B₇+C₆⁺)+A₇ ... (B₁+C₀⁺)+A₁ A₀+B₀
                // ((B₈+C₇⁺)+A₈)-(C₇⁻+M₈) ... (A₀+B₀)-M₀
            }
        });
        script! {
            { Self::zip(a, b) }
            { add_script.clone() }
        }
    }

    fn neg(a: u32) -> Script {
        script! {
            { Self::push_modulus() }
            { U254::sub(0, a + 1) }
        }
    }

    fn sub(a: u32, b: u32) -> Script {
        script! {
            { Self::neg(b) }
            if a > b {
                { Self::add(0, a) }
            } else {
                { Self::add(0, a + 1) }
            }
        }
    }

    fn double(a: u32) -> Script {
        script! {
            { Self::copy(a) }
            { Self::add(a + 1, 0) }
        }
    }

    fn mul() -> Script;

    // fn mul() -> Script {
    //     Self::MUL_ONCELOCK
    //         .get_or_init(|| {
    //             script! {
    //                 { fq_mul_montgomery(1, 0) }
    //             }
    //         })
    //         .clone()
    // }

    fn _mul() -> Script {
        Self::MUL_ONCELOCK
            .get_or_init(|| {
                script! {
                    for i in 0..Self::N_LIMBS - 1 {
                        {Self::N_LIMBS - 1 - i} OP_ROLL
                        OP_TOALTSTACK
                    }

                    { limb_to_be_bits_toaltstack(29) }

                    { Self::push_zero() }

                    OP_FROMALTSTACK
                    OP_IF
                        { Self::copy(1) }
                        { Self::add(1, 0) }
                    OP_ENDIF

                    // handle the first limb
                    for _ in 1..29 {
                        { Self::roll(1) }
                        { Self::double(0) }
                        { Self::roll(1) }
                        OP_FROMALTSTACK
                        OP_IF
                            { Self::copy(1) }
                            { Self::add(1, 0) }
                        OP_ENDIF
                    }

                    for _ in 1..Self::N_LIMBS - 1 {
                        OP_FROMALTSTACK
                        { limb_to_be_bits_toaltstack(29) }

                        for _ in 0..29 {
                            { Self::roll(1) }
                            { Self::double(0) }
                            { Self::roll(1) }
                            OP_FROMALTSTACK
                            OP_IF
                                { Self::copy(1) }
                                { Self::add(1, 0) }
                            OP_ENDIF
                        }
                    }

                    OP_FROMALTSTACK
                    { limb_to_be_bits_toaltstack(Self::N_BITS - 29 * (Self::N_LIMBS - 1)) }

                    for _ in 0..(Self::N_BITS - 29 * (Self::N_LIMBS - 1)) - 1 {
                        { Self::roll(1) }
                        { Self::double(0) }
                        { Self::roll(1) }
                        OP_FROMALTSTACK
                        OP_IF
                            { Self::copy(1) }
                            { Self::add(1, 0) }
                        OP_ENDIF
                    }

                    { Self::roll(1) }
                    { Self::double(0) }
                    OP_FROMALTSTACK
                    OP_IF
                        { Self::add(1, 0) }
                    OP_ELSE
                        { Self::drop() }
                    OP_ENDIF
                }
            })
            .clone()
    }

    fn is_zero(a: u32) -> Script { U254::is_zero(a) }

    fn is_one(a: u32) -> Script { U254::is_one(a) }

    fn is_zero_keep_element(a: u32) -> Script { U254::is_zero_keep_element(a) }

    fn is_one_keep_element(a: u32) -> Script { U254::is_one_keep_element(a) }

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
            { Self::copy(0) }
            { Self::mul() }
        }
    }

    fn inv_montgomery() -> Script;

    fn inv() -> Script {
        script! {
            { Self::push_modulus() }
            { Self::roll(1) }
            { U254::inv_stage1() }
            { U254::inv_stage2(Self::MODULUS) }
            { Self::_mul() }
            { Self::inv_montgomery() }
        }
    }

    fn mul_by_constant(constant: &Self::ConstantType) -> Script {
        let mut naf = ark_ff::biginteger::arithmetic::find_naf(constant.into_bigint().as_ref());

        if naf.len() > 3 {
            let len = naf.len();
            if naf[len - 2] == 0 && naf[len - 3] == -1 {
                naf[len - 3] = 1;
                naf[len - 2] = 1;
                naf.resize(len - 1, 0);
            }
        }

        let mut cur = 0usize;

        let mut script_bytes = vec![];

        let double = Self::double(0);

        while cur < naf.len() && naf[cur] == 0 {
            script_bytes.extend_from_slice(double.as_bytes());
            cur += 1;
        }

        if cur < naf.len() {
            if naf[cur] == 1 {
                script_bytes.extend_from_slice(Self::copy(0).as_bytes());
                script_bytes.extend_from_slice(double.as_bytes());
                cur += 1;
            } else if naf[cur] == -1 {
                script_bytes.extend_from_slice(
                    script! {
                        { Self::copy(0) }
                        { Self::neg(0) }
                        { Self::roll(1) }
                    }
                    .as_bytes(),
                );
                script_bytes.extend_from_slice(double.as_bytes());
                cur += 1;
            } else {
                unreachable!()
            }
        } else {
            script_bytes.extend_from_slice(
                script! {
                    { Self::drop() }
                    { Self::push_zero() }
                }
                .as_bytes(),
            );

            return Script::from(script_bytes);
        }

        if cur < naf.len() {
            while cur < naf.len() {
                if naf[cur] == 0 {
                    script_bytes.extend_from_slice(double.as_bytes());
                } else if naf[cur] == 1 {
                    script_bytes.extend_from_slice(
                        script! {
                            { Self::roll(1) }
                            { Self::copy(1) }
                            { Self::add(1, 0) }
                            { Self::roll(1) }
                        }
                        .as_bytes(),
                    );
                    if cur != naf.len() - 1 {
                        script_bytes.extend_from_slice(double.as_bytes());
                    }
                } else if naf[cur] == -1 {
                    script_bytes.extend_from_slice(
                        script! {
                            { Self::roll(1) }
                            { Self::copy(1) }
                            { Self::sub(1, 0) }
                            { Self::roll(1) }
                        }
                        .as_bytes(),
                    );
                    if cur != naf.len() - 1 {
                        script_bytes.extend_from_slice(double.as_bytes());
                    }
                }
                cur += 1;
            }
        }

        script_bytes.extend_from_slice(Self::drop().as_bytes());

        Script::from(script_bytes)
    }

    fn div2() -> Script {
        script! {
            { U254::div2rem() }
            OP_IF
                { Self::push_hex(Self::P_PLUS_ONE_DIV2) }
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
                    { Self::push_hex(Self::P_PLUS_TWO_DIV3) }
                    { Self::add(1, 0) }
                OP_ELSE
                    { Self::push_hex(Self::TWO_P_PLUS_ONE_DIV3) }
                    { Self::add(1, 0) }
                OP_ENDIF
            OP_ELSE
                OP_DROP
            OP_ENDIF
        }
    }

    fn from_hash() -> Script {
        let modulus = BigUint::from_str_radix(Self::MODULUS, 16).unwrap();
        let a: BigUint = BigUint::one().shl(253);
        let a = a.rem(&modulus).to_u32_digits();
        let b: BigUint = BigUint::one().shl(254);
        let b = b.rem(&modulus).to_u32_digits();
        let c: BigUint = BigUint::one().shl(255);
        let c = c.rem(&modulus).to_u32_digits();

        script! {
            for _ in 0..8 {
                { 28 } OP_ROLL
                { 29 } OP_ROLL
                { 30 } OP_ROLL
                { 31 } OP_ROLL
            }

            convert_15_bytes_to_4_limbs
            convert_15_bytes_to_4_limbs

            OP_SWAP
            take_away_top_3_bits
            OP_256MUL
            4 OP_ROLL OP_ADD

            for _ in 0..8 {
                OP_FROMALTSTACK
            }

            9 OP_ROLL
            OP_IF
                { Self::push_u32_le(&a) }
                { Self::add(1, 0) }
            OP_ENDIF

            9 OP_ROLL
            OP_IF
                { Self::push_u32_le(&b) }
                { Self::add(1, 0) }
            OP_ENDIF

            9 OP_ROLL
            OP_IF
                { Self::push_u32_le(&c) }
                { Self::add(1, 0) }
            OP_ENDIF
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

    fn toaltstack() -> Script { U254::toaltstack() }

    fn fromaltstack() -> Script { U254::fromaltstack() }
}

fn convert_15_bytes_to_4_limbs() -> Script {
    script! {
        // step 1: combine the lower 30 bits to 1st limb

        // move the 3 elements to the alt stack
        OP_TOALTSTACK OP_TOALTSTACK OP_TOALTSTACK

        // take away the top 2 bits of the last element
        take_away_top_2_bits

        // assemble the 1st limb
        OP_256MUL
        OP_FROMALTSTACK OP_ADD
        OP_256MUL
        OP_FROMALTSTACK OP_ADD
        OP_256MUL
        OP_FROMALTSTACK OP_ADD

        OP_TOALTSTACK
        OP_SWAP OP_DUP OP_ADD OP_ADD OP_TOALTSTACK

        // now in the altstack
        // 1st-limb
        // b128 * 2 + b64

        // step 2: combine the next 28 bits together with the 2 bit we already obtain to the 2nd limb

        // move the 3 elements to the alt stack
        OP_TOALTSTACK OP_TOALTSTACK OP_TOALTSTACK

        // take away the top 4 bits of the last element
        take_away_top_4_bits

        // assemble the 2nd limb
        OP_256MUL
        OP_FROMALTSTACK OP_ADD
        OP_256MUL
        OP_FROMALTSTACK OP_ADD
        OP_256MUL
        OP_FROMALTSTACK OP_ADD

        // no overflow shift
        OP_DUP OP_ADD
        OP_DUP OP_ADD

        OP_FROMALTSTACK OP_ADD
        OP_TOALTSTACK

        3 OP_ROLL OP_DUP OP_ADD
        3 OP_ROLL OP_ADD OP_DUP OP_ADD
        2 OP_ROLL OP_ADD OP_DUP OP_ADD
        OP_ADD
        OP_TOALTSTACK

        // now in the altstack
        // 1st-limb
        // 2nd-limb
        // b128 * 8 + b64 * 4 + b32 * 2 + b16

        // step 3: combine the next 26 bits together with the 4 bit we already obtain to the 3rd limb

        // move the 3 elements to the alt stack
        OP_TOALTSTACK OP_TOALTSTACK OP_TOALTSTACK

        // take away the top 6 bits of the last element
        take_away_top_6_bits

        // assemble the 3rd limb
        OP_256MUL
        OP_FROMALTSTACK OP_ADD
        OP_256MUL
        OP_FROMALTSTACK OP_ADD
        OP_256MUL
        OP_FROMALTSTACK OP_ADD

        // no overflow shift
        OP_DUP OP_ADD
        OP_DUP OP_ADD
        OP_DUP OP_ADD
        OP_DUP OP_ADD

        OP_FROMALTSTACK OP_ADD
        OP_TOALTSTACK

        5 OP_ROLL OP_DUP OP_ADD
        5 OP_ROLL OP_ADD OP_DUP OP_ADD
        4 OP_ROLL OP_ADD OP_DUP OP_ADD
        3 OP_ROLL OP_ADD OP_DUP OP_ADD
        2 OP_ROLL OP_ADD OP_DUP OP_ADD
        OP_ADD
        OP_TOALTSTACK

        // now in the altstack
        // 1st-limb
        // 2nd-limb
        // 3rd-limb
        // b128 * 32 + b64 * 16 + b32 * 8 + b16 * 4 + b8 * 2 + b4

        // step 4: combine the next 24 bits together with the 6 bit we already obtain to the 4th limb
        OP_TOALTSTACK OP_TOALTSTACK
        OP_256MUL OP_FROMALTSTACK OP_ADD
        OP_256MUL OP_FROMALTSTACK OP_ADD

        // no overflow shift
        OP_DUP OP_ADD
        OP_DUP OP_ADD
        OP_DUP OP_ADD
        OP_DUP OP_ADD
        OP_DUP OP_ADD
        OP_DUP OP_ADD

        OP_FROMALTSTACK OP_ADD
        OP_TOALTSTACK

        // now in the altstack
        // 1st-limb
        // 2nd-limb
        // 3rd-limb
        // 4th-limb
        // which comes from 120 / 8 = 15 bytes
    }
}

fn take_away_top_2_bits() -> Script {
    script! {
        // input: x
        // output: b128 b64 x

        OP_DUP { 128 } OP_GREATERTHANOREQUAL OP_SWAP OP_OVER
        OP_IF
            128 OP_SUB
        OP_ENDIF

        OP_DUP { 64 } OP_GREATERTHANOREQUAL OP_SWAP OP_OVER
        OP_IF
            64 OP_SUB
        OP_ENDIF
    }
}

fn take_away_top_3_bits() -> Script {
    script! {
        // input: x
        // output: b128 b64 b32 x

        take_away_top_2_bits

        OP_DUP { 32 } OP_GREATERTHANOREQUAL OP_SWAP OP_OVER
        OP_IF
            32 OP_SUB
        OP_ENDIF
    }
}

fn take_away_top_4_bits() -> Script {
    script! {
        // input: x
        // output: b128 b64 b32 b16 x
        take_away_top_3_bits

        OP_DUP { 16 } OP_GREATERTHANOREQUAL OP_SWAP OP_OVER
        OP_IF
            16 OP_SUB
        OP_ENDIF
    }
}

fn take_away_top_6_bits() -> Script {
    script! {
        // input: x
        // output: b128 b64 b32 b16 b8 b4 x
        take_away_top_4_bits

        OP_DUP { 8 } OP_GREATERTHANOREQUAL OP_SWAP OP_OVER
        OP_IF
            8 OP_SUB
        OP_ENDIF

        OP_DUP { 4 } OP_GREATERTHANOREQUAL OP_SWAP OP_OVER
        OP_IF
            4 OP_SUB
        OP_ENDIF
    }
}

#[cfg(test)]
mod test {
    use crate::bn254::fp254impl::{
        take_away_top_2_bits, take_away_top_4_bits, take_away_top_6_bits,
    };
    use crate::treepp::*;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_take_away_top_2_bits() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..100 {
            let x: u8 = prng.gen();

            let b128 = (x & 128 != 0) as u8;
            let b64 = (x & 64 != 0) as u8;
            let new_x = x & 0x3f;

            let script = script! {
                { x }
                take_away_top_2_bits
                { new_x } OP_EQUALVERIFY
                { b64 } OP_EQUALVERIFY
                { b128 } OP_EQUAL
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_take_away_top_4_bits() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..100 {
            let x: u8 = prng.gen();

            let b128 = (x & 128 != 0) as u8;
            let b64 = (x & 64 != 0) as u8;
            let b32 = (x & 32 != 0) as u8;
            let b16 = (x & 16 != 0) as u8;

            let new_x = x & 0xf;

            let script = script! {
                { x }
                take_away_top_4_bits
                { new_x } OP_EQUALVERIFY
                { b16 } OP_EQUALVERIFY
                { b32 } OP_EQUALVERIFY
                { b64 } OP_EQUALVERIFY
                { b128 } OP_EQUAL
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_take_away_top_6_bits() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..100 {
            let x: u8 = prng.gen();

            let b128 = (x & 128 != 0) as u8;
            let b64 = (x & 64 != 0) as u8;
            let b32 = (x & 32 != 0) as u8;
            let b16 = (x & 16 != 0) as u8;
            let b8 = (x & 8 != 0) as u8;
            let b4 = (x & 4 != 0) as u8;

            let new_x = x & 0x3;

            let script = script! {
                { x }
                take_away_top_6_bits
                { new_x } OP_EQUALVERIFY
                { b4 } OP_EQUALVERIFY
                { b8 } OP_EQUALVERIFY
                { b16 } OP_EQUALVERIFY
                { b32 } OP_EQUALVERIFY
                { b64 } OP_EQUALVERIFY
                { b128 } OP_EQUAL
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}
