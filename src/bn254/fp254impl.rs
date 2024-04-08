use crate::bigint::add::u30_add_carry;
use crate::bigint::sub::u30_sub_borrow;
use crate::bigint::{MAX_U30, U254};
use crate::treepp::*;
use ark_ff::PrimeField;
use bitcoin_script::script;
use std::sync::OnceLock;

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
    fn push_hex(hex_string: &str) -> Script { U254::push_hex(hex_string) }

    #[inline]
    fn convert_to_bits_toaltstack() -> Script { U254::convert_to_bits_toaltstack() }

    #[inline]
    fn push_modulus() -> Script { Self::push_hex(Self::MODULUS) }

    #[inline]
    fn push_zero() -> Script {
        script! {
            for _ in 0..Self::N_LIMBS { 0 }
        }
    }

    #[inline]
    fn push_one() -> Script {
        script! {
            for _ in 1..Self::N_LIMBS { 0 }
            1
        }
    }

    // A + B mod M
    // Ci⁺ overflow carry bit (A+B)
    // Ci⁻ overflow carry bit (A-B)
    fn add(a: u32, b: u32) -> Script {
        let binding = Self::ADD_ONCELOCK;
        let add_script = binding.get_or_init(|| {
            script! {
                { MAX_U30 }
                // A₀ + B₀
                u30_add_carry
                // A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ B₁ 2³⁰ C₀⁺ A₀+B₀
                OP_DUP
                OP_TOALTSTACK
                // A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ B₁ 2³⁰ C₀⁺ A₀+B₀ | A₀+B₀
                OP_ROT
                // A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ B₁ C₀⁺ A₀+B₀ 2³⁰
                { Self::MODULUS_LIMBS[0] }
                OP_SWAP
                // A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ B₁ C₀⁺ A₀+B₀ M₀ 2³⁰
                u30_sub_borrow
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
                    u30_add_carry
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
                    u30_sub_borrow
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
                u30_sub_borrow
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

    fn mul() -> Script {
        Self::MUL_ONCELOCK
            .get_or_init(|| {
                script! {
                    { Self::convert_to_bits_toaltstack() }

                    { Self::push_zero() }

                    OP_FROMALTSTACK
                    OP_IF
                        { Self::copy(1) }
                        { Self::add(1, 0) }
                    OP_ENDIF

                    for _ in 1..Self::N_BITS - 1 {
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

    fn is_zero(a: u32) -> Script {
        let a = Self::N_LIMBS * a;
        script! {
            1
            for i in 0..Self::N_LIMBS {
                { a + i+1 } OP_PICK
                OP_NOT
                OP_BOOLAND
            }
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
            { Self::copy(0) }
            { Self::mul() }
        }
    }

    fn inv() -> Script {
        script! {
            { Self::push_modulus() }
            { Self::roll(1) }
            { U254::inv_stage1() }
            { U254::inv_stage2(Self::MODULUS) }
            { Self::mul() }
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
}
