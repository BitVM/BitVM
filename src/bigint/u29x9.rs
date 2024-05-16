use crate::bigint::U254;
use crate::treepp::*;

const USE_STRICT: bool = true;

// assert 0 ≤ a ≤ max
// a
fn assert_nn_le(max: u32) -> Script {
    script! {
        if USE_STRICT {
            // a
            OP_DUP
            // a a
            OP_0 { max + 1 }
            // a a 0 2³⁰
            OP_WITHIN
            // a 0≤a≤max
            OP_VERIFY
            // a
        }
    }
}

// A₀ | A₁ A₂ A₃ ⋯ A₂₆ A₂₇ A₂₈
// A₂₈…₀
fn u29_bits_to_altstack() -> Script {
    // NOTE: A₀ is left in the basket
    script! {
        // A₂₈…₀
        { assert_nn_le(0x1FFFFFFF) } // 0≤A₂₈…₀<2²⁹
        // A₂₈…₀
        { 0x10000000 }
        // A₂₈…₀ 2²⁸
        OP_SWAP
        // 2²⁸ A₂₈…₀
        for _ in 0..27 {
            OP_2DUP OP_LESSTHANOREQUAL
            // 2²⁸ A₂₈…₀ A₂₈
            OP_DUP OP_TOALTSTACK
            // 2²⁸ A₂₈…₀ A₂₈ | A₂₈
            OP_IF OP_OVER OP_SUB OP_ENDIF
            // 2²⁸ A₂₇…₀
            OP_DUP OP_ADD
            // 2²⁸ 2¹⋅A₂₇…₀
        }
        // 2²⁸ 2²⁷⋅A₁…₀ | A₂ A₃ A₄ ⋯ A₂₆ A₂₇ A₂₈
        OP_2DUP OP_LESSTHANOREQUAL
        // 2²⁸ 2²⁷⋅A₁…₀ A₁
        OP_DUP OP_TOALTSTACK
        // 2²⁸ 2²⁷⋅A₁…₀ A₁ | A₁ A₂ A₃ ⋯ A₂₆ A₂₇ A₂₈
        OP_IF OP_SWAP OP_SUB OP_ELSE OP_NIP OP_ENDIF
        // 2²⁷⋅A₀
        OP_0NOTEQUAL
        // A₀ | A₁ A₂ A₃ ⋯ A₂₆ A₂₇ A₂₈
    }
}

// (A₂₈…₀ ⋅ B₂₈…₀)₂₈…₀ (A₂₈…₀ ⋅ B₂₈…₀)₅₇…₂₉
// A₂₈…₀ B₂₈…₀
fn u29_mul_carry_29() -> Script {
    script! {
        // A₂₈…₀ B₂₈…₀
        { assert_nn_le(0x1FFFFFFF) } // 0≤A₂₈…₀<2²⁹
        // A₂₈…₀ B₂₈…₀
        { u29_bits_to_altstack() }
        // A₂₈…₀ B₀ | B₁ B₂ B₃ ⋯ B₂₆ B₂₇ B₂₈
        OP_IF OP_DUP OP_ELSE OP_0 OP_SWAP OP_ENDIF
        // A₂₈…₀⋅B₀ A₂₈…₀
        OP_DUP OP_ADD
        // A₂₈…₀⋅B₀ 2¹⋅A₂₈…₀
        { 0x20000000 }
        // A₂₈…₀⋅B₀ 2¹⋅A₂₈…₀ 2²⁹
        OP_SWAP
        // A₂₈…₀⋅B₀ 2²⁹ 2¹⋅A₂₈…₀
        OP_2DUP OP_LESSTHANOREQUAL
        // A₂₈…₀⋅B₀ 2²⁹ 2¹⋅A₂₈…₀ A₂₈
        OP_TUCK
        // A₂₈…₀⋅B₀ 2²⁹ A₂₈ 2¹⋅A₂₈…₀ A₂₈
        OP_IF OP_2 OP_PICK OP_SUB OP_ENDIF
        // A₂₈…₀⋅B₀ 2²⁹ A₂₈ 2¹⋅A₂₇…₀
        OP_FROMALTSTACK
        // A₂₈…₀⋅B₀ 2²⁹ A₂₈ 2¹⋅A₂₇…₀ B₁ | B₂ B₃ B₄ ⋯ B₂₆ B₂₇ B₂₈
        OP_IF OP_2DUP OP_ELSE OP_0 OP_0 OP_ENDIF
        // A₂₈…₀⋅B₀ 2²⁹ A₂₈ 2¹⋅A₂₇…₀ A₂₈⋅B₁ 2¹⋅A₂₇…₀⋅B₁
        OP_5 OP_ROLL
        // 2²⁹ A₂₈ 2¹⋅A₂₇…₀ A₂₈⋅B₁ 2¹⋅A₂₇…₀⋅B₁ A₂₈…₀⋅B₀
        OP_ADD
        // 2²⁹ A₂₈ 2¹⋅A₂₇…₀ A₂₈⋅B₁ A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁
        OP_4 OP_PICK
        // 2²⁹ A₂₈ 2¹⋅A₂₇…₀ A₂₈⋅B₁ A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁ 2²⁹
        OP_2DUP OP_GREATERTHANOREQUAL
        // 2²⁹ A₂₈ 2¹⋅A₂₇…₀ A₂₈⋅B₁ A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁ 2²⁹ (A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁)₂₉
        OP_IF OP_SUB OP_SWAP OP_1ADD OP_ELSE OP_DROP OP_SWAP OP_ENDIF
        // 2²⁹ A₂₈ 2¹⋅A₂₇…₀ (A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁)₂₈…₀ A₂₈⋅B₁+(A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁)₂₉
        OP_2SWAP
        // 2²⁹ (A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁)₂₈…₀ A₂₈⋅B₁+(A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁)₂₉ A₂₈ 2¹⋅A₂₇…₀
        OP_SWAP
        // 2²⁹ (A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁)₂₈…₀ A₂₈⋅B₁+(A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁)₂₉ 2¹⋅A₂₇…₀ A₂₈
        OP_DUP OP_ADD
        // 2²⁹ (A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁)₂₈…₀ A₂₈⋅B₁+(A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁)₂₉ 2¹⋅A₂₇…₀ 2¹⋅A₂₈
        OP_SWAP
        // 2²⁹ (A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁)₂₈…₀ A₂₈⋅B₁+(A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁)₂₉ 2¹⋅A₂₈ 2¹⋅A₂₇…₀
        OP_DUP OP_ADD
        // 2²⁹ (A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁)₂₈…₀ A₂₈⋅B₁+(A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁)₂₉ 2¹⋅A₂₈ 2²⋅A₂₇…₀
        OP_4 OP_PICK
        // 2²⁹ (A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁)₂₈…₀ A₂₈⋅B₁+(A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁)₂₉ 2¹⋅A₂₈ 2²⋅A₂₇…₀ 2²⁹
        OP_2DUP OP_GREATERTHANOREQUAL
        // 2²⁹ (A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁)₂₈…₀ A₂₈⋅B₁+(A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁)₂₉ 2¹⋅A₂₈ 2²⋅A₂₇…₀ 2²⁹ A₂₇
        OP_IF OP_SUB OP_SWAP OP_1ADD OP_ELSE OP_DROP OP_SWAP OP_ENDIF
        // 2²⁹ (A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁)₂₈…₀ A₂₈⋅B₁+(A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁)₂₉ 2²⋅A₂₆…₀ A₂₈…₂₇
        for _ in 0..26 {
            // 2²⁹ (A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁)₂₈…₀ A₂₈⋅B₁+(A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁)₂₉ 2²⋅A₂₆…₀ A₂₈…₂₇
            OP_FROMALTSTACK
            // 2²⁹ (A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁)₂₈…₀ A₂₈⋅B₁+(A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁)₂₉ 2²⋅A₂₆…₀ A₂₈…₂₇ B₂ | B₃ B₄ B₅ ⋯ B₂₆ B₂₇ B₂₈
            OP_IF OP_2DUP OP_ELSE OP_0 OP_0 OP_ENDIF
            // 2²⁹ (A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁)₂₈…₀ A₂₈⋅B₁+(A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁)₂₉ 2²⋅A₂₆…₀ A₂₈…₂₇ 2²⋅A₂₆…₀⋅B₂ A₂₈…₂₇⋅B₂
            OP_2ROT
            // 2²⁹ 2²⋅A₂₆…₀ A₂₈…₂₇ 2²⋅A₂₆…₀⋅B₂ A₂₈…₂₇⋅B₂ (A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁)₂₈…₀ A₂₈⋅B₁+(A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁)₂₉
            OP_ROT
            // 2²⁹ 2²⋅A₂₆…₀ A₂₈…₂₇ 2²⋅A₂₆…₀⋅B₂ (A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁)₂₈…₀ A₂₈⋅B₁+(A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁)₂₉ A₂₈…₂₇⋅B₂
            OP_ADD
            // 2²⁹ 2²⋅A₂₆…₀ A₂₈…₂₇ 2²⋅A₂₆…₀⋅B₂ (A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁)₂₈…₀ A₂₈⋅B₁+A₂₈…₂₇⋅B₂+(A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁)₂₉
            OP_ROT
            // 2²⁹ 2²⋅A₂₆…₀ A₂₈…₂₇ (A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁)₂₈…₀ A₂₈⋅B₁+A₂₈…₂₇⋅B₂+(A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁)₂₉ 2²⋅A₂₆…₀⋅B₂
            OP_ROT
            // 2²⁹ 2²⋅A₂₆…₀ A₂₈…₂₇ A₂₈⋅B₁+A₂₈…₂₇⋅B₂+(A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁)₂₉ 2²⋅A₂₆…₀⋅B₂ (A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁)₂₈…₀
            OP_ADD
            // 2²⁹ 2²⋅A₂₆…₀ A₂₈…₂₇ A₂₈⋅B₁+A₂₈…₂₇⋅B₂+(A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁)₂₉ (A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁)₂₈…₀+2²⋅A₂₆…₀⋅B₂
            OP_4 OP_PICK
            // 2²⁹ 2²⋅A₂₆…₀ A₂₈…₂₇ A₂₈⋅B₁+A₂₈…₂₇⋅B₂+(A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁)₂₉ (A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁)₂₈…₀+2²⋅A₂₆…₀⋅B₂ 2²⁹
            OP_2DUP OP_GREATERTHANOREQUAL
            // 2²⁹ 2²⋅A₂₆…₀ A₂₈…₂₇ A₂₈⋅B₁+A₂₈…₂₇⋅B₂+(A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁)₂₉ (A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁)₂₈…₀+2²⋅A₂₆…₀⋅B₂ 2²⁹ (A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁)₂₈…₀+2²⋅A₂₆…₀⋅B₂≥2²⁹
            OP_IF OP_SUB OP_SWAP OP_1ADD OP_ELSE OP_DROP OP_SWAP OP_ENDIF
            // 2²⁹ 2²⋅A₂₆…₀ A₂₈…₂₇ (A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁+2²⋅A₂₆…₀⋅B₂)₂₈…₀ A₂₈⋅B₁+A₂₈…₂₇⋅B₂+(A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁+2²⋅A₂₆…₀⋅B₂)₃₀…₂₉
            OP_2SWAP
            // 2²⁹ (A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁+2²⋅A₂₆…₀⋅B₂)₂₈…₀ A₂₈⋅B₁+A₂₈…₂₇⋅B₂+(A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁+2²⋅A₂₆…₀⋅B₂)₃₀…₂₉ 2²⋅A₂₆…₀ A₂₈…₂₇
            OP_DUP OP_ADD
            // 2²⁹ (A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁+2²⋅A₂₆…₀⋅B₂)₂₈…₀ A₂₈⋅B₁+A₂₈…₂₇⋅B₂+(A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁+2²⋅A₂₆…₀⋅B₂)₃₀…₂₉ 2²⋅A₂₆…₀ 2¹⋅A₂₈…₂₇
            OP_SWAP
            // 2²⁹ (A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁+2²⋅A₂₆…₀⋅B₂)₂₈…₀ A₂₈⋅B₁+A₂₈…₂₇⋅B₂+(A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁+2²⋅A₂₆…₀⋅B₂)₃₀…₂₉ 2¹⋅A₂₈…₂₇ 2²⋅A₂₆…₀
            OP_DUP OP_ADD
            // 2²⁹ (A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁+2²⋅A₂₆…₀⋅B₂)₂₈…₀ A₂₈⋅B₁+A₂₈…₂₇⋅B₂+(A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁+2²⋅A₂₆…₀⋅B₂)₃₀…₂₉ 2¹⋅A₂₈…₂₇ 2³⋅A₂₆…₀
            OP_4 OP_PICK
            // 2²⁹ (A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁+2²⋅A₂₆…₀⋅B₂)₂₈…₀ A₂₈⋅B₁+A₂₈…₂₇⋅B₂+(A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁+2²⋅A₂₆…₀⋅B₂)₃₀…₂₉ 2¹⋅A₂₈…₂₇ 2³⋅A₂₆…₀ 2²⁹
            OP_2DUP OP_GREATERTHANOREQUAL
            // 2²⁹ (A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁+2²⋅A₂₆…₀⋅B₂)₂₈…₀ A₂₈⋅B₁+A₂₈…₂₇⋅B₂+(A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁+2²⋅A₂₆…₀⋅B₂)₃₀…₂₉ 2¹⋅A₂₈…₂₇ 2³⋅A₂₆…₀ 2²⁹ A₂₆
            OP_IF OP_SUB OP_SWAP OP_1ADD OP_ELSE OP_DROP OP_SWAP OP_ENDIF
            // 2²⁹ (2⁰⋅A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁+2²⋅A₂₆…₀⋅B₂)₂₈…₀ A₂₈⋅B₁+A₂₈…₂₇⋅B₂+(2⁰⋅A₂₈…₀⋅B₀+2¹⋅A₂₇…₀⋅B₁+2²⋅A₂₆…₀⋅B₂)₃₀…₂₉ 2³⋅A₂₅…₀ A₂₈…₂₆
        }
        // 2²⁹ (2⁰⋅A₂₈…₀⋅B₀⋯2²⁷⋅A₁…₀⋅B₂₇)₂₈…₀ A₂₈⋅B₁⋯A₂₈…₂⋅B₂₇+(2⁰⋅A₂₈…₀⋅B₀⋯2²⁷⋅A₁…₀⋅B₂₇)₅₅…₂₉ 2²⁸⋅A₀ A₂₈…₁ | B₂₈
        OP_FROMALTSTACK
        // 2²⁹ (2⁰⋅A₂₈…₀⋅B₀⋯2²⁷⋅A₁…₀⋅B₂₇)₂₈…₀ A₂₈⋅B₁⋯A₂₈…₂⋅B₂₇+(2⁰⋅A₂₈…₀⋅B₀⋯2²⁷⋅A₁…₀⋅B₂₇)₅₅…₂₉ 2²⁸⋅A₀ A₂₈…₁ B₂₈
        OP_NOTIF OP_2DROP OP_0 OP_0 OP_ENDIF
        // 2²⁹ (2⁰⋅A₂₈…₀⋅B₀⋯2²⁷⋅A₁…₀⋅B₂₇)₂₈…₀ A₂₈⋅B₁⋯A₂₈…₂⋅B₂₇+(2⁰⋅A₂₈…₀⋅B₀⋯2²⁷⋅A₁…₀⋅B₂₇)₅₅…₂₉ 2²⁸⋅A₀⋅B₂₈ A₂₈…₁⋅B₂₈
        OP_2SWAP
        // 2²⁹ 2²⁸⋅A₀⋅B₂₈ A₂₈…₁⋅B₂₈ (2⁰⋅A₂₈…₀⋅B₀⋯2²⁷⋅A₁…₀⋅B₂₇)₂₈…₀ A₂₈⋅B₁⋯A₂₈…₂⋅B₂₇+(2⁰⋅A₂₈…₀⋅B₀⋯2²⁷⋅A₁…₀⋅B₂₇)₅₅…₂₉
        OP_ROT
        // 2²⁹ 2²⁸⋅A₀⋅B₂₈ (2⁰⋅A₂₈…₀⋅B₀⋯2²⁷⋅A₁…₀⋅B₂₇)₂₈…₀ A₂₈⋅B₁⋯A₂₈…₂⋅B₂₇+(2⁰⋅A₂₈…₀⋅B₀⋯2²⁷⋅A₁…₀⋅B₂₇)₅₅…₂₉ A₂₈…₁⋅B₂₈
        OP_ADD
        // 2²⁹ 2²⁸⋅A₀⋅B₂₈ (2⁰⋅A₂₈…₀⋅B₀⋯2²⁷⋅A₁…₀⋅B₂₇)₂₈…₀ A₂₈⋅B₁⋯A₂₈…₁⋅B₂₈+(2⁰⋅A₂₈…₀⋅B₀⋯2²⁷⋅A₁…₀⋅B₂₇)₅₅…₂₉
        OP_ROT
        // 2²⁹ (2⁰⋅A₂₈…₀⋅B₀⋯2²⁷⋅A₁…₀⋅B₂₇)₂₈…₀ A₂₈⋅B₁⋯A₂₈…₁⋅B₂₈+(2⁰⋅A₂₈…₀⋅B₀⋯2²⁷⋅A₁…₀⋅B₂₇)₅₅…₂₉ 2²⁸⋅A₀⋅B₂₈
        OP_ROT
        // 2²⁹ A₂₈⋅B₁⋯A₂₈…₁⋅B₂₈+(2⁰⋅A₂₈…₀⋅B₀⋯2²⁷⋅A₁…₀⋅B₂₇)₅₅…₂₉ 2²⁸⋅A₀⋅B₂₈ (2⁰⋅A₂₈…₀⋅B₀⋯2²⁷⋅A₁…₀⋅B₂₇)₂₈…₀
        OP_ADD
        // 2²⁹ A₂₈⋅B₁⋯A₂₈…₁⋅B₂₈+(2⁰⋅A₂₈…₀⋅B₀⋯2²⁷⋅A₁…₀⋅B₂₇)₅₅…₂₉ (2⁰⋅A₂₈…₀⋅B₀⋯2²⁷⋅A₁…₀⋅B₂₇)₂₈…₀+2²⁸⋅A₀⋅B₂₈
        OP_ROT
        // A₂₈⋅B₁⋯A₂₈…₁⋅B₂₈+(2⁰⋅A₂₈…₀⋅B₀⋯2²⁷⋅A₁…₀⋅B₂₇)₅₅…₂₉ (2⁰⋅A₂₈…₀⋅B₀⋯2²⁷⋅A₁…₀⋅B₂₇)₂₈…₀+2²⁸⋅A₀⋅B₂₈ 2²⁹
        OP_2DUP OP_GREATERTHANOREQUAL
        // A₂₈⋅B₁⋯A₂₈…₁⋅B₂₈+(2⁰⋅A₂₈…₀⋅B₀⋯2²⁷⋅A₁…₀⋅B₂₇)₅₅…₂₉ (2⁰⋅A₂₈…₀⋅B₀⋯2²⁷⋅A₁…₀⋅B₂₇)₂₈…₀+2²⁸⋅A₀⋅B₂₈ 2²⁹ (2⁰⋅A₂₈…₀⋅B₀⋯2²⁷⋅A₁…₀⋅B₂₇)₂₈…₀+2²⁸⋅A₀⋅B₂₈≥2²⁹
        OP_IF OP_SUB OP_SWAP OP_1ADD OP_ELSE OP_DROP OP_SWAP OP_ENDIF
        // (2⁰⋅A₂₈…₀⋅B₀⋯2²⁸⋅A₀⋅B₂₈)₂₈…₀ A₂₈⋅B₁⋯A₂₈…₁⋅B₂₈+(2⁰⋅A₂₈…₀⋅B₀⋯2²⁸⋅A₀⋅B₂₈)₅₆…₂₉
        // OP_SWAP
        // A₂₈⋅B₁⋯A₂₈…₁⋅B₂₈+(2⁰⋅A₂₈…₀⋅B₀⋯2²⁸⋅A₀⋅B₂₈)₅₆…₂₉ (2⁰⋅A₂₈…₀⋅B₀⋯2²⁸⋅A₀⋅B₂₈)₂₈…₀
        // A₂₈⋅B₁⋯A₂₈…₁⋅B₂₈+(2⁰⋅A₂₈…₀⋅B₀⋯2²⁸⋅A₀⋅B₂₈)₅₆…₂₉ (2⁰⋅A₂₈…₀⋅B₀⋯2²⁸⋅A₀⋅B₂₈)₂₈…₀
        // (A₂₈…₀ ⋅ B₂₈…₀)₅₇…₂₉ (A₂₈…₀ ⋅ B₂₈…₀)₂₈…₀
    }
}

// (A₂₉…₀ ⋅ B₂₉…₀)₂₈…₀ (A₂₉…₀ ⋅ B₂₉…₀)₅₉…₂₉
// A₂₉…₀ B₂₉…₀
fn u30_mul_to_u29_carry_31() -> Script {
    script! {
        // A₂₉…₀ B₂₉…₀
        { assert_nn_le(0x3FFFFFFF) } // 0≤A₂₉…₀<2³⁰

        // Rearrange A₂₉…₀⋅B₂₉…₀ to A₂₈…₀⋅B₂₈…₀:
        //  (A₂₉⋅2²⁹+A₂₈…₀)₂₉…₀ ⋅ (B₂₉⋅2²⁹+B₂₈…₀)₂₉…₀ = A₂₈…₀⋅B₂₈…₀ + A₂₈…₀⋅B₂₉⋅2²⁹ + B₂₈…₀⋅A₂₉⋅2²⁹ + A₂₉⋅B₂₉⋅2⁵⁸

        // A₂₉…₀ B₂₉…₀
        { 0x20000000 }
        // A₂₉…₀ B₂₉…₀ 2²⁹
        OP_TUCK
        // A₂₉…₀ 2²⁹ B₂₉…₀ 2²⁹
        OP_2DUP OP_GREATERTHANOREQUAL
        // A₂₉…₀ 2²⁹ B₂₉…₀ 2²⁹ B₂₉
        OP_DUP OP_TOALTSTACK
        // A₂₉…₀ 2²⁹ B₂₉…₀ 2²⁹ B₂₉ | B₂₉
        OP_IF OP_SUB OP_ELSE OP_DROP OP_ENDIF
        // A₂₉…₀ 2²⁹ B₂₈…₀
        OP_TOALTSTACK
        // A₂₉…₀ 2²⁹ | B₂₈…₀ B₂₉
        OP_TUCK
        // 2²⁹ A₂₉…₀ 2²⁹
        OP_2DUP OP_GREATERTHANOREQUAL
        // 2²⁹ A₂₉…₀ 2²⁹ A₂₉
        OP_DUP OP_TOALTSTACK
        // 2²⁹ A₂₉…₀ 2²⁹ A₂₉ | A₂₉ B₂₈…₀ B₂₉
        OP_IF OP_SUB OP_ELSE OP_DROP OP_ENDIF
        // 2²⁹ A₂₈…₀
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        // 2²⁹ A₂₈…₀ A₂₉ B₂₈…₀ B₂₉
        OP_2 OP_PICK
        OP_OVER
        // 2²⁹ A₂₈…₀ A₂₉ B₂₈…₀ B₂₉ A₂₉ B₂₉
        OP_BOOLAND
        OP_TOALTSTACK
        // 2²⁹ A₂₈…₀ A₂₉ B₂₈…₀ B₂₉ | A₂₉∧B₂₉
        OP_IF
            // 2²⁹ A₂₈…₀ A₂₉ B₂₈…₀
            OP_2 OP_PICK
            // 2²⁹ A₂₈…₀ A₂₉ B₂₈…₀ A₂₈…₀
        OP_ELSE
            // 2²⁹ A₂₈…₀ A₂₉ B₂₈…₀
            OP_0
            // 2²⁹ A₂₈…₀ A₂₉ B₂₈…₀ 0
        OP_ENDIF
        // 2²⁹ A₂₈…₀ A₂₉ B₂₈…₀ B₂₉⋅A₂₈…₀
        OP_ROT
        // 2²⁹ A₂₈…₀ B₂₈…₀ B₂₉⋅A₂₈…₀ A₂₉
        OP_IF
            // 2²⁹ A₂₈…₀ B₂₈…₀ B₂₉⋅A₂₈…₀
            OP_OVER
            // 2²⁹ A₂₈…₀ B₂₈…₀ B₂₉⋅A₂₈…₀ B₂₈…₀
        OP_ELSE
            // 2²⁹ A₂₈…₀ B₂₈…₀ B₂₉⋅A₂₈…₀
            OP_0
            // 2²⁹ A₂₈…₀ B₂₈…₀ B₂₉⋅A₂₈…₀ 0
        OP_ENDIF
        // 2²⁹ A₂₈…₀ B₂₈…₀ B₂₉⋅A₂₈…₀ A₂₉⋅B₂₈…₀
        OP_ADD OP_TOALTSTACK
        // 2²⁹ A₂₈…₀ B₂₈…₀ | B₂₉⋅A₂₈…₀+A₂₉⋅B₂₈…₀

        // Compute A₂₈…₀ ⋅ B₂₈…₀
        { u29_mul_carry_29() }
        // (A₂₉…₀ ⋅ B₂₉…₀)₂₈…₀  = (A₂₈…₀ ⋅ B₂₈…₀)₂₈…₀
        // (A₂₉…₀ ⋅ B₂₉…₀)₅₉…₂₉ = (A₂₈…₀ ⋅ B₂₈…₀)₅₇…₂₉ + A₂₉⋅B₂₈…₀ + B₂₉⋅A₂₈…₀ + A₂₉⋅B₂₉⋅2²⁹

        // 2²⁹ (A₂₈…₀⋅B₂₈…₀)₂₈…₀ (A₂₈…₀⋅B₂₈…₀)₂₉…₅₈ | B₂₉⋅A₂₈…₀+A₂₉⋅B₂₈…₀ A₂₉∧B₂₉
        OP_FROMALTSTACK
        // 2²⁹ (A₂₈…₀⋅B₂₈…₀)₂₈…₀ (A₂₈…₀⋅B₂₈…₀)₂₉…₅₈ B₂₉⋅A₂₈…₀+A₂₉⋅B₂₈…₀
        OP_ADD
        // 2²⁹ (A₂₈…₀⋅B₂₈…₀)₂₈…₀ (A₂₈…₀⋅B₂₈…₀)₂₉…₅₈+B₂₉⋅A₂₈…₀+A₂₉⋅B₂₈…₀
        OP_ROT
        // (A₂₈…₀⋅B₂₈…₀)₂₈…₀ (A₂₈…₀⋅B₂₈…₀)₂₉…₅₈+B₂₉⋅A₂₈…₀+A₂₉⋅B₂₈…₀ 2²⁹
        OP_FROMALTSTACK
        // (A₂₈…₀⋅B₂₈…₀)₂₈…₀ (A₂₈…₀⋅B₂₈…₀)₂₉…₅₈+B₂₉⋅A₂₈…₀+A₂₉⋅B₂₈…₀ 2²⁹ A₂₉∧B₂₉
        OP_IF
            // (A₂₈…₀⋅B₂₈…₀)₂₈…₀ (A₂₈…₀⋅B₂₈…₀)₂₉…₅₈+B₂₉⋅A₂₈…₀+A₂₉⋅B₂₈…₀ 2²⁹
            OP_ADD
            // (A₂₈…₀⋅B₂₈…₀)₂₈…₀ (A₂₈…₀⋅B₂₈…₀)₂₉…₅₈+B₂₉⋅A₂₈…₀+A₂₉⋅B₂₈…₀+2²⁹
        OP_ELSE
            // (A₂₈…₀⋅B₂₈…₀)₂₈…₀ (A₂₈…₀⋅B₂₈…₀)₂₉…₅₈+B₂₉⋅A₂₈…₀+A₂₉⋅B₂₈…₀ 2²⁹
            OP_DROP
            // (A₂₈…₀⋅B₂₈…₀)₂₈…₀ (A₂₈…₀⋅B₂₈…₀)₂₉…₅₈+B₂₉⋅A₂₈…₀+A₂₉⋅B₂₈…₀
        OP_ENDIF
        // (A₂₈…₀⋅B₂₈…₀)₂₈…₀ (A₂₈…₀⋅B₂₈…₀)₂₉…₅₈+B₂₉⋅A₂₈…₀+A₂₉⋅B₂₈…₀+A₂₉⋅B₂₉⋅2²⁹


        // A₂₉…₀ B₂₉…₀ 2²⁹⋅A₂₉⋅B₂₉ 2²⁹


        // Add A₂₉⋅B₂₈…₀
        // OP_IF /* A₂₉ */ OP_OVER /* (A₂₈…₀ ⋅ B₂₈…₀)₂₉…₅₈ */ OP_ADD /* B₂₈…₀ */ OP_ENDIF
        // Add B₂₉⋅A₂₈…₀
        // OP_IF /* B₂₉ */ OP_OVER /* (A₂₈…₀ ⋅ B₂₈…₀)₂₉…₅₈ + A₂₉⋅B₂₈…₀ */ OP_ADD /* A₂₈…₀ */ OP_ENDIF
        // Add 2²⁹⋅A₂₉⋅B₂₉
        // /* A₂₉ */ OP_BOOLAND /* B₂₉ */ OP_IF /* A₂₉⋅B₂₉ */ OP_ADD /* 2²⁹ */ OP_ENDIF

        // (A₂₉…₀ ⋅ B₂₉…₀)₂₈…₀ (A₂₉…₀ ⋅ B₂₉…₀)₅₉…₂₉
        // OP_SWAP
        // // (A₂₉…₀ ⋅ B₂₉…₀)₅₉…₂₉ (A₂₉…₀ ⋅ B₂₉…₀)₂₈…₀

    }
}

fn u29x2_sub_noborrow() -> Script {
    script! {
        OP_2SWAP
        // A₂₈…₀ A₅₇…₂₉ B₂₈…₀ B₅₉…₂₉
        OP_TOALTSTACK
        // A₂₈…₀ A₅₇…₂₉ B₂₈…₀ | B₅₉…₂₉
        OP_ROT
        // A₅₇…₂₉ B₂₈…₀ A₂₈…₀
        OP_2DUP OP_LESSTHAN
        // A₅₇…₂₉ B₂₈…₀ A₂₈…₀ B₂₈…₀<A₂₈…₀
        OP_ROT
        // A₅₇…₂₉ A₂₈…₀ B₂₈…₀<A₂₈…₀ B₂₈…₀
        OP_OVER
        // A₅₇…₂₉ A₂₈…₀ B₂₈…₀<A₂₈…₀ B₂₈…₀ B₂₈…₀<A₂₈…₀
        OP_IF
            // A₅₇…₂₉ A₂₈…₀ B₂₈…₀<A₂₈…₀ B₂₈…₀
            { 1 << 29 }
            // A₅₇…₂₉ A₂₈…₀ B₂₈…₀<A₂₈…₀ B₂₈…₀ 2²⁹
            OP_ADD
            // A₅₇…₂₉ A₂₈…₀ B₂₈…₀<A₂₈…₀ B₂₈…₀+2²⁹
        OP_ENDIF
        // A₅₇…₂₉ A₂₈…₀ B₂₈…₀<A₂₈…₀ B₂₈…₀[+2²⁹]
        OP_ROT
        // A₅₇…₂₉ B₂₈…₀<A₂₈…₀ B₂₈…₀[+2²⁹] A₂₈…₀
        OP_SUB
        // A₅₇…₂₉ B₂₈…₀<A₂₈…₀ (B₂₈…₀-A₂₈…₀)ᵐᵒᵈ2²⁹
        OP_FROMALTSTACK
        // A₅₇…₂₉ B₂₈…₀<A₂₈…₀ (B₂₈…₀-A₂₈…₀)ᵐᵒᵈ2²⁹ B₅₉…₂₉
        OP_SWAP
        // A₅₇…₂₉ B₂₈…₀<A₂₈…₀ B₅₉…₂₉ (B₂₈…₀-A₂₈…₀)ᵐᵒᵈ2²⁹
        OP_TOALTSTACK
        // A₅₇…₂₉ B₂₈…₀<A₂₈…₀ B₅₉…₂₉ | (B₂₈…₀-A₂₈…₀)ᵐᵒᵈ2²⁹
        OP_ROT
        // B₂₈…₀<A₂₈…₀ B₅₉…₂₉ A₅₇…₂₉
        OP_SUB
        // B₂₈…₀<A₂₈…₀ B₅₉…₂₉-A₅₇…₂₉
        OP_SWAP
        // B₅₉…₂₉-A₅₇…₂₉ B₂₈…₀<A₂₈…₀
        OP_SUB
        // B₅₉…₂₉-A₅₇…₂₉-(B₂₈…₀<A₂₈…₀)
        OP_FROMALTSTACK
        // B₅₉…₂₉-A₅₇…₂₉-(B₂₈…₀<A₂₈…₀) (B₂₈…₀-A₂₈…₀)ᵐᵒᵈ2²⁹
        OP_SWAP
        // (B₂₈…₀-A₂₈…₀)ᵐᵒᵈ2²⁹ B₅₉…₂₉-A₅₇…₂₉-(B₂₈…₀<A₂₈…₀)
    }
}

fn u29x2_add_u29() -> Script {
    script! {
        // A₂₈…₀ A₅₇…₂₉ B₂₈…₀
        OP_ROT
        // A₅₇…₂₉ B₂₈…₀ A₂₈…₀
        OP_ADD
        // A₅₇…₂₉ (B₂₈…₀+A₂₈…₀)₂₉…₀
        { 1 << 29 }
        // A₅₇…₂₉ (B₂₈…₀+A₂₈…₀)₂₉…₀ 2²⁹
        OP_2DUP OP_GREATERTHANOREQUAL
        // A₅₇…₂₉ (B₂₈…₀+A₂₈…₀)₂₉…₀ 2²⁹ (B₂₈…₀+A₂₈…₀)₂₉
        OP_TUCK
        // A₅₇…₂₉ (B₂₈…₀+A₂₈…₀)₂₉…₀ (B₂₈…₀+A₂₈…₀)₂₉ 2²⁹ (B₂₈…₀+A₂₈…₀)₂₉
        OP_IF
            // A₅₇…₂₉ (B₂₈…₀+A₂₈…₀)₂₉…₀ (B₂₈…₀+A₂₈…₀)₂₉ 2²⁹
            OP_ROT
            // A₅₇…₂₉ (B₂₈…₀+A₂₈…₀)₂₉ 2²⁹ (B₂₈…₀+A₂₈…₀)₂₉…₀
            OP_SWAP
            // A₅₇…₂₉ (B₂₈…₀+A₂₈…₀)₂₉ (B₂₈…₀+A₂₈…₀)₂₉…₀ 2²⁹
            OP_SUB
            // A₅₇…₂₉ (B₂₈…₀+A₂₈…₀)₂₉ (B₂₈…₀+A₂₈…₀)₂₈…₀
            OP_SWAP
            // A₅₇…₂₉ (B₂₈…₀+A₂₈…₀)₂₈…₀ (B₂₈…₀+A₂₈…₀)₂₉
        OP_ELSE
            // A₅₇…₂₉ (B₂₈…₀+A₂₈…₀)₂₈…₀ (B₂₈…₀+A₂₈…₀)₂₉ 2²⁹
            OP_DROP
            // A₅₇…₂₉ (B₂₈…₀+A₂₈…₀)₂₈…₀ (B₂₈…₀+A₂₈…₀)₂₉
        OP_ENDIF
        // A₅₇…₂₉ (B₂₈…₀+A₂₈…₀)₂₈…₀ (B₂₈…₀+A₂₈…₀)₂₉
        OP_ROT
        // (B₂₈…₀+A₂₈…₀)₂₈…₀ (B₂₈…₀+A₂₈…₀)₂₉ A₅₇…₂₉
        OP_ADD
        // (B₂₈…₀+A₂₈…₀)₂₈…₀ A₅₇…₂₉+(B₂₈…₀+A₂₈…₀)₂₉
    }
}

// A₀ A₁ A₂ B₀ B₁
fn u29x3_add_u29x2_nocarry() -> Script {
    script! {
        // A₀ A₁ A₂ B₀ B₁
        OP_ROT OP_TOALTSTACK OP_TOALTSTACK
        // A₀ A₁ B₀ | B₁ A₂
        { u29x2_add_u29() }
        // (A+B₀)₀ (A+B₀)₁ | B₁ A₂
        OP_FROMALTSTACK OP_FROMALTSTACK OP_SWAP
        // (A+B₀)₀ (A+B₀)₁ A₂ B₁
        { u29x2_add_u29() }
        // (A+B)₀ (A+B)₁ (A+B)₂
    }
}

fn u29x2_add_u29u30_carry() -> Script {
    script! {
        // ⋯ (A₀⋅B₀)₅₇…₂₉ (A₁⋅B₁)₂₈…₀ (A₁⋅B₀+A₀⋅B₁)₂₈…₀ (A₁⋅B₀+A₀⋅B₁)₅₈…₂₉
        { 1 << 29 } OP_2DUP OP_GREATERTHANOREQUAL
        // ⋯ (A₀⋅B₀)₅₇…₂₉ (A₁⋅B₁)₂₈…₀ (A₁⋅B₀+A₀⋅B₁)₂₈…₀ (A₁⋅B₀+A₀⋅B₁)₅₈…₂₉ 2²⁹ (A₁⋅B₀+A₀⋅B₁)₅₈
        OP_IF OP_SUB OP_1 OP_ELSE OP_DROP OP_0 OP_ENDIF
        // ⋯ (A₀⋅B₀)₅₇…₂₉ (A₁⋅B₁)₂₈…₀ (A₁⋅B₀+A₀⋅B₁)₂₈…₀ (A₁⋅B₀+A₀⋅B₁)₅₇…₂₉ (A₁⋅B₀+A₀⋅B₁)₅₈
        OP_4 OP_ROLL
        // ⋯ (A₁⋅B₁)₂₈…₀ (A₁⋅B₀+A₀⋅B₁)₂₈…₀ (A₁⋅B₀+A₀⋅B₁)₅₇…₂₉ (A₁⋅B₀+A₀⋅B₁)₅₈ (A₀⋅B₀)₅₇…₂₉
        OP_4 OP_ROLL
        // ⋯ (A₁⋅B₀+A₀⋅B₁)₂₈…₀ (A₁⋅B₀+A₀⋅B₁)₅₇…₂₉ (A₁⋅B₀+A₀⋅B₁)₅₈ (A₀⋅B₀)₅₇…₂₉ (A₁⋅B₁)₂₈…₀
        { u29x3_add_u29x2_nocarry() }
    }
}

// (A₀⋅B₀)₂₈…₀

// (A₀⋅B₀)₅₇…₂₉ +
// (A₁⋅B₀+A₀⋅B₁)₂₈…₀

// (A₁⋅B₀+A₀⋅B₁)₅₈…₂₉ +
// (A₁⋅B₁)₂₈…₀ + (A₂⋅B₀+A₀⋅B₂)₂₈…₀

// (A₁⋅B₁)₅₇…₂₉ + (A₂⋅B₀+A₀⋅B₂)₅₈…₂₉ +
// (A₃⋅B₀+A₀⋅B₃)₂₈…₀ + (A₂⋅B₁+A₁⋅B₂)₂₈…₀

// (A₃⋅B₀+A₀⋅B₃)₅₈…₂₉ + (A₂⋅B₁+A₁⋅B₂)₅₈…₂₉ +
// (A₂⋅B₂)₂₈…₀ + (A₄⋅B₀+A₀⋅B₄)₂₈…₀ + (A₃⋅B₁+A₁⋅B₃)₂₈…₀

// (A₂⋅B₂)₅₇…₂₉ + (A₄⋅B₀+A₀⋅B₄)₅₈…₂₉ + (A₃⋅B₁+A₁⋅B₃)₅₈…₂₉ +
// (A₅⋅B₀+A₀⋅B₅)₂₈…₀ + (A₄⋅B₁+A₁⋅B₄)₂₈…₀ + (A₃⋅B₂+A₂⋅B₃)₂₈…₀

// (A₅⋅B₀+A₀⋅B₅)₅₈…₂₉ + (A₄⋅B₁+A₁⋅B₄)₅₈…₂₉ + (A₃⋅B₂+A₂⋅B₃)₅₈…₂₉ +
// (A₃⋅B₃)₂₈…₀ + (A₆⋅B₀+A₀⋅B₆)₂₈…₀ + (A₅⋅B₁+A₁⋅B₅)₂₈…₀ + (A₄⋅B₂+A₂⋅B₄)₂₈…₀

// (A₃⋅B₃)₅₇…₂₉ + (A₆⋅B₀+A₀⋅B₆)₅₈…₂₉ + (A₅⋅B₁+A₁⋅B₅)₅₈…₂₉ + (A₄⋅B₂+A₂⋅B₄)₅₈…₂₉ +
// (A₇⋅B₀+A₀⋅B₇)₂₈…₀ + (A₆⋅B₁+A₁⋅B₆)₂₈…₀ + (A₅⋅B₂+A₂⋅B₅)₂₈…₀ + (A₄⋅B₃+A₃⋅B₄)₂₈…₀

// (A₇⋅B₀+A₀⋅B₇)₅₈…₂₉ + (A₆⋅B₁+A₁⋅B₆)₅₈…₂₉ + (A₅⋅B₂+A₂⋅B₅)₅₈…₂₉ + (A₄⋅B₃+A₃⋅B₄)₅₈…₂₉ +
// (A₄⋅B₄)₂₈…₀ + (A₈⋅B₀+A₀⋅B₈)₂₈…₀ + (A₇⋅B₁+A₁⋅B₇)₂₈…₀ + (A₆⋅B₂+A₂⋅B₆)₂₈…₀ + (A₅⋅B₃+A₃⋅B₅)₂₈…₀

// (A₄⋅B₄)₅₇…₂₉ + (A₈⋅B₀+A₀⋅B₈)₅₈…₂₉ + (A₇⋅B₁+A₁⋅B₇)₅₈…₂₉ + (A₆⋅B₂+A₂⋅B₆)₅₈…₂₉ + (A₅⋅B₃+A₃⋅B₅)₅₈…₂₉ +
// (A₈⋅B₁+A₁⋅B₈)₂₈…₀ + (A₇⋅B₂+A₂⋅B₇)₂₈…₀ + (A₆⋅B₃+A₃⋅B₆)₂₈…₀ + (A₅⋅B₄+A₄⋅B₅)₂₈…₀

// (A₈⋅B₁+A₁⋅B₈)₅₈…₂₉ + (A₇⋅B₂+A₂⋅B₇)₅₈…₂₉ + (A₆⋅B₃+A₃⋅B₆)₅₈…₂₉ + (A₅⋅B₄+A₄⋅B₅)₅₈…₂₉ +
// (A₅⋅B₅)₂₈…₀ + (A₈⋅B₂+A₂⋅B₈)₂₈…₀ + (A₇⋅B₃+A₃⋅B₇)₂₈…₀ + (A₆⋅B₄+A₄⋅B₆)₂₈…₀

// (A₅⋅B₅)₅₇…₂₉ + (A₈⋅B₂+A₂⋅B₈)₅₈…₂₉ + (A₇⋅B₃+A₃⋅B₇)₅₈…₂₉ + (A₆⋅B₄+A₄⋅B₆)₅₈…₂₉ +
// (A₈⋅B₃+A₃⋅B₈)₂₈…₀ + (A₇⋅B₄+A₄⋅B₇)₂₈…₀ + (A₆⋅B₅+A₅⋅B₆)₂₈…₀

// (A₈⋅B₃+A₃⋅B₈)₅₈…₂₉ + (A₇⋅B₄+A₄⋅B₇)₅₈…₂₉ + (A₆⋅B₅+A₅⋅B₆)₅₈…₂₉ +
// (A₆⋅B₆)₂₈…₀ + (A₇⋅B₅+A₅⋅B₇)₂₈…₀ + (A₈⋅B₄+A₄⋅B₈)₂₈…₀

// (A₆⋅B₆)₅₇…₂₉ + (A₇⋅B₅+A₅⋅B₇)₅₈…₂₉ + (A₈⋅B₄+A₄⋅B₈)₅₈…₂₉ +
// (A₈⋅B₅+A₅⋅B₈)₂₈…₀ + (A₇⋅B₆+A₆⋅B₇)₂₈…₀

// (A₈⋅B₅+A₅⋅B₈)₅₈…₂₉ + (A₇⋅B₆+A₆⋅B₇)₅₈…₂₉ +
// (A₇⋅B₇)₂₈…₀ + (A₈⋅B₆+A₆⋅B₈)₂₈…₀

// (A₇⋅B₇)₅₇…₂₉ + (A₈⋅B₆+A₆⋅B₈)₅₈…₂₉ +
// (A₈⋅B₇+A₇⋅B₈)₂₈…₀

// (A₈⋅B₇+A₇⋅B₈)₅₈…₂₉ +
// (A₈⋅B₈)₂₈…₀

// (A₈⋅B₈)₅₇…₂₉

//                       A₈⋅B₈
//                    A₈⋅B₇+A₇⋅B₈
//                 A₈⋅B₆+A₇⋅B₇+A₆⋅B₈
//              A₈⋅B₅+A₇⋅B₆+A₆⋅B₇+A₅⋅B₈
//            A₈⋅B₄+A₇⋅B₅+A₆⋅B₆+A₅⋅B₇+A₄⋅B₈
//         A₈⋅B₃+A₇⋅B₄+A₆⋅B₅+A₅⋅B₆+A₄⋅B₇+A₃⋅B₈
//       A₈⋅B₂+A₇⋅B₃+A₆⋅B₄+A₅⋅B₅+A₄⋅B₆+A₃⋅B₇+A₂⋅B₈
//    A₈⋅B₁+A₇⋅B₂+A₆⋅B₃+A₅⋅B₄+A₄⋅B₅+A₃⋅B₆+A₂⋅B₇+A₁⋅B₈
// A₈⋅B₀+A₇⋅B₁+A₆⋅B₂+A₅⋅B₃+A₄⋅B₄+A₃⋅B₅+A₂⋅B₆+A₁⋅B₇+A₀⋅B₈
//    A₇⋅B₀+A₆⋅B₁+A₅⋅B₂+A₄⋅B₃+A₃⋅B₄+A₂⋅B₅+A₁⋅B₆+A₀⋅B₇
//       A₆⋅B₀+A₅⋅B₁+A₄⋅B₂+A₃⋅B₃+A₂⋅B₄+A₁⋅B₅+A₀⋅B₆
//         A₅⋅B₀+A₄⋅B₁+A₃⋅B₂+A₂⋅B₃+A₁⋅B₄+A₀⋅B₅
//            A₄⋅B₀+A₃⋅B₁+A₂⋅B₂+A₁⋅B₃+A₀⋅B₄
//               A₃⋅B₀+A₂⋅B₁+A₁⋅B₂+A₀⋅B₃
//                  A₂⋅B₀+A₁⋅B₁+A₀⋅B₂
//                     A₁⋅B₀+A₀⋅B₁
//                        A₀⋅B₀

pub fn u29x9_mul_karazuba(a: u32, b: u32) -> Script {
    script! {
        // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ A₁ A₀ ⋯ B₈ B₇ B₆ B₅ B₄ B₃ B₂ B₁ B₀ ⋯
        { U254::zip(a, b) }
        // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ B₁ A₀ B₀

        // A₁₊₀ B₁₊₀
        { 1 << 1 | 0 } OP_PICK { 0 << 1 | 0 } OP_1ADD OP_PICK OP_ADD OP_TOALTSTACK
        { 1 << 1 | 1 } OP_PICK { 0 << 1 | 1 } OP_1ADD OP_PICK OP_ADD OP_TOALTSTACK
        // A₂₊₀ B₂₊₀
        { 2 << 1 | 0 } OP_PICK { 0 << 1 | 0 } OP_1ADD OP_PICK OP_ADD OP_TOALTSTACK
        { 2 << 1 | 1 } OP_PICK { 0 << 1 | 1 } OP_1ADD OP_PICK OP_ADD OP_TOALTSTACK
        // A₃₊₀ B₃₊₀ A₂₊₁ B₂₊₁
        for j in 0..2 {
            { 3 - j << 1 | 0 } OP_PICK { j << 1 | 0 } OP_1ADD OP_PICK OP_ADD OP_TOALTSTACK
            { 3 - j << 1 | 1 } OP_PICK { j << 1 | 1 } OP_1ADD OP_PICK OP_ADD OP_TOALTSTACK
        }
        // A₄₊₀ B₄₊₀ A₃₊₁ B₃₊₁
        for j in 0..2 {
            { 4 - j << 1 | 0 } OP_PICK { j << 1 | 0 } OP_1ADD OP_PICK OP_ADD OP_TOALTSTACK
            { 4 - j << 1 | 1 } OP_PICK { j << 1 | 1 } OP_1ADD OP_PICK OP_ADD OP_TOALTSTACK
        }
        // A₅₊₀ B₅₊₀ A₄₊₁ B₄₊₁ A₃₊₂ B₃₊₂
        for j in 0..3 {
            { 5 - j << 1 | 0 } OP_PICK { j << 1 | 0 } OP_1ADD OP_PICK OP_ADD OP_TOALTSTACK
            { 5 - j << 1 | 1 } OP_PICK { j << 1 | 1 } OP_1ADD OP_PICK OP_ADD OP_TOALTSTACK
        }
        // A₆₊₀ B₆₊₀ A₅₊₁ B₅₊₁ A₄₊₂ B₄₊₂
        for j in 0..3 {
            { 6 - j << 1 | 0 } OP_PICK { j << 1 | 0 } OP_1ADD OP_PICK OP_ADD OP_TOALTSTACK
            { 6 - j << 1 | 1 } OP_PICK { j << 1 | 1 } OP_1ADD OP_PICK OP_ADD OP_TOALTSTACK
        }
        // A₇₊₀ B₇₊₀ A₆₊₁ B₆₊₁ A₅₊₂ B₅₊₂ A₄₊₃ B₄₊₃
        for j in 0..4 {
            { 7 - j << 1 | 0 } OP_PICK { j << 1 | 0 } OP_1ADD OP_PICK OP_ADD OP_TOALTSTACK
            { 7 - j << 1 | 1 } OP_PICK { j << 1 | 1 } OP_1ADD OP_PICK OP_ADD OP_TOALTSTACK
        }
        // A₈₊₀ B₈₊₀ A₇₊₁ B₇₊₁ A₆₊₂ B₆₊₂ A₅₊₃ B₅₊₃
        for j in 0..4 {
            { 8 - j << 1 | 0 } OP_PICK { j << 1 | 0 } OP_1ADD OP_PICK OP_ADD OP_TOALTSTACK
            { 8 - j << 1 | 1 } OP_PICK { j << 1 | 1 } OP_1ADD OP_PICK OP_ADD OP_TOALTSTACK
        }
        // A₈₊₁ B₈₊₁ A₇₊₂ B₇₊₂ A₆₊₃ B₆₊₃ A₅₊₄ B₅₊₄
        for j in 1..5 {
            { 9 - j << 1 | 0 } OP_PICK { j << 1 | 0 } OP_1ADD OP_PICK OP_ADD OP_TOALTSTACK
            { 9 - j << 1 | 1 } OP_PICK { j << 1 | 1 } OP_1ADD OP_PICK OP_ADD OP_TOALTSTACK
        }
        // A₈₊₂ B₈₊₂ A₇₊₃ B₇₊₃ A₆₊₄ B₆₊₄
        for j in 2..5 {
            { 10 - j << 1 | 0 } OP_PICK { j << 1 | 0 } OP_1ADD OP_PICK OP_ADD OP_TOALTSTACK
            { 10 - j << 1 | 1 } OP_PICK { j << 1 | 1 } OP_1ADD OP_PICK OP_ADD OP_TOALTSTACK
        }
        // A₈₊₃ B₈₊₃ A₇₊₄ B₇₊₄ A₆₊₅ B₆₊₅
        for j in 3..6 {
            { 11 - j << 1 | 0 } OP_PICK { j << 1 | 0 } OP_1ADD OP_PICK OP_ADD OP_TOALTSTACK
            { 11 - j << 1 | 1 } OP_PICK { j << 1 | 1 } OP_1ADD OP_PICK OP_ADD OP_TOALTSTACK
        }
        // A₈₊₄ B₈₊₄ A₇₊₅ B₇₊₅
        for j in 4..6 {
            { 12 - j << 1 | 0 } OP_PICK { j << 1 | 0 } OP_1ADD OP_PICK OP_ADD OP_TOALTSTACK
            { 12 - j << 1 | 1 } OP_PICK { j << 1 | 1 } OP_1ADD OP_PICK OP_ADD OP_TOALTSTACK
        }
        // A₈₊₅ B₈₊₅ A₇₊₆ B₇₊₆
        for j in 5..7 {
            { 13 - j << 1 | 0 } OP_PICK { j << 1 | 0 } OP_1ADD OP_PICK OP_ADD OP_TOALTSTACK
            { 13 - j << 1 | 1 } OP_PICK { j << 1 | 1 } OP_1ADD OP_PICK OP_ADD OP_TOALTSTACK
        }
        // A₈₊₆ B₈₊₆
        { 8 << 1 | 0 } OP_PICK { 6 << 1 | 0 } OP_1ADD OP_PICK OP_ADD OP_TOALTSTACK
        { 8 << 1 | 1 } OP_PICK { 6 << 1 | 1 } OP_1ADD OP_PICK OP_ADD OP_TOALTSTACK
        // A₈₊₇ B₈₊₇
        { 8 << 1 | 0 } OP_PICK { 7 << 1 | 0 } OP_1ADD OP_PICK OP_ADD OP_TOALTSTACK
        { 8 << 1 | 1 } OP_PICK { 7 << 1 | 1 } OP_1ADD OP_PICK OP_ADD OP_TOALTSTACK

        for _ in 0..9 {
            { 8 << 1 | 1 } OP_ROLL
            { 8 << 1 | 1 } OP_ROLL
            { u29_mul_carry_29() }
            OP_SWAP
        }

        // ⋯
        OP_DEPTH
        // ⋯ *

        // A₈₊₇⋅B₈₊₇ - A₈⋅B₈ - A₇⋅B₇  <=>  A₈⋅B₇ + A₇⋅B₈
        // ⋯ *
        OP_FROMALTSTACK OP_FROMALTSTACK { u30_mul_to_u29_carry_31() } OP_ROT
        // ⋯ (A₈₊₇⋅B₈₊₇)₂₈…₀ (A₈₊₇⋅B₈₊₇)₅₉…₂₉ *
        OP_DEPTH OP_OVER OP_SUB { 8 << 1 } OP_ADD OP_PICK OP_SWAP OP_DEPTH OP_OVER OP_SUB { 8 << 1| 1 } OP_ADD OP_PICK OP_SWAP OP_TOALTSTACK { u29x2_sub_noborrow() } OP_FROMALTSTACK
        OP_DEPTH OP_OVER OP_SUB { 7 << 1 } OP_ADD OP_PICK OP_SWAP OP_DEPTH OP_OVER OP_SUB { 7 << 1| 1 } OP_ADD OP_PICK OP_SWAP OP_TOALTSTACK { u29x2_sub_noborrow() } OP_FROMALTSTACK
        // ⋯ (A₈⋅B₇+A₇⋅B₈)₂₈…₀ (A₈⋅B₇+A₇⋅B₈)₅₈…₂₉ *

        // A₈₊₆⋅B₈₊₆ - A₈⋅B₈ - A₆⋅B₆  <=>  A₈⋅B₆ + A₆⋅B₈
        OP_FROMALTSTACK OP_FROMALTSTACK { u30_mul_to_u29_carry_31() } OP_ROT
        // ⋯ (A₈₊₆⋅B₈₊₆)₂₈…₀ (A₈₊₆⋅B₈₊₆)₅₉…₂₉ *
        OP_DEPTH OP_OVER OP_SUB { 8 << 1 } OP_ADD OP_PICK OP_SWAP OP_DEPTH OP_OVER OP_SUB { 8 << 1 | 1 } OP_ADD OP_PICK OP_SWAP OP_TOALTSTACK { u29x2_sub_noborrow() } OP_FROMALTSTACK
        OP_DEPTH OP_OVER OP_SUB { 6 << 1 } OP_ADD OP_PICK OP_SWAP OP_DEPTH OP_OVER OP_SUB { 6 << 1 | 1 } OP_ADD OP_PICK OP_SWAP OP_TOALTSTACK { u29x2_sub_noborrow() } OP_FROMALTSTACK
        // ⋯ (A₈⋅B₆+A₆⋅B₈)₂₈…₀ (A₈⋅B₆+A₆⋅B₈)₅₈…₂₉ *

        // A₈₊₅⋅B₈₊₅ - A₈⋅B₈ - A₅⋅B₅  <=>  A₈⋅B₅ + A₅⋅B₈
        // A₇₊₆⋅B₇₊₆ - A₇⋅B₇ - A₆⋅B₆  <=>  A₇⋅B₆ + A₆⋅B₇
        for j in 5..7 {
            OP_FROMALTSTACK OP_FROMALTSTACK { u30_mul_to_u29_carry_31() } OP_ROT
            // ⋯ (A₈₊₅⋅B₈₊₅)₂₈…₀ (A₈₊₅⋅B₈₊₅)₅₉…₂₉ *
            // ⋯ (A₇₊₆⋅B₇₊₆)₂₈…₀ (A₇₊₆⋅B₇₊₆)₅₉…₂₉ *
            OP_DEPTH OP_OVER OP_SUB { 13 - j << 1 } OP_ADD OP_PICK OP_SWAP OP_DEPTH OP_OVER OP_SUB { 13 - j << 1 | 1 } OP_ADD OP_PICK OP_SWAP OP_TOALTSTACK { u29x2_sub_noborrow() } OP_FROMALTSTACK
            OP_DEPTH OP_OVER OP_SUB {      j << 1 } OP_ADD OP_PICK OP_SWAP OP_DEPTH OP_OVER OP_SUB {      j << 1 | 1 } OP_ADD OP_PICK OP_SWAP OP_TOALTSTACK { u29x2_sub_noborrow() } OP_FROMALTSTACK
            // ⋯ (A₈⋅B₅+A₅⋅B₈)₂₈…₀ (A₈⋅B₅+A₅⋅B₈)₅₈…₂₉ *
            // ⋯ (A₇⋅B₆+A₆⋅B₇)₂₈…₀ (A₇⋅B₆+A₆⋅B₇)₅₈…₂₉ *
        }

        // A₈₊₄⋅B₈₊₄ - A₈⋅B₈ - A₄⋅B₄  <=>  A₈⋅B₄ + A₄⋅B₈
        // A₇₊₅⋅B₇₊₅ - A₇⋅B₇ - A₅⋅B₅  <=>  A₇⋅B₅ + A₅⋅B₇
        for j in 4..6 {
            OP_FROMALTSTACK OP_FROMALTSTACK { u30_mul_to_u29_carry_31() } OP_ROT
            // ⋯ (A₈₊₄⋅B₈₊₄)₂₈…₀ (A₈₊₄⋅B₈₊₄)₅₉…₂₉ *
            // ⋯ (A₇₊₅⋅B₇₊₅)₂₈…₀ (A₇₊₅⋅B₇₊₅)₅₉…₂₉ *
            OP_DEPTH OP_OVER OP_SUB { 12 - j << 1 } OP_ADD OP_PICK OP_SWAP OP_DEPTH OP_OVER OP_SUB { 12 - j << 1 | 1 } OP_ADD OP_PICK OP_SWAP OP_TOALTSTACK { u29x2_sub_noborrow() } OP_FROMALTSTACK
            OP_DEPTH OP_OVER OP_SUB {      j << 1 } OP_ADD OP_PICK OP_SWAP OP_DEPTH OP_OVER OP_SUB {      j << 1 | 1 } OP_ADD OP_PICK OP_SWAP OP_TOALTSTACK { u29x2_sub_noborrow() } OP_FROMALTSTACK
            // ⋯ (A₈⋅B₄+A₄⋅B₈)₂₈…₀ (A₈⋅B₄+A₄⋅B₈)₅₈…₂₉ *
            // ⋯ (A₇⋅B₅+A₅⋅B₇)₂₈…₀ (A₇⋅B₅+A₅⋅B₇)₅₈…₂₉ *
        }

        // A₈₊₃⋅B₈₊₃ - A₈⋅B₈ - A₃⋅B₃  <=>  A₈⋅B₃ + A₃⋅B₈
        // A₇₊₄⋅B₇₊₄ - A₇⋅B₇ - A₄⋅B₄  <=>  A₇⋅B₄ + A₄⋅B₇
        // A₆₊₅⋅B₆₊₅ - A₆⋅B₆ - A₅⋅B₅  <=>  A₆⋅B₅ + A₅⋅B₆
        for j in 3..6 {
            OP_FROMALTSTACK OP_FROMALTSTACK { u30_mul_to_u29_carry_31() } OP_ROT
            // ⋯ (A₈₊₃⋅B₈₊₃)₂₈…₀ (A₈₊₃⋅B₈₊₃)₅₉…₂₉ *
            // ⋯ (A₇₊₄⋅B₇₊₄)₂₈…₀ (A₇₊₄⋅B₇₊₄)₅₉…₂₉ *
            // ⋯ (A₆₊₅⋅B₆₊₅)₂₈…₀ (A₆₊₅⋅B₆₊₅)₅₉…₂₉ *
            OP_DEPTH OP_OVER OP_SUB { 11 - j << 1 } OP_ADD OP_PICK OP_SWAP OP_DEPTH OP_OVER OP_SUB { 11 - j << 1 | 1 } OP_ADD OP_PICK OP_SWAP OP_TOALTSTACK { u29x2_sub_noborrow() } OP_FROMALTSTACK
            OP_DEPTH OP_OVER OP_SUB {      j << 1 } OP_ADD OP_PICK OP_SWAP OP_DEPTH OP_OVER OP_SUB {      j << 1 | 1 } OP_ADD OP_PICK OP_SWAP OP_TOALTSTACK { u29x2_sub_noborrow() } OP_FROMALTSTACK
            // ⋯ (A₈⋅B₃+A₃⋅B₈)₂₈…₀ (A₈⋅B₃+A₃⋅B₈)₅₈…₂₉ *
            // ⋯ (A₇⋅B₄+A₄⋅B₇)₂₈…₀ (A₇⋅B₄+A₄⋅B₇)₅₈…₂₉ *
            // ⋯ (A₆⋅B₅+A₅⋅B₆)₂₈…₀ (A₆⋅B₅+A₅⋅B₆)₅₈…₂₉ *
        }

        // A₈₊₂⋅B₈₊₂ - A₈⋅B₈ - A₂⋅B₂  <=>  A₈⋅B₂ + A₂⋅B₈
        // A₇₊₃⋅B₇₊₃ - A₇⋅B₇ - A₃⋅B₃  <=>  A₇⋅B₃ + A₃⋅B₇
        // A₆₊₄⋅B₆₊₄ - A₆⋅B₆ - A₄⋅B₄  <=>  A₆⋅B₄ + A₄⋅B₆
        for j in 2..5 {
            OP_FROMALTSTACK OP_FROMALTSTACK { u30_mul_to_u29_carry_31() } OP_ROT
            // ⋯ (A₈₊₂⋅B₈₊₂)₂₈…₀ (A₈₊₂⋅B₈₊₂)₅₉…₂₉ *
            // ⋯ (A₇₊₃⋅B₇₊₃)₂₈…₀ (A₇₊₃⋅B₇₊₃)₅₉…₂₉ *
            // ⋯ (A₆₊₄⋅B₆₊₄)₂₈…₀ (A₆₊₄⋅B₆₊₄)₅₉…₂₉ *
            OP_DEPTH OP_OVER OP_SUB { 10 - j << 1 } OP_ADD OP_PICK OP_SWAP OP_DEPTH OP_OVER OP_SUB { 10 - j << 1 | 1 } OP_ADD OP_PICK OP_SWAP OP_TOALTSTACK { u29x2_sub_noborrow() } OP_FROMALTSTACK
            OP_DEPTH OP_OVER OP_SUB {      j << 1 } OP_ADD OP_PICK OP_SWAP OP_DEPTH OP_OVER OP_SUB {      j << 1 | 1 } OP_ADD OP_PICK OP_SWAP OP_TOALTSTACK { u29x2_sub_noborrow() } OP_FROMALTSTACK
            // ⋯ (A₈⋅B₂+A₂⋅B₈)₂₈…₀ (A₈⋅B₂+A₂⋅B₈)₅₈…₂₉ *
            // ⋯ (A₇⋅B₃+A₃⋅B₇)₂₈…₀ (A₇⋅B₃+A₃⋅B₇)₅₈…₂₉ *
            // ⋯ (A₆⋅B₄+A₄⋅B₆)₂₈…₀ (A₆⋅B₄+A₄⋅B₆)₅₈…₂₉ *
        }

        // A₈₊₁⋅B₈₊₁ - A₈⋅B₈ - A₁⋅B₁  <=>  A₈⋅B₁ + A₁⋅B₈
        // A₇₊₂⋅B₇₊₂ - A₇⋅B₇ - A₂⋅B₂  <=>  A₇⋅B₂ + A₂⋅B₇
        // A₆₊₃⋅B₆₊₃ - A₆⋅B₆ - A₃⋅B₃  <=>  A₆⋅B₃ + A₃⋅B₆
        // A₅₊₄⋅B₅₊₄ - A₅⋅B₅ - A₄⋅B₄  <=>  A₅⋅B₄ + A₄⋅B₅
        for j in 1..5 {
            OP_FROMALTSTACK OP_FROMALTSTACK { u30_mul_to_u29_carry_31() } OP_ROT
            // ⋯ (A₈₊₁⋅B₈₊₁)₂₈…₀ (A₈₊₁⋅B₈₊₁)₅₉…₂₉ *
            // ⋯ (A₇₊₂⋅B₇₊₂)₂₈…₀ (A₇₊₂⋅B₇₊₂)₅₉…₂₉ *
            // ⋯ (A₆₊₃⋅B₆₊₃)₂₈…₀ (A₆₊₃⋅B₆₊₃)₅₉…₂₉ *
            // ⋯ (A₅₊₄⋅B₅₊₄)₂₈…₀ (A₅₊₄⋅B₅₊₄)₅₉…₂₉ *
            OP_DEPTH OP_OVER OP_SUB { 9 - j << 1 } OP_ADD OP_PICK OP_SWAP OP_DEPTH OP_OVER OP_SUB { 9 - j << 1 | 1 } OP_ADD OP_PICK OP_SWAP OP_TOALTSTACK { u29x2_sub_noborrow() } OP_FROMALTSTACK
            OP_DEPTH OP_OVER OP_SUB {     j << 1 } OP_ADD OP_PICK OP_SWAP OP_DEPTH OP_OVER OP_SUB {     j << 1 | 1 } OP_ADD OP_PICK OP_SWAP OP_TOALTSTACK { u29x2_sub_noborrow() } OP_FROMALTSTACK
            // ⋯ (A₈⋅B₁+A₁⋅B₈)₂₈…₀ (A₈⋅B₁+A₁⋅B₈)₅₈…₂₉ *
            // ⋯ (A₇⋅B₂+A₂⋅B₇)₂₈…₀ (A₇⋅B₂+A₂⋅B₇)₅₈…₂₉ *
            // ⋯ (A₆⋅B₃+A₃⋅B₆)₂₈…₀ (A₆⋅B₃+A₃⋅B₆)₅₈…₂₉ *
            // ⋯ (A₅⋅B₄+A₄⋅B₅)₂₈…₀ (A₅⋅B₄+A₄⋅B₅)₅₈…₂₉ *
        }

        // A₈₊₀⋅B₈₊₀ - A₈⋅B₈ - A₀⋅B₀  <=>  A₈⋅B₀ + A₀⋅B₈
        // A₇₊₁⋅B₇₊₁ - A₇⋅B₇ - A₁⋅B₁  <=>  A₇⋅B₁ + A₁⋅B₇
        // A₆₊₂⋅B₆₊₂ - A₆⋅B₆ - A₂⋅B₂  <=>  A₆⋅B₂ + A₂⋅B₆
        // A₅₊₃⋅B₅₊₃ - A₅⋅B₅ - A₃⋅B₃  <=>  A₅⋅B₃ + A₃⋅B₅
        for j in 0..4 {
            OP_FROMALTSTACK OP_FROMALTSTACK { u30_mul_to_u29_carry_31() } OP_ROT
            // ⋯ (A₈₊₀⋅B₈₊₀)₂₈…₀ (A₈₊₀⋅B₈₊₀)₅₉…₂₉ *
            // ⋯ (A₇₊₁⋅B₇₊₁)₂₈…₀ (A₇₊₁⋅B₇₊₁)₅₉…₂₉ *
            // ⋯ (A₆₊₂⋅B₆₊₂)₂₈…₀ (A₆₊₂⋅B₆₊₂)₅₉…₂₉ *
            // ⋯ (A₅₊₃⋅B₅₊₃)₂₈…₀ (A₅₊₃⋅B₅₊₃)₅₉…₂₉ *
            OP_DEPTH OP_OVER OP_SUB { 8 - j << 1 } OP_ADD OP_PICK OP_SWAP OP_DEPTH OP_OVER OP_SUB { 8 - j << 1 | 1 } OP_ADD OP_PICK OP_SWAP OP_TOALTSTACK { u29x2_sub_noborrow() } OP_FROMALTSTACK
            OP_DEPTH OP_OVER OP_SUB {     j << 1 } OP_ADD OP_PICK OP_SWAP OP_DEPTH OP_OVER OP_SUB {     j << 1 | 1 } OP_ADD OP_PICK OP_SWAP OP_TOALTSTACK { u29x2_sub_noborrow() } OP_FROMALTSTACK
            // ⋯ (A₈⋅B₀+A₀⋅B₈)₂₈…₀ (A₈⋅B₀+A₀⋅B₈)₅₈…₂₉ *
            // ⋯ (A₇⋅B₁+A₁⋅B₇)₂₈…₀ (A₇⋅B₁+A₁⋅B₇)₅₈…₂₉ *
            // ⋯ (A₆⋅B₂+A₂⋅B₆)₂₈…₀ (A₆⋅B₂+A₂⋅B₆)₅₈…₂₉ *
            // ⋯ (A₅⋅B₃+A₃⋅B₅)₂₈…₀ (A₅⋅B₃+A₃⋅B₅)₅₈…₂₉ *
        }

        // A₇₊₀⋅B₇₊₀ - A₇⋅B₇ - A₀⋅B₀  <=>  A₇⋅B₀ + A₀⋅B₇
        // A₆₊₁⋅B₆₊₁ - A₆⋅B₆ - A₁⋅B₁  <=>  A₆⋅B₁ + A₁⋅B₆
        // A₅₊₂⋅B₅₊₂ - A₅⋅B₅ - A₂⋅B₂  <=>  A₅⋅B₂ + A₂⋅B₅
        // A₄₊₃⋅B₄₊₃ - A₄⋅B₄ - A₃⋅B₃  <=>  A₄⋅B₃ + A₃⋅B₄
        for j in 0..4 {
            OP_FROMALTSTACK OP_FROMALTSTACK { u30_mul_to_u29_carry_31() } OP_ROT
            // ⋯ (A₇₊₀⋅B₇₊₀)₂₈…₀ (A₇₊₀⋅B₇₊₀)₅₉…₂₉ *
            // ⋯ (A₆₊₁⋅B₆₊₁)₂₈…₀ (A₆₊₁⋅B₆₊₁)₅₉…₂₉ *
            // ⋯ (A₅₊₂⋅B₅₊₂)₂₈…₀ (A₅₊₂⋅B₅₊₂)₅₉…₂₉ *
            // ⋯ (A₄₊₃⋅B₄₊₃)₂₈…₀ (A₄₊₃⋅B₄₊₃)₅₉…₂₉ *
            OP_DEPTH OP_OVER OP_SUB { 7 - j << 1 } OP_ADD OP_PICK OP_SWAP OP_DEPTH OP_OVER OP_SUB { 7 - j << 1 | 1 } OP_ADD OP_PICK OP_SWAP OP_TOALTSTACK { u29x2_sub_noborrow() } OP_FROMALTSTACK
            OP_DEPTH OP_OVER OP_SUB {     j << 1 } OP_ADD OP_PICK OP_SWAP OP_DEPTH OP_OVER OP_SUB {     j << 1 | 1 } OP_ADD OP_PICK OP_SWAP OP_TOALTSTACK { u29x2_sub_noborrow() } OP_FROMALTSTACK
            // ⋯ (A₇⋅B₀+A₀⋅B₇)₂₈…₀ (A₇⋅B₀+A₀⋅B₇)₅₈…₂₉ *
            // ⋯ (A₆⋅B₁+A₁⋅B₆)₂₈…₀ (A₆⋅B₁+A₁⋅B₆)₅₈…₂₉ *
            // ⋯ (A₅⋅B₂+A₂⋅B₅)₂₈…₀ (A₅⋅B₂+A₂⋅B₅)₅₈…₂₉ *
            // ⋯ (A₄⋅B₃+A₃⋅B₄)₂₈…₀ (A₄⋅B₃+A₃⋅B₄)₅₈…₂₉ *
        }

        // A₆₊₀⋅B₆₊₀ - A₆⋅B₆ - A₀⋅B₀  <=>  A₆⋅B₀ + A₀⋅B₆
        // A₅₊₁⋅B₅₊₁ - A₅⋅B₅ - A₁⋅B₁  <=>  A₅⋅B₁ + A₁⋅B₅
        // A₄₊₂⋅B₄₊₂ - A₄⋅B₄ - A₂⋅B₂  <=>  A₄⋅B₂ + A₂⋅B₄
        for j in 0..3 {
            OP_FROMALTSTACK OP_FROMALTSTACK { u30_mul_to_u29_carry_31() } OP_ROT
            // ⋯ (A₆₊₀⋅B₆₊₀)₂₈…₀ (A₆₊₀⋅B₆₊₀)₅₉…₂₉ *
            // ⋯ (A₅₊₁⋅B₅₊₁)₂₈…₀ (A₅₊₁⋅B₅₊₁)₅₉…₂₉ *
            // ⋯ (A₄₊₂⋅B₄₊₂)₂₈…₀ (A₄₊₂⋅B₄₊₂)₅₉…₂₉ *
            OP_DEPTH OP_OVER OP_SUB { 6 - j << 1 } OP_ADD OP_PICK OP_SWAP OP_DEPTH OP_OVER OP_SUB { 6 - j << 1 | 1 } OP_ADD OP_PICK OP_SWAP OP_TOALTSTACK { u29x2_sub_noborrow() } OP_FROMALTSTACK
            OP_DEPTH OP_OVER OP_SUB {     j << 1 } OP_ADD OP_PICK OP_SWAP OP_DEPTH OP_OVER OP_SUB {     j << 1 | 1 } OP_ADD OP_PICK OP_SWAP OP_TOALTSTACK { u29x2_sub_noborrow() } OP_FROMALTSTACK
            // ⋯ (A₆⋅B₀+A₀⋅B₆)₂₈…₀ (A₆⋅B₀+A₀⋅B₆)₅₈…₂₉ *
            // ⋯ (A₅⋅B₁+A₁⋅B₅)₂₈…₀ (A₅⋅B₁+A₁⋅B₅)₅₈…₂₉ *
            // ⋯ (A₄⋅B₂+A₂⋅B₄)₂₈…₀ (A₄⋅B₂+A₂⋅B₄)₅₈…₂₉ *
        }

        // A₅₊₀⋅B₅₊₀ - A₅⋅B₅ - A₀⋅B₀  <=>  A₅⋅B₀ + A₀⋅B₅
        // A₄₊₁⋅B₄₊₁ - A₄⋅B₄ - A₁⋅B₁  <=>  A₄⋅B₁ + A₁⋅B₄
        // A₃₊₂⋅B₃₊₂ - A₃⋅B₃ - A₂⋅B₂  <=>  A₃⋅B₂ + A₂⋅B₃
        for j in 0..3 {
            OP_FROMALTSTACK OP_FROMALTSTACK { u30_mul_to_u29_carry_31() } OP_ROT
            // ⋯ (A₅₊₀⋅B₅₊₀)₂₈…₀ (A₅₊₀⋅B₅₊₀)₅₉…₂₉ *
            // ⋯ (A₄₊₁⋅B₄₊₁)₂₈…₀ (A₄₊₁⋅B₄₊₁)₅₉…₂₉ *
            // ⋯ (A₃₊₂⋅B₃₊₂)₂₈…₀ (A₃₊₂⋅B₃₊₂)₅₉…₂₉ *
            OP_DEPTH OP_OVER OP_SUB { 5 - j << 1 } OP_ADD OP_PICK OP_SWAP OP_DEPTH OP_OVER OP_SUB { 5 - j << 1 | 1 } OP_ADD OP_PICK OP_SWAP OP_TOALTSTACK { u29x2_sub_noborrow() } OP_FROMALTSTACK
            OP_DEPTH OP_OVER OP_SUB {     j << 1 } OP_ADD OP_PICK OP_SWAP OP_DEPTH OP_OVER OP_SUB {     j << 1 | 1 } OP_ADD OP_PICK OP_SWAP OP_TOALTSTACK { u29x2_sub_noborrow() } OP_FROMALTSTACK
            // ⋯ (A₅⋅B₀+A₀⋅B₅)₂₈…₀ (A₅⋅B₀+A₀⋅B₅)₅₈…₂₉ *
            // ⋯ (A₄⋅B₁+A₁⋅B₄)₂₈…₀ (A₄⋅B₁+A₁⋅B₄)₅₈…₂₉ *
            // ⋯ (A₃⋅B₂+A₂⋅B₃)₂₈…₀ (A₃⋅B₂+A₂⋅B₃)₅₈…₂₉ *
        }

        // A₄₊₀⋅B₄₊₀ - A₄⋅B₄ - A₀⋅B₀  <=>  A₄⋅B₀ + A₀⋅B₄
        // A₃₊₁⋅B₃₊₁ - A₃⋅B₃ - A₁⋅B₁  <=>  A₃⋅B₁ + A₁⋅B₃
        for j in 0..2 {
            OP_FROMALTSTACK OP_FROMALTSTACK { u30_mul_to_u29_carry_31() } OP_ROT
            // ⋯ (A₄₊₀⋅B₄₊₀)₂₈…₀ (A₄₊₀⋅B₄₊₀)₅₉…₂₉ *
            // ⋯ (A₃₊₁⋅B₃₊₁)₂₈…₀ (A₃₊₁⋅B₃₊₁)₅₉…₂₉ *
            OP_DEPTH OP_OVER OP_SUB { 4 - j << 1 } OP_ADD OP_PICK OP_SWAP OP_DEPTH OP_OVER OP_SUB { 4 - j << 1 | 1 } OP_ADD OP_PICK OP_SWAP OP_TOALTSTACK { u29x2_sub_noborrow() } OP_FROMALTSTACK
            OP_DEPTH OP_OVER OP_SUB {     j << 1 } OP_ADD OP_PICK OP_SWAP OP_DEPTH OP_OVER OP_SUB {     j << 1 | 1 } OP_ADD OP_PICK OP_SWAP OP_TOALTSTACK { u29x2_sub_noborrow() } OP_FROMALTSTACK
            // ⋯ (A₄⋅B₀+A₀⋅B₄)₂₈…₀ (A₄⋅B₀+A₀⋅B₄)₅₈…₂₉ *
            // ⋯ (A₃⋅B₁+A₁⋅B₃)₂₈…₀ (A₃⋅B₁+A₁⋅B₃)₅₈…₂₉ *
        }

        // A₃₊₀⋅B₃₊₀ - A₃⋅B₃ - A₀⋅B₀  <=>  A₃⋅B₀ + A₀⋅B₃
        // A₂₊₁⋅B₂₊₁ - A₂⋅B₂ - A₁⋅B₁  <=>  A₂⋅B₁ + A₁⋅B₂
        for j in 0..2 {
            OP_FROMALTSTACK OP_FROMALTSTACK { u30_mul_to_u29_carry_31() } OP_ROT
            // ⋯ (A₃₊₀⋅B₃₊₀)₂₈…₀ (A₃₊₀⋅B₃₊₀)₅₉…₂₉ *
            // ⋯ (A₂₊₁⋅B₂₊₁)₂₈…₀ (A₂₊₁⋅B₂₊₁)₅₉…₂₉ *
            OP_DEPTH OP_OVER OP_SUB { 3 - j << 1 } OP_ADD OP_PICK OP_SWAP OP_DEPTH OP_OVER OP_SUB { 3 - j << 1 | 1 } OP_ADD OP_PICK OP_SWAP OP_TOALTSTACK { u29x2_sub_noborrow() } OP_FROMALTSTACK
            OP_DEPTH OP_OVER OP_SUB {     j << 1 } OP_ADD OP_PICK OP_SWAP OP_DEPTH OP_OVER OP_SUB {     j << 1 | 1 } OP_ADD OP_PICK OP_SWAP OP_TOALTSTACK { u29x2_sub_noborrow() } OP_FROMALTSTACK
            // ⋯ (A₃⋅B₀+A₀⋅B₃)₂₈…₀ (A₃⋅B₀+A₀⋅B₃)₅₈…₂₉ *
            // ⋯ (A₂⋅B₁+A₁⋅B₂)₂₈…₀ (A₂⋅B₁+A₁⋅B₂)₅₈…₂₉ *
        }

        // A₂₊₀⋅B₂₊₀ - A₂⋅B₂ - A₀⋅B₀  <=>  A₂⋅B₀ + A₀⋅B₂
        OP_FROMALTSTACK OP_FROMALTSTACK { u30_mul_to_u29_carry_31() } OP_ROT
        // ⋯ (A₂₊₀⋅B₂₊₀)₂₈…₀ (A₂₊₀⋅B₂₊₀)₅₉…₂₉ *
        OP_DEPTH OP_OVER OP_SUB { 2 << 1 } OP_ADD OP_PICK OP_SWAP OP_DEPTH OP_OVER OP_SUB { 2 << 1 | 1 } OP_ADD OP_PICK OP_SWAP OP_TOALTSTACK { u29x2_sub_noborrow() } OP_FROMALTSTACK
        OP_DEPTH OP_OVER OP_SUB { 0 << 1 } OP_ADD OP_PICK OP_SWAP OP_DEPTH OP_OVER OP_SUB { 0 << 1 | 1 } OP_ADD OP_PICK OP_SWAP OP_TOALTSTACK { u29x2_sub_noborrow() } OP_FROMALTSTACK
        // ⋯ (A₂⋅B₀+A₀⋅B₂)₂₈…₀ (A₂⋅B₀+A₀⋅B₂)₅₈…₂₉ *

        // A₁₊₀⋅B₁₊₀ - A₁⋅B₁ - A₀⋅B₀  <=>  A₁⋅B₀ + A₀⋅B₁
        OP_FROMALTSTACK OP_FROMALTSTACK { u30_mul_to_u29_carry_31() } OP_ROT
        // ⋯ (A₁₊₀⋅B₁₊₀)₂₈…₀ (A₁₊₀⋅B₁₊₀)₅₉…₂₉ *
        OP_DEPTH OP_OVER OP_SUB { 1 << 1 } OP_ADD OP_PICK OP_SWAP OP_DEPTH OP_OVER OP_SUB { 1 << 1 | 1 } OP_ADD OP_PICK OP_SWAP OP_TOALTSTACK { u29x2_sub_noborrow() } OP_FROMALTSTACK
        OP_DEPTH OP_OVER OP_SUB { 0 << 1 } OP_ADD OP_PICK OP_SWAP OP_DEPTH OP_OVER OP_SUB { 0 << 1 | 1 } OP_ADD OP_PICK OP_SWAP OP_TOALTSTACK { u29x2_sub_noborrow() } OP_FROMALTSTACK
        // ⋯ (A₁⋅B₀+A₀⋅B₁)₂₈…₀ (A₁⋅B₀+A₀⋅B₁)₅₈…₂₉ *
        // (A₀⋅B₀)₂₈…₀
        // (A₀⋅B₀)₅₇…₂₉ + (A₁⋅B₀+A₀⋅B₁)₂₈…₀
        // (A₁⋅B₁)₂₈…₀ + (A₁⋅B₀+A₀⋅B₁)₅₈…₂₉ + (A₂⋅B₀+A₀⋅B₂)₂₈…₀
        // (A₁⋅B₁)₅₇…₂₉ + (A₂⋅B₀+A₀⋅B₂)₅₈…₂₉ + (A₃⋅B₀+A₀⋅B₃)₂₈…₀ + (A₂⋅B₁+A₁⋅B₂)₂₈…₀
        // (A₂⋅B₂)₂₈…₀ + (A₃⋅B₀+A₀⋅B₃)₅₈…₂₉ + (A₂⋅B₁+A₁⋅B₂)₅₈…₂₉ + (A₄⋅B₀+A₀⋅B₄)₂₈…₀ + (A₃⋅B₁+A₁⋅B₃)₂₈…₀
        // (A₂⋅B₂)₅₇…₂₉ + (A₄⋅B₀+A₀⋅B₄)₅₈…₂₉ + (A₃⋅B₁+A₁⋅B₃)₅₈…₂₉ + (A₅⋅B₀+A₀⋅B₅)₂₈…₀ + (A₄⋅B₁+A₁⋅B₄)₂₈…₀ + (A₃⋅B₂+A₂⋅B₃)₂₈…₀
        // (A₃⋅B₃)₂₈…₀ + (A₅⋅B₀+A₀⋅B₅)₅₈…₂₉ + (A₄⋅B₁+A₁⋅B₄)₅₈…₂₉ + (A₃⋅B₂+A₂⋅B₃)₅₈…₂₉ + (A₆⋅B₀+A₀⋅B₆)₂₈…₀ + (A₅⋅B₁+A₁⋅B₅)₂₈…₀ + (A₄⋅B₂+A₂⋅B₄)₂₈…₀
        // (A₃⋅B₃)₅₇…₂₉ + (A₆⋅B₀+A₀⋅B₆)₅₈…₂₉ + (A₅⋅B₁+A₁⋅B₅)₅₈…₂₉ + (A₄⋅B₂+A₂⋅B₄)₅₈…₂₉ + (A₇⋅B₀+A₀⋅B₇)₂₈…₀ + (A₆⋅B₁+A₁⋅B₆)₂₈…₀ + (A₅⋅B₂+A₂⋅B₅)₂₈…₀ + (A₄⋅B₃+A₃⋅B₄)₂₈…₀
        // (A₄⋅B₄)₂₈…₀ + (A₇⋅B₀+A₀⋅B₇)₅₈…₂₉ + (A₆⋅B₁+A₁⋅B₆)₅₈…₂₉ + (A₅⋅B₂+A₂⋅B₅)₅₈…₂₉ + (A₄⋅B₃+A₃⋅B₄)₅₈…₂₉ + (A₈⋅B₀+A₀⋅B₈)₂₈…₀ + (A₇⋅B₁+A₁⋅B₇)₂₈…₀ + (A₆⋅B₂+A₂⋅B₆)₂₈…₀ + (A₅⋅B₃+A₃⋅B₅)₂₈…₀
        // (A₄⋅B₄)₅₇…₂₉ + (A₈⋅B₀+A₀⋅B₈)₅₈…₂₉ + (A₇⋅B₁+A₁⋅B₇)₅₈…₂₉ + (A₆⋅B₂+A₂⋅B₆)₅₈…₂₉ + (A₅⋅B₃+A₃⋅B₅)₅₈…₂₉ (A₈⋅B₁+A₁⋅B₈)₂₈…₀ + (A₇⋅B₂+A₂⋅B₇)₂₈…₀ + (A₆⋅B₃+A₃⋅B₆)₂₈…₀ + (A₅⋅B₄+A₄⋅B₅)₂₈…₀
        // (A₅⋅B₅)₂₈…₀ + (A₈⋅B₁+A₁⋅B₈)₅₈…₂₉ + (A₇⋅B₂+A₂⋅B₇)₅₈…₂₉ + (A₆⋅B₃+A₃⋅B₆)₅₈…₂₉ + (A₅⋅B₄+A₄⋅B₅)₅₈…₂₉ + (A₈⋅B₂+A₂⋅B₈)₂₈…₀ + (A₇⋅B₃+A₃⋅B₇)₂₈…₀ + (A₆⋅B₄+A₄⋅B₆)₂₈…₀
        // (A₅⋅B₅)₅₇…₂₉ + (A₈⋅B₂+A₂⋅B₈)₅₈…₂₉ + (A₇⋅B₃+A₃⋅B₇)₅₈…₂₉ + (A₆⋅B₄+A₄⋅B₆)₅₈…₂₉ + (A₈⋅B₃+A₃⋅B₈)₂₈…₀ + (A₇⋅B₄+A₄⋅B₇)₂₈…₀ + (A₆⋅B₅+A₅⋅B₆)₂₈…₀
        // (A₆⋅B₆)₂₈…₀ + (A₈⋅B₃+A₃⋅B₈)₅₈…₂₉ + (A₇⋅B₄+A₄⋅B₇)₅₈…₂₉ + (A₆⋅B₅+A₅⋅B₆)₅₈…₂₉ + (A₈⋅B₄+A₄⋅B₈)₂₈…₀ + (A₇⋅B₅+A₅⋅B₇)₂₈…₀
        // (A₆⋅B₆)₅₇…₂₉ + (A₈⋅B₄+A₄⋅B₈)₅₈…₂₉ + (A₇⋅B₅+A₅⋅B₇)₅₈…₂₉ + (A₈⋅B₅+A₅⋅B₈)₂₈…₀ + (A₇⋅B₆+A₆⋅B₇)₂₈…₀
        // (A₇⋅B₇)₂₈…₀ + (A₈⋅B₅+A₅⋅B₈)₅₈…₂₉ + (A₇⋅B₆+A₆⋅B₇)₅₈…₂₉ + (A₈⋅B₆+A₆⋅B₈)₂₈…₀
        // (A₇⋅B₇)₅₇…₂₉ + (A₈⋅B₆+A₆⋅B₈)₅₈…₂₉ + (A₈⋅B₇+A₇⋅B₈)₅₈…₂₉ + (A₈⋅B₇+A₇⋅B₈)₂₈…₀
        // (A₈⋅B₈)₂₈…₀ + (A₈⋅B₇+A₇⋅B₈)₅₈…₂₉
        // (A₈⋅B₈)₅₇…₂₉


        // (A₀⋅B₀)₂₈…₀
        // ⋯ *
        OP_DEPTH OP_OVER OP_SUB OP_ROLL OP_TOALTSTACK OP_1SUB
        // ⋯ * | (A⋅B)₀
        OP_DEPTH OP_OVER OP_SUB OP_ROLL OP_SWAP OP_1SUB
        // ⋯ (A₀⋅B₀)₅₇…₂₉ *

        // (2²⁹⋅(A₁⋅B₁)₂₈…₀+(A₀⋅B₀)₅₇…₂₉)₅₇…₀ + (A₁⋅B₀+A₀⋅B₁)₅₈…₀
        // ⋯ (A₁⋅B₀+A₀⋅B₁)₂₈…₀ (A₁⋅B₀+A₀⋅B₁)₅₈…₂₉ (A₀⋅B₀)₅₇…₂₉ *
        OP_DEPTH OP_OVER OP_SUB OP_ROLL OP_SWAP OP_1SUB OP_TOALTSTACK
        // ⋯ (A₁⋅B₀+A₀⋅B₁)₂₈…₀ (A₁⋅B₀+A₀⋅B₁)₅₈…₂₉ (A₀⋅B₀)₅₇…₂₉ (A₁⋅B₁)₂₈…₀ | * (A⋅B)₀
        OP_2SWAP
        // ⋯ (A₀⋅B₀)₅₇…₂₉ (A₁⋅B₁)₂₈…₀ (A₁⋅B₀+A₀⋅B₁)₂₈…₀ (A₁⋅B₀+A₀⋅B₁)₅₈…₂₉
        { u29x2_add_u29u30_carry() }
        // (2²⁹⋅(A₁⋅B₁)₂₈…₀+(A₀⋅B₀)₅₇…₂₉)₅₇…₀ + (A₁⋅B₀+A₀⋅B₁)₅₈…₀  <=>  TEMP₁
        // ⋯ (A⋅B)₁ (TEMP₁)₂₈…₀ (TEMP₁)₅₉…₅₈
        OP_ROT OP_FROMALTSTACK OP_SWAP OP_TOALTSTACK
        // ⋯ (TEMP₁)₂₈…₀ (TEMP₁)₅₉…₅₈ * | (A⋅B)₁ (A⋅B)₀

        // (2²⁹⋅(A₁⋅B₁)₅₇…₂₉+(⋯)₅₈…₂₉)₅₈…₀ + (A₂⋅B₀+A₀⋅B₂)₅₈…₀
        // ⋯ (A₂⋅B₀+A₀⋅B₂)₂₈…₀ (A₂⋅B₀+A₀⋅B₂)₅₈…₂₉ (TEMP₁)₂₈…₀ (TEMP₁)₅₉…₅₈ *
        OP_TOALTSTACK
        // ⋯ (A₂⋅B₀+A₀⋅B₂)₂₈…₀ (A₂⋅B₀+A₀⋅B₂)₅₈…₂₉ (TEMP₁)₂₈…₀ (TEMP₁)₅₉…₅₈ | *
        OP_2SWAP
        // ⋯ (TEMP₁)₂₈…₀ (TEMP₁)₅₉…₅₈ (A₂⋅B₀+A₀⋅B₂)₂₈…₀ (A₂⋅B₀+A₀⋅B₂)₅₈…₂₉
        { u29x2_add_u29u30_carry() }
        // ⋯ (TEMP₁)₂₈…₀ (TEMP₁)₅₇…₂₉ (TEMP₁)₅₉…₅₈
        OP_ROT OP_FROMALTSTACK OP_SWAP OP_TOALTSTACK

        // ⋯ (TEMP₁)₅₇…₂₉ (TEMP₁)₅₉…₅₈ * | (TEMP₁)₂₈…₀
        OP_DEPTH OP_OVER OP_SUB OP_ROLL OP_SWAP OP_1SUB OP_TOALTSTACK
        // ⋯ (TEMP₁)₅₇…₂₉ (TEMP₁)₅₉…₅₈ (A₁⋅B₁)₅₇…₂₉ | *
        { u29x2_add_u29() }
        // ⋯ (TEMP₁+(A₁⋅B₁)₅₇…₂₉)₂₈…₀ (TEMP₁+(A₁⋅B₁)₅₇…₂₉)₃₁…₂₉

        // (2²⁹⋅(A₂⋅B₂)₂₈…₀+(⋯)₅₈…₂₉)₅₈…₀ + (A₃⋅B₀+A₀⋅B₃)₅₈…₀ + (A₂⋅B₁+A₁⋅B₂)₅₈…₀
        // ⋯ (A₃⋅B₀+A₀⋅B₃)₂₈…₀ (A₃⋅B₀+A₀⋅B₃)₅₈…₂₉ (TEMP₁+(A₁⋅B₁)₅₇…₂₉)₂₈…₀ (TEMP₁+(A₁⋅B₁)₅₇…₂₉)₃₁…₂₉
        OP_0 OP_TOALTSTACK
        // ⋯ (A₃⋅B₀+A₀⋅B₃)₂₈…₀ (A₃⋅B₀+A₀⋅B₃)₅₈…₂₉ (TEMP₁+(A₁⋅B₁)₅₇…₂₉)₂₈…₀ (TEMP₁+(A₁⋅B₁)₅₇…₂₉)₃₁…₂₉ | 0
        for _ in 5..7 {
            // ⋯ (A₃⋅B₀+A₀⋅B₃)₂₈…₀ (A₃⋅B₀+A₀⋅B₃)₅₈…₂₉ (TEMP₁+(A₁⋅B₁)₅₇…₂₉)₂₈…₀ (TEMP₁+(A₁⋅B₁)₅₇…₂₉)₃₁…₂₉
            OP_2SWAP
            // ⋯ (TEMP₁+(A₁⋅B₁)₅₇…₂₉)₂₈…₀ (TEMP₁+(A₁⋅B₁)₅₇…₂₉)₃₁…₂₉ (A₃⋅B₀+A₀⋅B₃)₂₈…₀ (A₃⋅B₀+A₀⋅B₃)₅₈…₂₉
            { u29x2_add_u29u30_carry() }
            // ⋯ (A⋅B)₂ (TEMP₂)₂₈…₀ (TEMP₂)₅₉…₅₈
            OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
            // ⋯ (A⋅B)₂ (TEMP₂)₂₈…₀ | (TEMP₂)₅₉…₅₈
        }
        OP_FROMALTSTACK
        // ⋯ (A⋅B)₂ (TEMP₂)₂₈…₀ (TEMP₂)₅₉…₅₈
        OP_ROT OP_FROMALTSTACK OP_SWAP OP_TOALTSTACK
        // ⋯ (TEMP₂)₂₈…₀ (TEMP₂)₅₉…₅₈ * | (A⋅B)₂ (A⋅B)₁ (A⋅B)₀
        OP_DEPTH OP_OVER OP_SUB OP_ROLL OP_SWAP OP_1SUB OP_TOALTSTACK
        // ⋯ (TEMP₂)₂₈…₀ (TEMP₂)₅₉…₅₈ (A₂⋅B₂)₂₈…₀ | *
        { u29x2_add_u29() }
        // ⋯ (TEMP₂+(A₂⋅B₂)₂₈…₀)₂₈…₀ (TEMP₂+(A₂⋅B₂)₂₈…₀)₅₉…₅₈ | *

        // (2²⁹⋅(A₂⋅B₂)₅₇…₂₉+(⋯)₅₈…₂₉)₅₈…₀ + (A₄⋅B₀+A₀⋅B₄)₅₈…₀ + (A₃⋅B₁+A₁⋅B₃)₅₈…₀
        OP_0 OP_TOALTSTACK
        for _ in 4..6 {
            OP_2SWAP
            { u29x2_add_u29u30_carry() }
            OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        }
        OP_FROMALTSTACK
        OP_ROT OP_FROMALTSTACK OP_SWAP OP_TOALTSTACK
        OP_DEPTH OP_OVER OP_SUB OP_ROLL OP_SWAP OP_1SUB OP_TOALTSTACK
        { u29x2_add_u29() }

        // (2²⁹⋅(A₃⋅B₃)₂₈…₀+(⋯)₅₈…₂₉)₅₈…₀ + (A₅⋅B₀+A₀⋅B₅)₅₈…₀ + (A₄⋅B₁+A₁⋅B₄)₅₈…₀ + (A₃⋅B₂+A₂⋅B₃)₅₈…₀
        OP_0 OP_TOALTSTACK
        for _ in 3..6 {
            OP_2SWAP
            { u29x2_add_u29u30_carry() }
            OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        }
        OP_FROMALTSTACK
        OP_ROT OP_FROMALTSTACK OP_SWAP OP_TOALTSTACK
        OP_DEPTH OP_OVER OP_SUB OP_ROLL OP_SWAP OP_1SUB OP_TOALTSTACK
        { u29x2_add_u29() }

        // (2²⁹⋅(A₃⋅B₃)₅₇…₂₉+(⋯)₅₈…₂₉)₅₈…₀ + (A₆⋅B₀+A₀⋅B₆)₅₈…₀ + (A₅⋅B₁+A₁⋅B₅)₅₈…₀ + (A₄⋅B₂+A₂⋅B₄)₅₈…₀
        OP_0 OP_TOALTSTACK
        for _ in 2..5 {
            OP_2SWAP
            { u29x2_add_u29u30_carry() }
            OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        }
        OP_FROMALTSTACK
        OP_ROT OP_FROMALTSTACK OP_SWAP OP_TOALTSTACK
        OP_DEPTH OP_OVER OP_SUB OP_ROLL OP_SWAP OP_1SUB OP_TOALTSTACK
        { u29x2_add_u29() }

        // (2²⁹⋅(A₄⋅B₄)₂₈…₀+(⋯)₅₈…₂₉)₅₈…₀ + (A₇⋅B₀+A₀⋅B₇)₅₈…₀ + (A₆⋅B₁+A₁⋅B₆)₅₈…₀ + (A₅⋅B₂+A₂⋅B₅)₅₈…₀ + (A₄⋅B₃+A₃⋅B₄)₅₈…₀
        OP_0 OP_TOALTSTACK
        for _ in 1..5 {
            OP_2SWAP
            { u29x2_add_u29u30_carry() }
            OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        }
        OP_FROMALTSTACK
        OP_ROT OP_FROMALTSTACK OP_SWAP OP_TOALTSTACK
        OP_DEPTH OP_OVER OP_SUB OP_ROLL OP_SWAP OP_1SUB OP_TOALTSTACK
        { u29x2_add_u29() }

        // (2²⁹⋅(A₄⋅B₄)₅₇…₂₉+(⋯)₅₈…₂₉)₅₈…₀ + (A₈⋅B₀+A₀⋅B₈)₅₈…₀ + (A₇⋅B₁+A₁⋅B₇)₅₈…₀ + (A₆⋅B₂+A₂⋅B₆)₅₈…₀ + (A₅⋅B₃+A₃⋅B₅)₅₈…₀
        OP_0 OP_TOALTSTACK
        for _ in 0..4 {
            OP_2SWAP
            { u29x2_add_u29u30_carry() }
            OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        }
        OP_FROMALTSTACK
        OP_ROT OP_FROMALTSTACK OP_SWAP OP_TOALTSTACK
        OP_DEPTH OP_OVER OP_SUB OP_ROLL OP_SWAP OP_1SUB OP_TOALTSTACK
        { u29x2_add_u29() }

        // (2²⁹⋅(A₅⋅B₅)₂₈…₀+(⋯)₅₈…₂₉)₅₈…₀ + (A₈⋅B₁+A₁⋅B₈)₅₈…₀ + (A₇⋅B₂+A₂⋅B₇)₅₈…₀ + (A₆⋅B₃+A₃⋅B₆)₅₈…₀ + (A₅⋅B₄+A₄⋅B₅)₅₈…₀
        OP_0 OP_TOALTSTACK
        for _ in 0..4 {
            OP_2SWAP
            { u29x2_add_u29u30_carry() }
            OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        }
        OP_FROMALTSTACK
        OP_ROT OP_FROMALTSTACK OP_SWAP OP_TOALTSTACK
        OP_DEPTH OP_OVER OP_SUB OP_ROLL OP_SWAP OP_1SUB OP_TOALTSTACK
        { u29x2_add_u29() }

        // (2²⁹⋅(A₅⋅B₅)₅₇…₂₉+(⋯)₅₈…₂₉)₅₈…₀ + (A₈⋅B₂+A₂⋅B₈)₅₈…₀ + (A₇⋅B₃+A₃⋅B₇)₅₈…₀ + (A₆⋅B₄+A₄⋅B₆)₅₈…₀
        OP_0 OP_TOALTSTACK
        for _ in 0..3 {
            OP_2SWAP
            { u29x2_add_u29u30_carry() }
            OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        }
        OP_FROMALTSTACK
        OP_ROT OP_FROMALTSTACK OP_SWAP OP_TOALTSTACK
        OP_DEPTH OP_OVER OP_SUB OP_ROLL OP_SWAP OP_1SUB OP_TOALTSTACK
        { u29x2_add_u29() }

        // (2²⁹⋅(A₆⋅B₆)₂₈…₀+(⋯)₅₈…₂₉)₅₈…₀ + (A₈⋅B₃+A₃⋅B₈)₅₈…₀ + (A₇⋅B₄+A₄⋅B₇)₅₈…₀ + (A₆⋅B₅+A₅⋅B₆)₅₈…₀
        OP_0 OP_TOALTSTACK
        for _ in 0..3 {
            OP_2SWAP
            { u29x2_add_u29u30_carry() }
            OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        }
        OP_FROMALTSTACK
        OP_ROT OP_FROMALTSTACK OP_SWAP OP_TOALTSTACK
        OP_DEPTH OP_OVER OP_SUB OP_ROLL OP_SWAP OP_1SUB OP_TOALTSTACK
        { u29x2_add_u29() }

        // (2²⁹⋅(A₆⋅B₆)₅₇…₂₉+(⋯)₅₈…₂₉)₅₈…₀ + (A₈⋅B₄+A₄⋅B₈)₅₈…₀ + (A₇⋅B₅+A₅⋅B₇)₅₈…₀
        OP_0 OP_TOALTSTACK
        for _ in 0..2 {
            OP_2SWAP
            { u29x2_add_u29u30_carry() }
            OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        }
        OP_FROMALTSTACK
        OP_ROT OP_FROMALTSTACK OP_SWAP OP_TOALTSTACK
        OP_DEPTH OP_OVER OP_SUB OP_ROLL OP_SWAP OP_1SUB OP_TOALTSTACK
        { u29x2_add_u29() }

        // (2²⁹⋅(A₇⋅B₇)₂₈…₀+(⋯)₅₈…₂₉)₅₈…₀ + (A₈⋅B₅+A₅⋅B₈)₅₈…₀ + (A₇⋅B₆+A₆⋅B₇)₅₈…₀
        OP_0 OP_TOALTSTACK
        for _ in 0..2 {
            OP_2SWAP
            { u29x2_add_u29u30_carry() }
            OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        }
        OP_FROMALTSTACK
        OP_ROT OP_FROMALTSTACK OP_SWAP OP_TOALTSTACK
        OP_DEPTH OP_OVER OP_SUB OP_ROLL OP_SWAP OP_1SUB OP_TOALTSTACK
        { u29x2_add_u29() }

        // (2²⁹⋅(A₇⋅B₇)₅₇…₂₉+(⋯)₅₈…₂₉)₅₈…₀ + (A₈⋅B₆+A₆⋅B₈)₅₈…₀
        OP_2SWAP
        { u29x2_add_u29u30_carry() }
        OP_ROT OP_FROMALTSTACK OP_SWAP OP_TOALTSTACK
        OP_DEPTH OP_OVER OP_SUB OP_ROLL OP_SWAP OP_1SUB OP_TOALTSTACK
        { u29x2_add_u29() }

        // (2²⁹⋅(A₈⋅B₈)₂₈…₀+(⋯)₅₈…₂₉)₅₈…₀ + (A₈⋅B₇+A₇⋅B₈)₅₈…₀
        OP_2SWAP
        { u29x2_add_u29u30_carry() }
        OP_ROT OP_FROMALTSTACK OP_SWAP OP_TOALTSTACK
        OP_DEPTH OP_OVER OP_SUB OP_ROLL OP_SWAP OP_1SUB OP_TOALTSTACK
        { u29x2_add_u29() }

        // (2²⁹⋅(A₈⋅B₈)₅₇…₂₉+(⋯)₅₈…₂₉)₅₈…₀
        OP_SWAP OP_FROMALTSTACK OP_SWAP OP_TOALTSTACK OP_TOALTSTACK OP_FROMALTSTACK
        OP_DEPTH OP_OVER OP_SUB OP_ROLL OP_SWAP OP_DROP

        // (⋯)₅₈…₂₉
        OP_ADD OP_TOALTSTACK
        for _ in 0..9 {
            OP_FROMALTSTACK
            OP_FROMALTSTACK
        }

    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::treepp::*;

    #[test]
    fn test_u29_bits_to_altstack() {
        println!(
            "u29_bits_to_altstack: {} bytes",
            u29_bits_to_altstack().len()
        );
        let script = script! {
            { 0x187cfd47 } // Fq
            { u29_bits_to_altstack() }
                            OP_1 OP_EQUALVERIFY
            OP_FROMALTSTACK OP_1 OP_EQUALVERIFY
            OP_FROMALTSTACK OP_1 OP_EQUALVERIFY
            OP_FROMALTSTACK OP_0 OP_EQUALVERIFY
            OP_FROMALTSTACK OP_0 OP_EQUALVERIFY
            OP_FROMALTSTACK OP_0 OP_EQUALVERIFY
            OP_FROMALTSTACK OP_1 OP_EQUALVERIFY
            OP_FROMALTSTACK OP_0 OP_EQUALVERIFY
            OP_FROMALTSTACK OP_1 OP_EQUALVERIFY
            OP_FROMALTSTACK OP_0 OP_EQUALVERIFY
            OP_FROMALTSTACK OP_1 OP_EQUALVERIFY
            OP_FROMALTSTACK OP_1 OP_EQUALVERIFY
            OP_FROMALTSTACK OP_1 OP_EQUALVERIFY
            OP_FROMALTSTACK OP_1 OP_EQUALVERIFY
            OP_FROMALTSTACK OP_1 OP_EQUALVERIFY
            OP_FROMALTSTACK OP_1 OP_EQUALVERIFY
            OP_FROMALTSTACK OP_0 OP_EQUALVERIFY
            OP_FROMALTSTACK OP_0 OP_EQUALVERIFY
            OP_FROMALTSTACK OP_1 OP_EQUALVERIFY
            OP_FROMALTSTACK OP_1 OP_EQUALVERIFY
            OP_FROMALTSTACK OP_1 OP_EQUALVERIFY
            OP_FROMALTSTACK OP_1 OP_EQUALVERIFY
            OP_FROMALTSTACK OP_1 OP_EQUALVERIFY
            OP_FROMALTSTACK OP_0 OP_EQUALVERIFY
            OP_FROMALTSTACK OP_0 OP_EQUALVERIFY
            OP_FROMALTSTACK OP_0 OP_EQUALVERIFY
            OP_FROMALTSTACK OP_0 OP_EQUALVERIFY
            OP_FROMALTSTACK OP_1 OP_EQUALVERIFY
            OP_FROMALTSTACK OP_1 OP_EQUAL
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_u29_mul_carry_29() {
        println!("u29_mul_carry: {} bytes", u29_mul_carry_29().len());
        let script = script! {
            { 0x187cfd47 } // Fq₀
            { 0x10000001 } // Fr₀
            { u29_mul_carry_29() }
            { 0xC3E7EA4 } OP_EQUALVERIFY
            { 0x87CFD47 } OP_EQUALVERIFY

            { 0x10460b6 } // Fq₁
            { 0x1f0fac9f } // Fr₁
            { u29_mul_carry_29() }
            { 0xFCBD3A } OP_EQUALVERIFY
            { 0x75C590A } OP_EQUALVERIFY

            { 0x1c72a34f } // Fq₂
            { 0xe5c2450 } // Fr₂
            { u29_mul_carry_29() }
            { 0xCC41150 } OP_EQUALVERIFY
            { 0x52E24B0 } OP_EQUALVERIFY

            { 0x2d522d0 } // Fq₃
            { 0x7d090f3 } // Fr₃
            { u29_mul_carry_29() }
            { 0xB115D4 } OP_EQUALVERIFY
            { 0xCE50B70 } OP_EQUALVERIFY

            { 0x1585d978 } // Fq₄
            { 0x1585d283 } // Fr₄
            { u29_mul_carry_29() }
            { 0xE79D89D } OP_EQUALVERIFY
            { 0x33AB868 } OP_EQUALVERIFY

            { 0x2db40c0 } // Fq₅
            { 0x2db40c0 } // Fr₅
            { u29_mul_carry_29() }
            { 0x414656 } OP_EQUALVERIFY
            { 0x18E09000 } OP_EQUALVERIFY

            { 0xa6e141 } // Fq₆
            { 0xa6e141 } // Fr₆
            { u29_mul_carry_29() }
            { 0x36647 } OP_EQUALVERIFY
            { 0x67F5281 } OP_EQUALVERIFY

            { 0xe5c2634 } // Fq₇
            { 0xe5c2634 } // Fr₇
            { u29_mul_carry_29() }
            { 0x671AAC9 } OP_EQUALVERIFY
            { 0xB137A90 } OP_EQUALVERIFY

            { 0x30644e } // Fq₈
            { 0x30644e } // Fr₈
            { u29_mul_carry_29() }
            { 0x492E } OP_EQUALVERIFY
            { 0x48D07C4 } OP_EQUALVERIFY

            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_u30_mul_to_u29_carry_31() {
        println!(
            "u30_mul_to_u29_carry_31: {} bytes",
            u30_mul_to_u29_carry_31().len()
        );
        let script = script! {
            // Multiply (Fq₂₈…₀ + Fq₅₇…₂₉) ⋅ (Fr₂₈…₀ + Fr₅₇…₂₉)
            { 0x10460b6 } // Fq₅₇…₂₉
            { 0x187cfd47 } // Fq₂₈…₀
            OP_ADD
            { 0x1f0fac9f } // Fr₅₇…₂₉
            { 0x10000001 } // Fr₂₈…₀
            OP_ADD
            { u30_mul_to_u29_carry_31() }
            { 0x25828046 } OP_EQUALVERIFY
            { 0x10D3BA20 } OP_EQUALVERIFY

            // Multiply (2³⁰-2¹) ⋅ (2³⁰-2¹)
            { 0x1FFFFFFF }
            // 2⁰⋅(2²⁹-1)
            OP_DUP OP_ADD
            // 2¹⋅(2²⁹-1)
            OP_DUP
            // 2¹⋅(2²⁹-1) 2¹⋅(2²⁹-1)
            { u30_mul_to_u29_carry_31() }
            { 0x7FFFFFF8 } OP_EQUALVERIFY
            { 0x4 } OP_EQUALVERIFY

            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_u29x2_sub_noborrow() {
        println!("u29x2_sub_noborrow: {} bytes", u29x2_sub_noborrow().len());
        let script = script! {
            OP_1 OP_14
            OP_16 OP_1
            { u29x2_sub_noborrow() }
            OP_12 OP_EQUALVERIFY
            { 0x1FFFFFF1 } OP_EQUALVERIFY
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_u29x2_add_u29() {
        println!("u29x2_add_u29: {} bytes", u29x2_add_u29().len());
        let script = script! {
            { 0x1FFFFFFF } { 0x1FFFFFFE }
            { 0x1FFFFFFF }
            { u29x2_add_u29() }
            { 0x1FFFFFFF } OP_EQUALVERIFY
            { 0x1FFFFFFE } OP_EQUALVERIFY
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_u29x3_add_u29x2_nocarry() {
        println!(
            "u29x3_add_u29x2_nocarry: {} bytes",
            u29x3_add_u29x2_nocarry().len()
        );
        let script = script! {
            { 0x1FFFFFFF } { 0x1FFFFFFF } { 0x1FFFFFFE }
            { 0x1FFFFFFF } { 0x1FFFFFFF }
            { u29x3_add_u29x2_nocarry() }
            { 0x1FFFFFFF } OP_EQUALVERIFY
            { 0x1FFFFFFF } OP_EQUALVERIFY
            { 0x1FFFFFFE } OP_EQUALVERIFY
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_u29x2_add_u29u30_carry() {
        println!(
            "u29x2_add_u29u30_carry: {} bytes",
            u29x2_add_u29u30_carry().len()
        );
        let script = script! {
            { 0x1FFFFFFF } { 0x1FFFFFFF }
            { 0x1FFFFFFF } { 0x3FFFFFFF }
            { u29x2_add_u29u30_carry() }
            OP_2 OP_EQUALVERIFY
            { 0x1FFFFFFF } OP_EQUALVERIFY
            { 0x1FFFFFFE } OP_EQUALVERIFY
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_u29x9_mul_karazuba() {
        println!(
            "u29x9_mul_karazuba: {} bytes",
            u29x9_mul_karazuba(1, 0).len()
        );
        let script = script! {
            { 0xFFFFFF } { 0x1FFFFFFF } { 0x1FFFFFFF } { 0x1FFFFFFF } { 0x1FFFFFFF } { 0x1FFFFFFF } { 0x1FFFFFFF } { 0x1FFFFFFF } { 0x1FFFFFFF }
            { 0xFFFFFF } { 0x1FFFFFFF } { 0x1FFFFFFF } { 0x1FFFFFFF } { 0x1FFFFFFF } { 0x1FFFFFFF } { 0x1FFFFFFF } { 0x1FFFFFFF } { 0x1FFFFFFF }
            { u29x9_mul_karazuba(1, 0) }
            { 0x00000001 } OP_EQUALVERIFY
            { 0x00000000 } OP_EQUALVERIFY
            { 0x00000000 } OP_EQUALVERIFY
            { 0x00000000 } OP_EQUALVERIFY
            { 0x00000000 } OP_EQUALVERIFY
            { 0x00000000 } OP_EQUALVERIFY
            { 0x00000000 } OP_EQUALVERIFY
            { 0x00000000 } OP_EQUALVERIFY
            { 0x1E000000 } OP_EQUALVERIFY
            { 0x1FFFFFFF } OP_EQUALVERIFY
            { 0x1FFFFFFF } OP_EQUALVERIFY
            { 0x1FFFFFFF } OP_EQUALVERIFY
            { 0x1FFFFFFF } OP_EQUALVERIFY
            { 0x1FFFFFFF } OP_EQUALVERIFY
            { 0x1FFFFFFF } OP_EQUALVERIFY
            { 0x1FFFFFFF } OP_EQUALVERIFY
            { 0x1FFFFFFF } OP_EQUALVERIFY
            { 0x0007FFFF } OP_EQUALVERIFY
            { 0x30644e } { 0xe5c2634 } { 0xa6e141 } { 0x2db40c0 } { 0x1585d978 } { 0x2d522d0 } { 0x1c72a34f } { 0x10460b6 } { 0x187cfd47 } // Fq₈…₀
            { 0x30644e } { 0xe5c2634 } { 0xa6e141 } { 0x2db40c0 } { 0x1585d283 } { 0x7d090f3 } { 0xe5c2450 } { 0x1f0fac9f } { 0x10000001 } // Fr₈…₀
            { u29x9_mul_karazuba(1, 0) }
            { 0x87cfd47 } OP_EQUALVERIFY
            { 0xd38e273 } OP_EQUALVERIFY
            { 0xe4762f1 } OP_EQUALVERIFY
            { 0x1cc210fa } OP_EQUALVERIFY
            { 0x22abd0d } OP_EQUALVERIFY
            { 0x142be5a2 } OP_EQUALVERIFY
            { 0xa08b5c } OP_EQUALVERIFY
            { 0x19881028 } OP_EQUALVERIFY
            { 0x1a3d6934 } OP_EQUALVERIFY
            { 0x1df1f38d } OP_EQUALVERIFY
            { 0xa6ca99a } OP_EQUALVERIFY
            { 0x9b129e5 } OP_EQUALVERIFY
            { 0x1016080f } OP_EQUALVERIFY
            { 0x4690e4d } OP_EQUALVERIFY
            { 0x9bdf00d } OP_EQUALVERIFY
            { 0x17f38b33 } OP_EQUALVERIFY
            { 0x4b8763c } OP_EQUALVERIFY
            { 0x492e } OP_EQUALVERIFY
            OP_TRUE
        };

        let exec_result = execute_script(script);
        if exec_result.success == false {
            println!("ERROR: {:?} <---", exec_result.last_opcode)
        }
        assert!(exec_result.success);
    }
}
