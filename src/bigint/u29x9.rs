
use crate::bigint::U254;
use crate::treepp::*;

const USE_STRICT: bool = false;

// assert 0 ≤ a ≤ max
// a
fn assert_nn_le(max: u32) -> Script {
    script! {
        if USE_STRICT {
            if max < 0x7FFFFFFF {
                // a
                OP_DUP
                // a a
                OP_0 { max + 1 }
                // a a 0 2³⁰
                OP_WITHIN
                // a 0≤a≤max
                OP_VERIFY
                // a
            } else {
                // a
                OP_DUP
                // a a
                OP_0
                // a a 0
                OP_GREATERTHANOREQUAL
                // a 0≤a
                OP_VERIFY
                // a
            }
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

        // (A₂₉…₀ ⋅ B₂₉…₀)₂₈…₀ (A₂₉…₀ ⋅ B₂₉…₀)₅₉…₂₉

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
        OP_2 OP_PICK OP_1 OP_PICK OP_ADD OP_TOALTSTACK
        OP_3 OP_PICK OP_2 OP_PICK OP_ADD OP_TOALTSTACK
        // A₂₊₀ B₂₊₀
        OP_4 OP_PICK OP_1 OP_PICK OP_ADD OP_TOALTSTACK
        OP_5 OP_PICK OP_2 OP_PICK OP_ADD OP_TOALTSTACK
        // A₃₊₀ B₃₊₀
        OP_6 OP_PICK OP_1 OP_PICK OP_ADD OP_TOALTSTACK
        OP_7 OP_PICK OP_2 OP_PICK OP_ADD OP_TOALTSTACK
        // A₂₊₁ B₂₊₁
        OP_4 OP_PICK OP_3 OP_PICK OP_ADD OP_TOALTSTACK
        OP_5 OP_PICK OP_4 OP_PICK OP_ADD OP_TOALTSTACK
        // A₄₊₀ B₄₊₀
        OP_8 OP_PICK OP_1 OP_PICK OP_ADD OP_TOALTSTACK
        OP_9 OP_PICK OP_2 OP_PICK OP_ADD OP_TOALTSTACK
        // A₃₊₁ B₃₊₁
        OP_6 OP_PICK OP_3 OP_PICK OP_ADD OP_TOALTSTACK
        OP_7 OP_PICK OP_4 OP_PICK OP_ADD OP_TOALTSTACK
        // A₅₊₀ B₅₊₀
        OP_10 OP_PICK OP_1 OP_PICK OP_ADD OP_TOALTSTACK
        OP_11 OP_PICK OP_2 OP_PICK OP_ADD OP_TOALTSTACK
        // A₄₊₁ B₄₊₁
        OP_8 OP_PICK OP_3 OP_PICK OP_ADD OP_TOALTSTACK
        OP_9 OP_PICK OP_4 OP_PICK OP_ADD OP_TOALTSTACK
        // A₃₊₂ B₃₊₂
        OP_6 OP_PICK OP_5 OP_PICK OP_ADD OP_TOALTSTACK
        OP_7 OP_PICK OP_6 OP_PICK OP_ADD OP_TOALTSTACK
        // A₆₊₀ B₆₊₀
        OP_12 OP_PICK OP_1 OP_PICK OP_ADD OP_TOALTSTACK
        OP_13 OP_PICK OP_2 OP_PICK OP_ADD OP_TOALTSTACK
        // A₅₊₁ B₅₊₁
        OP_10 OP_PICK OP_3 OP_PICK OP_ADD OP_TOALTSTACK
        OP_11 OP_PICK OP_4 OP_PICK OP_ADD OP_TOALTSTACK
        // A₄₊₂ B₄₊₂
        OP_8 OP_PICK OP_5 OP_PICK OP_ADD OP_TOALTSTACK
        OP_9 OP_PICK OP_6 OP_PICK OP_ADD OP_TOALTSTACK
        // A₇₊₀ B₇₊₀
        OP_14 OP_PICK OP_1 OP_PICK OP_ADD OP_TOALTSTACK
        OP_15 OP_PICK OP_2 OP_PICK OP_ADD OP_TOALTSTACK
        // A₆₊₁ B₆₊₁
        OP_12 OP_PICK OP_3 OP_PICK OP_ADD OP_TOALTSTACK
        OP_13 OP_PICK OP_4 OP_PICK OP_ADD OP_TOALTSTACK
        // A₅₊₂ B₅₊₂
        OP_10 OP_PICK OP_5 OP_PICK OP_ADD OP_TOALTSTACK
        OP_11 OP_PICK OP_6 OP_PICK OP_ADD OP_TOALTSTACK
        // A₄₊₃ B₄₊₃
        OP_8 OP_PICK OP_7 OP_PICK OP_ADD OP_TOALTSTACK
        OP_9 OP_PICK OP_8 OP_PICK OP_ADD OP_TOALTSTACK
        // A₈₊₀ B₈₊₀
        OP_16 OP_PICK OP_1 OP_PICK OP_ADD OP_TOALTSTACK
        { 17 } OP_PICK OP_2 OP_PICK OP_ADD OP_TOALTSTACK
        // A₇₊₁ B₇₊₁
        OP_14 OP_PICK OP_3 OP_PICK OP_ADD OP_TOALTSTACK
        OP_15 OP_PICK OP_4 OP_PICK OP_ADD OP_TOALTSTACK
        // A₆₊₂ B₆₊₂
        OP_12 OP_PICK OP_5 OP_PICK OP_ADD OP_TOALTSTACK
        OP_13 OP_PICK OP_6 OP_PICK OP_ADD OP_TOALTSTACK
        // A₅₊₃ B₅₊₃
        OP_10 OP_PICK OP_7 OP_PICK OP_ADD OP_TOALTSTACK
        OP_11 OP_PICK OP_8 OP_PICK OP_ADD OP_TOALTSTACK
        // A₈₊₁ B₈₊₁
        OP_16 OP_PICK OP_3 OP_PICK OP_ADD OP_TOALTSTACK
        { 17 } OP_PICK OP_4 OP_PICK OP_ADD OP_TOALTSTACK
        // A₇₊₂ B₇₊₂
        OP_14 OP_PICK OP_5 OP_PICK OP_ADD OP_TOALTSTACK
        OP_15 OP_PICK OP_6 OP_PICK OP_ADD OP_TOALTSTACK
        // A₆₊₃ B₆₊₃
        OP_12 OP_PICK OP_7 OP_PICK OP_ADD OP_TOALTSTACK
        OP_13 OP_PICK OP_8 OP_PICK OP_ADD OP_TOALTSTACK
        // A₅₊₄ B₅₊₄
        OP_10 OP_PICK OP_9 OP_PICK OP_ADD OP_TOALTSTACK
        OP_11 OP_PICK OP_10 OP_PICK OP_ADD OP_TOALTSTACK
        // A₈₊₂ B₈₊₂
        OP_16 OP_PICK OP_5 OP_PICK OP_ADD OP_TOALTSTACK
        { 17 } OP_PICK OP_6 OP_PICK OP_ADD OP_TOALTSTACK
        // A₇₊₃ B₇₊₃
        OP_14 OP_PICK OP_7 OP_PICK OP_ADD OP_TOALTSTACK
        OP_15 OP_PICK OP_8 OP_PICK OP_ADD OP_TOALTSTACK
        // A₆₊₄ B₆₊₄
        OP_12 OP_PICK OP_9 OP_PICK OP_ADD OP_TOALTSTACK
        OP_13 OP_PICK OP_10 OP_PICK OP_ADD OP_TOALTSTACK
        // A₈₊₃ B₈₊₃
        OP_16 OP_PICK OP_7 OP_PICK OP_ADD OP_TOALTSTACK
        { 17 } OP_PICK OP_8 OP_PICK OP_ADD OP_TOALTSTACK
        // A₇₊₄ B₇₊₄
        OP_14 OP_PICK OP_9 OP_PICK OP_ADD OP_TOALTSTACK
        OP_15 OP_PICK OP_10 OP_PICK OP_ADD OP_TOALTSTACK
        // A₆₊₅ B₆₊₅
        OP_12 OP_PICK OP_11 OP_PICK OP_ADD OP_TOALTSTACK
        OP_13 OP_PICK OP_12 OP_PICK OP_ADD OP_TOALTSTACK
        // A₇₊₅ B₇₊₅
        OP_16 OP_PICK OP_9 OP_PICK OP_ADD OP_TOALTSTACK
        { 17 } OP_PICK OP_10 OP_PICK OP_ADD OP_TOALTSTACK
        // A₈₊₄ B₈₊₄
        OP_14 OP_PICK OP_11 OP_PICK OP_ADD OP_TOALTSTACK
        OP_15 OP_PICK OP_12 OP_PICK OP_ADD OP_TOALTSTACK
        // A₈₊₅ B₈₊₅
        OP_16 OP_PICK OP_11 OP_PICK OP_ADD OP_TOALTSTACK
        { 17 } OP_PICK OP_12 OP_PICK OP_ADD OP_TOALTSTACK
        // A₇₊₆ B₇₊₆
        OP_14 OP_PICK OP_13 OP_PICK OP_ADD OP_TOALTSTACK
        OP_15 OP_PICK OP_14 OP_PICK OP_ADD OP_TOALTSTACK
        // A₈₊₆ B₈₊₆
        OP_16 OP_PICK OP_13 OP_PICK OP_ADD OP_TOALTSTACK
        { 17 } OP_PICK OP_14 OP_PICK OP_ADD OP_TOALTSTACK
        // A₈₊₇ B₈₊₇
        OP_16 OP_PICK OP_15 OP_PICK OP_ADD OP_TOALTSTACK
        { 17 } OP_PICK OP_16 OP_PICK OP_ADD OP_TOALTSTACK

        for _ in 0..9 {
            { 17 } OP_ROLL
            { 17 } OP_ROLL
            u29_mul_carry_29
            OP_SWAP
        }

        // A₈₊₇⋅B₈₊₇ - A₈⋅B₈ - A₇⋅B₇  <=>  A₈⋅B₇ + A₇⋅B₈
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 18 } OP_PICK { 20 } OP_PICK u29x2_sub_noborrow
        { 16 } OP_PICK { 18 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₈⋅B₇+A₇⋅B₈)₂₈…₀ (A₈⋅B₇+A₇⋅B₈)₅₈…₂₉
        // A₈₊₆⋅B₈₊₆ - A₈⋅B₈ - A₆⋅B₆  <=>  A₈⋅B₆ + A₆⋅B₈
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 20 } OP_PICK { 22 } OP_PICK u29x2_sub_noborrow
        { 16 } OP_PICK { 18 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₈⋅B₆+A₆⋅B₈)₂₈…₀ (A₈⋅B₆+A₆⋅B₈)₅₈…₂₉
        // A₇₊₆⋅B₇₊₆ - A₇⋅B₇ - A₆⋅B₆  <=>  A₇⋅B₆ + A₆⋅B₇
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 20 } OP_PICK { 22 } OP_PICK u29x2_sub_noborrow
        { 18 } OP_PICK { 20 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₇⋅B₆+A₆⋅B₇)₂₈…₀ (A₇⋅B₆+A₆⋅B₇)₅₈…₂₉
        // A₈₊₅⋅B₈₊₅ - A₈⋅B₈ - A₅⋅B₅  <=>  A₈⋅B₅ + A₅⋅B₈
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 24 } OP_PICK { 26 } OP_PICK u29x2_sub_noborrow
        { 18 } OP_PICK { 20 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₈⋅B₅+A₅⋅B₈)₂₈…₀ (A₈⋅B₅+A₅⋅B₈)₅₈…₂₉
        // A₇₊₅⋅B₇₊₅ - A₇⋅B₇ - A₅⋅B₅  <=>  A₇⋅B₅ + A₅⋅B₇
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 24 } OP_PICK { 26 } OP_PICK u29x2_sub_noborrow
        { 20 } OP_PICK { 22 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₇⋅B₅+A₅⋅B₇)₂₈…₀ (A₇⋅B₅+A₅⋅B₇)₅₈…₂₉
        // A₈₊₄⋅B₈₊₄ - A₈⋅B₈ - A₄⋅B₄  <=>  A₈⋅B₄ + A₄⋅B₈
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 28 } OP_PICK { 30 } OP_PICK u29x2_sub_noborrow
        { 20 } OP_PICK { 22 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₈⋅B₄+A₄⋅B₈)₂₈…₀ (A₈⋅B₄+A₄⋅B₈)₅₈…₂₉
        // A₆₊₅⋅B₆₊₅ - A₆⋅B₆ - A₅⋅B₅  <=>  A₆⋅B₅ + A₅⋅B₆
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 26 } OP_PICK { 28 } OP_PICK u29x2_sub_noborrow
        { 24 } OP_PICK { 26 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₆⋅B₅+A₅⋅B₆)₂₈…₀ (A₆⋅B₅+A₅⋅B₆)₅₈…₂₉
        // A₇₊₄⋅B₇₊₄ - A₇⋅B₇ - A₄⋅B₄  <=>  A₇⋅B₄ + A₄⋅B₇
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 30 } OP_PICK { 32 } OP_PICK u29x2_sub_noborrow
        { 24 } OP_PICK { 26 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₇⋅B₄+A₄⋅B₇)₂₈…₀ (A₇⋅B₄+A₄⋅B₇)₅₈…₂₉
        // A₈₊₃⋅B₈₊₃ - A₈⋅B₈ - A₃⋅B₃  <=>  A₈⋅B₃ + A₃⋅B₈
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 34 } OP_PICK { 36 } OP_PICK u29x2_sub_noborrow
        { 24 } OP_PICK { 26 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₈⋅B₃+A₃⋅B₈)₂₈…₀ (A₈⋅B₃+A₃⋅B₈)₅₈…₂₉
        // A₆₊₄⋅B₆₊₄ - A₆⋅B₆ - A₄⋅B₄  <=>  A₆⋅B₄ + A₄⋅B₆
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 32 } OP_PICK { 34 } OP_PICK u29x2_sub_noborrow
        { 28 } OP_PICK { 30 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₆⋅B₄+A₄⋅B₆)₂₈…₀ (A₆⋅B₄+A₄⋅B₆)₅₈…₂₉
        // A₇₊₃⋅B₇₊₃ - A₇⋅B₇ - A₃⋅B₃  <=>  A₇⋅B₃ + A₃⋅B₇
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 36 } OP_PICK { 38 } OP_PICK u29x2_sub_noborrow
        { 28 } OP_PICK { 30 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₇⋅B₃+A₃⋅B₇)₂₈…₀ (A₇⋅B₃+A₃⋅B₇)₅₈…₂₉
        // A₈₊₂⋅B₈₊₂ - A₈⋅B₈ - A₂⋅B₂  <=>  A₈⋅B₂ + A₂⋅B₈
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 40 } OP_PICK { 42 } OP_PICK u29x2_sub_noborrow
        { 28 } OP_PICK { 30 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₈⋅B₂+A₂⋅B₈)₂₈…₀ (A₈⋅B₂+A₂⋅B₈)₅₈…₂₉
        // A₅₊₄⋅B₅₊₄ - A₅⋅B₅ - A₄⋅B₄  <=>  A₅⋅B₄ + A₄⋅B₅
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 36 } OP_PICK { 38 } OP_PICK u29x2_sub_noborrow
        { 34 } OP_PICK { 36 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₅⋅B₄+A₄⋅B₅)₂₈…₀ (A₅⋅B₄+A₄⋅B₅)₅₈…₂₉
        // A₆₊₃⋅B₆₊₃ - A₆⋅B₆ - A₃⋅B₃  <=>  A₆⋅B₃ + A₃⋅B₆
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 40 } OP_PICK { 42 } OP_PICK u29x2_sub_noborrow
        { 34 } OP_PICK { 36 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₆⋅B₃+A₃⋅B₆)₂₈…₀ (A₆⋅B₃+A₃⋅B₆)₅₈…₂₉
        // A₇₊₂⋅B₇₊₂ - A₇⋅B₇ - A₂⋅B₂  <=>  A₇⋅B₂ + A₂⋅B₇
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 44 } OP_PICK { 46 } OP_PICK u29x2_sub_noborrow
        { 34 } OP_PICK { 36 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₇⋅B₂+A₂⋅B₇)₂₈…₀ (A₇⋅B₂+A₂⋅B₇)₅₈…₂₉
        // A₈₊₁⋅B₈₊₁ - A₈⋅B₈ - A₁⋅B₁  <=>  A₈⋅B₁ + A₁⋅B₈
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 48 } OP_PICK { 50 } OP_PICK u29x2_sub_noborrow
        { 34 } OP_PICK { 36 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₈⋅B₁+A₁⋅B₈)₂₈…₀ (A₈⋅B₁+A₁⋅B₈)₅₈…₂₉
        // A₅₊₃⋅B₅₊₃ - A₅⋅B₅ - A₃⋅B₃  <=>  A₅⋅B₃ + A₃⋅B₅
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 44 } OP_PICK { 46 } OP_PICK u29x2_sub_noborrow
        { 40 } OP_PICK { 42 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₅⋅B₃+A₃⋅B₅)₂₈…₀ (A₅⋅B₃+A₃⋅B₅)₅₈…₂₉
        // A₆₊₂⋅B₆₊₂ - A₆⋅B₆ - A₂⋅B₂  <=>  A₆⋅B₂ + A₂⋅B₆
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 48 } OP_PICK { 50 } OP_PICK u29x2_sub_noborrow
        { 40 } OP_PICK { 42 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₆⋅B₂+A₂⋅B₆)₂₈…₀ (A₆⋅B₂+A₂⋅B₆)₅₈…₂₉
        // A₇₊₁⋅B₇₊₁ - A₇⋅B₇ - A₁⋅B₁  <=>  A₇⋅B₁ + A₁⋅B₇
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 52 } OP_PICK { 54 } OP_PICK u29x2_sub_noborrow
        { 40 } OP_PICK { 42 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₇⋅B₁+A₁⋅B₇)₂₈…₀ (A₇⋅B₁+A₁⋅B₇)₅₈…₂₉
        // A₈₊₀⋅B₈₊₀ - A₈⋅B₈ - A₀⋅B₀  <=>  A₈⋅B₀ + A₀⋅B₈
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 56 } OP_PICK { 58 } OP_PICK u29x2_sub_noborrow
        { 40 } OP_PICK { 42 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₈⋅B₀+A₀⋅B₈)₂₈…₀ (A₈⋅B₀+A₀⋅B₈)₅₈…₂₉
        // A₄₊₃⋅B₄₊₃ - A₄⋅B₄ - A₃⋅B₃  <=>  A₄⋅B₃ + A₃⋅B₄
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 50 } OP_PICK { 52 } OP_PICK u29x2_sub_noborrow
        { 48 } OP_PICK { 50 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₄⋅B₃+A₃⋅B₄)₂₈…₀ (A₄⋅B₃+A₃⋅B₄)₅₈…₂₉
        // A₅₊₂⋅B₅₊₂ - A₅⋅B₅ - A₂⋅B₂  <=>  A₅⋅B₂ + A₂⋅B₅
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 54 } OP_PICK { 56 } OP_PICK u29x2_sub_noborrow
        { 48 } OP_PICK { 50 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₅⋅B₂+A₂⋅B₅)₂₈…₀ (A₅⋅B₂+A₂⋅B₅)₅₈…₂₉
        // A₆₊₁⋅B₆₊₁ - A₆⋅B₆ - A₁⋅B₁  <=>  A₆⋅B₁ + A₁⋅B₆
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 58 } OP_PICK { 60 } OP_PICK u29x2_sub_noborrow
        { 48 } OP_PICK { 50 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₆⋅B₁+A₁⋅B₆)₂₈…₀ (A₆⋅B₁+A₁⋅B₆)₅₈…₂₉
        // A₇₊₀⋅B₇₊₀ - A₇⋅B₇ - A₀⋅B₀  <=>  A₇⋅B₀ + A₀⋅B₇
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 62 } OP_PICK { 64 } OP_PICK u29x2_sub_noborrow
        { 48 } OP_PICK { 50 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₇⋅B₀+A₀⋅B₇)₂₈…₀ (A₇⋅B₀+A₀⋅B₇)₅₈…₂₉
        // A₄₊₂⋅B₄₊₂ - A₄⋅B₄ - A₂⋅B₂  <=>  A₄⋅B₂ + A₂⋅B₄
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 58 } OP_PICK { 60 } OP_PICK u29x2_sub_noborrow
        { 54 } OP_PICK { 56 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₄⋅B₂+A₂⋅B₄)₂₈…₀ (A₄⋅B₂+A₂⋅B₄)₅₈…₂₉
        // A₅₊₁⋅B₅₊₁ - A₅⋅B₅ - A₁⋅B₁  <=>  A₅⋅B₁ + A₁⋅B₅
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 62 } OP_PICK { 64 } OP_PICK u29x2_sub_noborrow
        { 54 } OP_PICK { 56 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₅⋅B₁+A₁⋅B₅)₂₈…₀ (A₅⋅B₁+A₁⋅B₅)₅₈…₂₉
        // A₆₊₀⋅B₆₊₀ - A₆⋅B₆ - A₀⋅B₀  <=>  A₆⋅B₀ + A₀⋅B₆
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 66 } OP_PICK { 68 } OP_PICK u29x2_sub_noborrow
        { 54 } OP_PICK { 56 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₆⋅B₀+A₀⋅B₆)₂₈…₀ (A₆⋅B₀+A₀⋅B₆)₅₈…₂₉
        // A₃₊₂⋅B₃₊₂ - A₃⋅B₃ - A₂⋅B₂  <=>  A₃⋅B₂ + A₂⋅B₃
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 62 } OP_PICK { 64 } OP_PICK u29x2_sub_noborrow
        { 60 } OP_PICK { 62 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₃⋅B₂+A₂⋅B₃)₂₈…₀ (A₃⋅B₂+A₂⋅B₃)₅₈…₂₉
        // A₄₊₁⋅B₄₊₁ - A₄⋅B₄ - A₁⋅B₁  <=>  A₄⋅B₁ + A₁⋅B₄
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 66 } OP_PICK { 68 } OP_PICK u29x2_sub_noborrow
        { 60 } OP_PICK { 62 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₄⋅B₁+A₁⋅B₄)₂₈…₀ (A₄⋅B₁+A₁⋅B₄)₅₈…₂₉
        // A₅₊₀⋅B₅₊₀ - A₅⋅B₅ - A₀⋅B₀  <=>  A₅⋅B₀ + A₀⋅B₅
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 70 } OP_PICK { 72 } OP_PICK u29x2_sub_noborrow
        { 60 } OP_PICK { 62 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₅⋅B₀+A₀⋅B₅)₂₈…₀ (A₅⋅B₀+A₀⋅B₅)₅₈…₂₉
        // A₃₊₁⋅B₃₊₁ - A₃⋅B₃ - A₁⋅B₁  <=>  A₃⋅B₁ + A₁⋅B₃
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 68 } OP_PICK { 70 } OP_PICK u29x2_sub_noborrow
        { 64 } OP_PICK { 66 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₃⋅B₁+A₁⋅B₃)₂₈…₀ (A₃⋅B₁+A₁⋅B₃)₅₈…₂₉
        // A₄₊₀⋅B₄₊₀ - A₄⋅B₄ - A₀⋅B₀  <=>  A₄⋅B₀ + A₀⋅B₄
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 72 } OP_PICK { 74 } OP_PICK u29x2_sub_noborrow
        { 64 } OP_PICK { 66 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₄⋅B₀+A₀⋅B₄)₂₈…₀ (A₄⋅B₀+A₀⋅B₄)₅₈…₂₉
        // A₂₊₁⋅B₂₊₁ - A₂⋅B₂ - A₁⋅B₁  <=>  A₂⋅B₁ + A₁⋅B₂
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 70 } OP_PICK { 72 } OP_PICK u29x2_sub_noborrow
        { 68 } OP_PICK { 70 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₂⋅B₁+A₁⋅B₂)₂₈…₀ (A₂⋅B₁+A₁⋅B₂)₅₈…₂₉
        // A₃₊₀⋅B₃₊₀ - A₃⋅B₃ - A₀⋅B₀  <=>  A₃⋅B₀ + A₀⋅B₃
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 74 } OP_PICK { 76 } OP_PICK u29x2_sub_noborrow
        { 68 } OP_PICK { 70 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₃⋅B₀+A₀⋅B₃)₂₈…₀ (A₃⋅B₀+A₀⋅B₃)₅₈…₂₉
        // A₂₊₀⋅B₂₊₀ - A₂⋅B₂ - A₀⋅B₀  <=>  A₂⋅B₀ + A₀⋅B₂
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 74 } OP_PICK { 76 } OP_PICK u29x2_sub_noborrow
        { 70 } OP_PICK { 72 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₂⋅B₀+A₀⋅B₂)₂₈…₀ (A₂⋅B₀+A₀⋅B₂)₅₈…₂₉
        // A₁₊₀⋅B₁₊₀ - A₁⋅B₁ - A₀⋅B₀  <=>  A₁⋅B₀ + A₀⋅B₁
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 74 } OP_PICK { 76 } OP_PICK u29x2_sub_noborrow
        { 72 } OP_PICK { 74 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₁⋅B₀+A₀⋅B₁)₂₈…₀ (A₁⋅B₀+A₀⋅B₁)₅₈…₂₉

        // ⋯ (A₁⋅B₀+A₀⋅B₁)₂₈…₀ (A₁⋅B₀+A₀⋅B₁)₅₈…₂₉
        { 72 } OP_ROLL OP_TOALTSTACK
        // ⋯ (A₁⋅B₀+A₀⋅B₁)₂₈…₀ (A₁⋅B₀+A₀⋅B₁)₅₈…₂₉ | (A⋅B)₀
        { 72 } OP_ROLL
        // ⋯ (A₁⋅B₀+A₀⋅B₁)₂₈…₀ (A₁⋅B₀+A₀⋅B₁)₅₈…₂₉ (A₀⋅B₀)₅₇…₂₉

        // (2²⁹⋅(A₁⋅B₁)₂₈…₀+(A₀⋅B₀)₅₇…₂₉)₅₇…₀ + (A₁⋅B₀+A₀⋅B₁)₅₈…₀
        // ⋯ (A₁⋅B₀+A₀⋅B₁)₂₈…₀ (A₁⋅B₀+A₀⋅B₁)₅₈…₂₉ (A₀⋅B₀)₅₇…₂₉
        { 73 } OP_ROLL
        // ⋯ (A₁⋅B₀+A₀⋅B₁)₂₈…₀ (A₁⋅B₀+A₀⋅B₁)₅₈…₂₉ (A₀⋅B₀)₅₇…₂₉ (A₁⋅B₁)₂₈…₀
        OP_2SWAP
        // ⋯ (A₀⋅B₀)₅₇…₂₉ (A₁⋅B₁)₂₈…₀ (A₁⋅B₀+A₀⋅B₁)₂₈…₀ (A₁⋅B₀+A₀⋅B₁)₅₈…₂₉
        u29x2_add_u29u30_carry
        // (2²⁹⋅(A₁⋅B₁)₂₈…₀+(A₀⋅B₀)₅₇…₂₉)₅₇…₀ + (A₁⋅B₀+A₀⋅B₁)₅₈…₀  <=>  TEMP₁
        // ⋯ (A⋅B)₁ (TEMP₁)₂₈…₀ (TEMP₁)₅₉…₅₈
        OP_ROT OP_TOALTSTACK
        // ⋯ (TEMP₁)₂₈…₀ (TEMP₁)₅₉…₅₈ | (A⋅B)₁ (A⋅B)₀

        // (2²⁹⋅(A₁⋅B₁)₅₇…₂₉+(⋯)₅₈…₂₉)₅₈…₀ + (A₂⋅B₀+A₀⋅B₂)₅₈…₀
        // ⋯ (A₂⋅B₀+A₀⋅B₂)₂₈…₀ (A₂⋅B₀+A₀⋅B₂)₅₈…₂₉ (TEMP₁)₂₈…₀ (TEMP₁)₅₉…₅₈
        OP_2SWAP
        // ⋯ (TEMP₁)₂₈…₀ (TEMP₁)₅₉…₅₈ (A₂⋅B₀+A₀⋅B₂)₂₈…₀ (A₂⋅B₀+A₀⋅B₂)₅₈…₂₉
        u29x2_add_u29u30_carry
        // ⋯ (TEMP₁)₂₈…₀ (TEMP₁)₅₇…₂₉ (TEMP₁)₅₉…₅₈
        OP_ROT OP_TOALTSTACK

        // ⋯ (TEMP₁)₅₇…₂₉ (TEMP₁)₅₉…₅₈ | (TEMP₁)₂₈…₀
        { 70 } OP_ROLL
        // ⋯ (TEMP₁)₅₇…₂₉ (TEMP₁)₅₉…₅₈ (A₁⋅B₁)₅₇…₂₉
        u29x2_add_u29
        // ⋯ (TEMP₁+(A₁⋅B₁)₅₇…₂₉)₂₈…₀ (TEMP₁+(A₁⋅B₁)₅₇…₂₉)₃₁…₂₉

        // (2²⁹⋅(A₂⋅B₂)₂₈…₀+(⋯)₅₈…₂₉)₅₈…₀ + (A₃⋅B₀+A₀⋅B₃)₅₈…₀ + (A₂⋅B₁+A₁⋅B₂)₅₈…₀
        // ⋯ (A₃⋅B₀+A₀⋅B₃)₂₈…₀ (A₃⋅B₀+A₀⋅B₃)₅₈…₂₉ (TEMP₁+(A₁⋅B₁)₅₇…₂₉)₂₈…₀ (TEMP₁+(A₁⋅B₁)₅₇…₂₉)₃₁…₂₉
        OP_0 OP_TOALTSTACK
        // ⋯ (A₃⋅B₀+A₀⋅B₃)₂₈…₀ (A₃⋅B₀+A₀⋅B₃)₅₈…₂₉ (TEMP₁+(A₁⋅B₁)₅₇…₂₉)₂₈…₀ (TEMP₁+(A₁⋅B₁)₅₇…₂₉)₃₁…₂₉ | 0
        OP_2SWAP u29x2_add_u29u30_carry OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        OP_2SWAP u29x2_add_u29u30_carry OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        // ⋯ (A⋅B)₂ (TEMP₂)₂₈…₀ | (TEMP₂)₅₉…₅₈
        
        OP_FROMALTSTACK
        // ⋯ (A⋅B)₂ (TEMP₂)₂₈…₀ (TEMP₂)₅₉…₅₈
        OP_ROT OP_TOALTSTACK
        // ⋯ (TEMP₂)₂₈…₀ (TEMP₂)₅₉…₅₈ | (A⋅B)₂ (A⋅B)₁ (A⋅B)₀
        { 66 } OP_ROLL
        // ⋯ (TEMP₂)₂₈…₀ (TEMP₂)₅₉…₅₈ (A₂⋅B₂)₂₈…₀
        u29x2_add_u29
        // ⋯ (TEMP₂+(A₂⋅B₂)₂₈…₀)₂₈…₀ (TEMP₂+(A₂⋅B₂)₂₈…₀)₅₉…₅₈

        // (2²⁹⋅(A₂⋅B₂)₅₇…₂₉+(⋯)₅₈…₂₉)₅₈…₀ + (A₄⋅B₀+A₀⋅B₄)₅₈…₀ + (A₃⋅B₁+A₁⋅B₃)₅₈…₀
        OP_0 OP_TOALTSTACK
        OP_2SWAP u29x2_add_u29u30_carry OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        OP_2SWAP u29x2_add_u29u30_carry OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        
        OP_FROMALTSTACK
        OP_ROT OP_TOALTSTACK
        { 62 } OP_ROLL
        u29x2_add_u29

        // (2²⁹⋅(A₃⋅B₃)₂₈…₀+(⋯)₅₈…₂₉)₅₈…₀ + (A₅⋅B₀+A₀⋅B₅)₅₈…₀ + (A₄⋅B₁+A₁⋅B₄)₅₈…₀ + (A₃⋅B₂+A₂⋅B₃)₅₈…₀
        OP_0 OP_TOALTSTACK
        OP_2SWAP u29x2_add_u29u30_carry OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        OP_2SWAP u29x2_add_u29u30_carry OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        OP_2SWAP u29x2_add_u29u30_carry OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        
        OP_FROMALTSTACK
        OP_ROT OP_TOALTSTACK
        { 56 } OP_ROLL
        u29x2_add_u29

        // (2²⁹⋅(A₃⋅B₃)₅₇…₂₉+(⋯)₅₈…₂₉)₅₈…₀ + (A₆⋅B₀+A₀⋅B₆)₅₈…₀ + (A₅⋅B₁+A₁⋅B₅)₅₈…₀ + (A₄⋅B₂+A₂⋅B₄)₅₈…₀
        OP_0 OP_TOALTSTACK
        OP_2SWAP u29x2_add_u29u30_carry OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        OP_2SWAP u29x2_add_u29u30_carry OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        OP_2SWAP u29x2_add_u29u30_carry OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        
        OP_FROMALTSTACK
        OP_ROT OP_TOALTSTACK
        { 50 } OP_ROLL
        u29x2_add_u29

        // (2²⁹⋅(A₄⋅B₄)₂₈…₀+(⋯)₅₈…₂₉)₅₈…₀ + (A₇⋅B₀+A₀⋅B₇)₅₈…₀ + (A₆⋅B₁+A₁⋅B₆)₅₈…₀ + (A₅⋅B₂+A₂⋅B₅)₅₈…₀ + (A₄⋅B₃+A₃⋅B₄)₅₈…₀
        OP_0 OP_TOALTSTACK
        OP_2SWAP u29x2_add_u29u30_carry OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        OP_2SWAP u29x2_add_u29u30_carry OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        OP_2SWAP u29x2_add_u29u30_carry OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        OP_2SWAP u29x2_add_u29u30_carry OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        
        OP_FROMALTSTACK
        OP_ROT OP_TOALTSTACK
        { 42 } OP_ROLL
        u29x2_add_u29

        // (2²⁹⋅(A₄⋅B₄)₅₇…₂₉+(⋯)₅₈…₂₉)₅₈…₀ + (A₈⋅B₀+A₀⋅B₈)₅₈…₀ + (A₇⋅B₁+A₁⋅B₇)₅₈…₀ + (A₆⋅B₂+A₂⋅B₆)₅₈…₀ + (A₅⋅B₃+A₃⋅B₅)₅₈…₀
        OP_0 OP_TOALTSTACK
        OP_2SWAP u29x2_add_u29u30_carry OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        OP_2SWAP u29x2_add_u29u30_carry OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        OP_2SWAP u29x2_add_u29u30_carry OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        OP_2SWAP u29x2_add_u29u30_carry OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        
        OP_FROMALTSTACK
        OP_ROT OP_TOALTSTACK
        { 34 } OP_ROLL
        u29x2_add_u29

        // (2²⁹⋅(A₅⋅B₅)₂₈…₀+(⋯)₅₈…₂₉)₅₈…₀ + (A₈⋅B₁+A₁⋅B₈)₅₈…₀ + (A₇⋅B₂+A₂⋅B₇)₅₈…₀ + (A₆⋅B₃+A₃⋅B₆)₅₈…₀ + (A₅⋅B₄+A₄⋅B₅)₅₈…₀
        OP_0 OP_TOALTSTACK
        OP_2SWAP u29x2_add_u29u30_carry OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        OP_2SWAP u29x2_add_u29u30_carry OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        OP_2SWAP u29x2_add_u29u30_carry OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        OP_2SWAP u29x2_add_u29u30_carry OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        
        OP_FROMALTSTACK
        OP_ROT OP_TOALTSTACK
        { 26 } OP_ROLL
        u29x2_add_u29

        // (2²⁹⋅(A₅⋅B₅)₅₇…₂₉+(⋯)₅₈…₂₉)₅₈…₀ + (A₈⋅B₂+A₂⋅B₈)₅₈…₀ + (A₇⋅B₃+A₃⋅B₇)₅₈…₀ + (A₆⋅B₄+A₄⋅B₆)₅₈…₀
        OP_0 OP_TOALTSTACK
        OP_2SWAP u29x2_add_u29u30_carry OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        OP_2SWAP u29x2_add_u29u30_carry OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        OP_2SWAP u29x2_add_u29u30_carry OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        
        OP_FROMALTSTACK
        OP_ROT OP_TOALTSTACK
        { 20 } OP_ROLL
        u29x2_add_u29

        // (2²⁹⋅(A₆⋅B₆)₂₈…₀+(⋯)₅₈…₂₉)₅₈…₀ + (A₈⋅B₃+A₃⋅B₈)₅₈…₀ + (A₇⋅B₄+A₄⋅B₇)₅₈…₀ + (A₆⋅B₅+A₅⋅B₆)₅₈…₀
        OP_0 OP_TOALTSTACK
        OP_2SWAP u29x2_add_u29u30_carry OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        OP_2SWAP u29x2_add_u29u30_carry OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        OP_2SWAP u29x2_add_u29u30_carry OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        
        OP_FROMALTSTACK
        OP_ROT OP_TOALTSTACK
        OP_14 OP_ROLL
        u29x2_add_u29

        // (2²⁹⋅(A₆⋅B₆)₅₇…₂₉+(⋯)₅₈…₂₉)₅₈…₀ + (A₈⋅B₄+A₄⋅B₈)₅₈…₀ + (A₇⋅B₅+A₅⋅B₇)₅₈…₀
        OP_0 OP_TOALTSTACK
        OP_2SWAP u29x2_add_u29u30_carry OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        OP_2SWAP u29x2_add_u29u30_carry OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        
        OP_FROMALTSTACK
        OP_ROT OP_TOALTSTACK
        OP_10 OP_ROLL
        u29x2_add_u29

        // (2²⁹⋅(A₇⋅B₇)₂₈…₀+(⋯)₅₈…₂₉)₅₈…₀ + (A₈⋅B₅+A₅⋅B₈)₅₈…₀ + (A₇⋅B₆+A₆⋅B₇)₅₈…₀
        OP_0 OP_TOALTSTACK
        OP_2SWAP u29x2_add_u29u30_carry OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        OP_2SWAP u29x2_add_u29u30_carry OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        
        OP_FROMALTSTACK
        OP_ROT OP_TOALTSTACK
        OP_6 OP_ROLL
        u29x2_add_u29

        // (2²⁹⋅(A₇⋅B₇)₅₇…₂₉+(⋯)₅₈…₂₉)₅₈…₀ + (A₈⋅B₆+A₆⋅B₈)₅₈…₀
        OP_2SWAP
        u29x2_add_u29u30_carry
        OP_ROT OP_TOALTSTACK
        OP_4 OP_ROLL
        u29x2_add_u29

        // (2²⁹⋅(A₈⋅B₈)₂₈…₀+(⋯)₅₈…₂₉)₅₈…₀ + (A₈⋅B₇+A₇⋅B₈)₅₈…₀
        OP_2SWAP
        u29x2_add_u29u30_carry
        OP_ROT OP_TOALTSTACK
        OP_ROT
        u29x2_add_u29

        // (2²⁹⋅(A₈⋅B₈)₅₇…₂₉+(⋯)₅₈…₂₉)₅₈…₀
        OP_SWAP OP_TOALTSTACK

        // (⋯)₅₈…₂₉
        OP_ADD OP_TOALTSTACK
        for _ in 0..9 {
            OP_FROMALTSTACK
            OP_FROMALTSTACK
        }

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

// A₈⋅B₀+A₇⋅B₁+A₆⋅B₂+A₅⋅B₃+A₄⋅B₄+A₃⋅B₅+A₂⋅B₆+A₁⋅B₇+A₀⋅B₈
//    A₇⋅B₀+A₆⋅B₁+A₅⋅B₂+A₄⋅B₃+A₃⋅B₄+A₂⋅B₅+A₁⋅B₆+A₀⋅B₇
//       A₆⋅B₀+A₅⋅B₁+A₄⋅B₂+A₃⋅B₃+A₂⋅B₄+A₁⋅B₅+A₀⋅B₆
//         A₅⋅B₀+A₄⋅B₁+A₃⋅B₂+A₂⋅B₃+A₁⋅B₄+A₀⋅B₅
//            A₄⋅B₀+A₃⋅B₁+A₂⋅B₂+A₁⋅B₃+A₀⋅B₄
//               A₃⋅B₀+A₂⋅B₁+A₁⋅B₂+A₀⋅B₃
//                  A₂⋅B₀+A₁⋅B₁+A₀⋅B₂
//                     A₁⋅B₀+A₀⋅B₁
//                        A₀⋅B₀

pub fn u29x9_mullo_karazuba(a: u32, b: u32) -> Script {
    script! {
        // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ A₁ A₀ ⋯ B₈ B₇ B₆ B₅ B₄ B₃ B₂ B₁ B₀ ⋯
        { U254::zip(a, b) }
        // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ B₁ A₀ B₀

        // A₁₊₀ B₁₊₀
        OP_2 OP_PICK OP_1 OP_PICK OP_ADD OP_TOALTSTACK
        OP_3 OP_PICK OP_2 OP_PICK OP_ADD OP_TOALTSTACK
        // A₂₊₀ B₂₊₀
        OP_4 OP_PICK OP_1 OP_PICK OP_ADD OP_TOALTSTACK
        OP_5 OP_PICK OP_2 OP_PICK OP_ADD OP_TOALTSTACK
        // A₃₊₀ B₃₊₀
        OP_6 OP_PICK OP_1 OP_PICK OP_ADD OP_TOALTSTACK
        OP_7 OP_PICK OP_2 OP_PICK OP_ADD OP_TOALTSTACK
        // A₂₊₁ B₂₊₁
        OP_4 OP_PICK OP_3 OP_PICK OP_ADD OP_TOALTSTACK
        OP_5 OP_PICK OP_4 OP_PICK OP_ADD OP_TOALTSTACK
        // A₄₊₀ B₄₊₀
        OP_8 OP_PICK OP_1 OP_PICK OP_ADD OP_TOALTSTACK
        OP_9 OP_PICK OP_2 OP_PICK OP_ADD OP_TOALTSTACK
        // A₃₊₁ B₃₊₁
        OP_6 OP_PICK OP_3 OP_PICK OP_ADD OP_TOALTSTACK
        OP_7 OP_PICK OP_4 OP_PICK OP_ADD OP_TOALTSTACK
        // A₅₊₀ B₅₊₀
        OP_10 OP_PICK OP_1 OP_PICK OP_ADD OP_TOALTSTACK
        OP_11 OP_PICK OP_2 OP_PICK OP_ADD OP_TOALTSTACK
        // A₄₊₁ B₄₊₁
        OP_8 OP_PICK OP_3 OP_PICK OP_ADD OP_TOALTSTACK
        OP_9 OP_PICK OP_4 OP_PICK OP_ADD OP_TOALTSTACK
        // A₃₊₂ B₃₊₂
        OP_6 OP_PICK OP_5 OP_PICK OP_ADD OP_TOALTSTACK
        OP_7 OP_PICK OP_6 OP_PICK OP_ADD OP_TOALTSTACK
        // A₆₊₀ B₆₊₀
        OP_12 OP_PICK OP_1 OP_PICK OP_ADD OP_TOALTSTACK
        OP_13 OP_PICK OP_2 OP_PICK OP_ADD OP_TOALTSTACK
        // A₅₊₁ B₅₊₁
        OP_10 OP_PICK OP_3 OP_PICK OP_ADD OP_TOALTSTACK
        OP_11 OP_PICK OP_4 OP_PICK OP_ADD OP_TOALTSTACK
        // A₄₊₂ B₄₊₂
        OP_8 OP_PICK OP_5 OP_PICK OP_ADD OP_TOALTSTACK
        OP_9 OP_PICK OP_6 OP_PICK OP_ADD OP_TOALTSTACK
        // A₇₊₀ B₇₊₀
        OP_14 OP_PICK OP_1 OP_PICK OP_ADD OP_TOALTSTACK
        OP_15 OP_PICK OP_2 OP_PICK OP_ADD OP_TOALTSTACK
        // A₆₊₁ B₆₊₁
        OP_12 OP_PICK OP_3 OP_PICK OP_ADD OP_TOALTSTACK
        OP_13 OP_PICK OP_4 OP_PICK OP_ADD OP_TOALTSTACK
        // A₅₊₂ B₅₊₂
        OP_10 OP_PICK OP_5 OP_PICK OP_ADD OP_TOALTSTACK
        OP_11 OP_PICK OP_6 OP_PICK OP_ADD OP_TOALTSTACK
        // A₄₊₃ B₄₊₃
        OP_8 OP_PICK OP_7 OP_PICK OP_ADD OP_TOALTSTACK
        OP_9 OP_PICK OP_8 OP_PICK OP_ADD OP_TOALTSTACK
        // A₈₊₀ B₈₊₀
        OP_16 OP_PICK OP_1 OP_PICK OP_ADD OP_TOALTSTACK
        { 17 } OP_PICK OP_2 OP_PICK OP_ADD OP_TOALTSTACK
        // A₇₊₁ B₇₊₁
        OP_14 OP_PICK OP_3 OP_PICK OP_ADD OP_TOALTSTACK
        OP_15 OP_PICK OP_4 OP_PICK OP_ADD OP_TOALTSTACK
        // A₆₊₂ B₆₊₂
        OP_12 OP_PICK OP_5 OP_PICK OP_ADD OP_TOALTSTACK
        OP_13 OP_PICK OP_6 OP_PICK OP_ADD OP_TOALTSTACK
        // A₅₊₃ B₅₊₃
        OP_10 OP_PICK OP_7 OP_PICK OP_ADD OP_TOALTSTACK
        OP_11 OP_PICK OP_8 OP_PICK OP_ADD OP_TOALTSTACK

        // NOTE: Unused high-word
        // A₈₊₁ B₈₊₁ A₇₊₂ B₇₊₂ A₆₊₃ B₆₊₃ A₅₊₄ B₅₊₄
        // A₈₊₂ B₈₊₂ A₇₊₃ B₇₊₃ A₆₊₄ B₆₊₄
        // A₈₊₃ B₈₊₃ A₇₊₄ B₇₊₄ A₆₊₅ B₆₊₅
        // A₈₊₄ B₈₊₄ A₇₊₅ B₇₊₅
        // A₈₊₅ B₈₊₅ A₇₊₆ B₇₊₆
        // A₈₊₆ B₈₊₆
        // A₈₊₇ B₈₊₇

        for _ in 0..9 {
            { 17 } OP_ROLL
            { 17 } OP_ROLL
            u29_mul_carry_29
            OP_SWAP
        }

        // NOTE: Unused high-word
        // A₈₊₇⋅B₈₊₇ - A₈⋅B₈ - A₇⋅B₇  <=>  A₈⋅B₇ + A₇⋅B₈
        // A₈₊₆⋅B₈₊₆ - A₈⋅B₈ - A₆⋅B₆  <=>  A₈⋅B₆ + A₆⋅B₈
        // A₇₊₆⋅B₇₊₆ - A₇⋅B₇ - A₆⋅B₆  <=>  A₇⋅B₆ + A₆⋅B₇
        // A₈₊₅⋅B₈₊₅ - A₈⋅B₈ - A₅⋅B₅  <=>  A₈⋅B₅ + A₅⋅B₈
        // A₇₊₅⋅B₇₊₅ - A₇⋅B₇ - A₅⋅B₅  <=>  A₇⋅B₅ + A₅⋅B₇
        // A₈₊₄⋅B₈₊₄ - A₈⋅B₈ - A₄⋅B₄  <=>  A₈⋅B₄ + A₄⋅B₈
        // A₆₊₅⋅B₆₊₅ - A₆⋅B₆ - A₅⋅B₅  <=>  A₆⋅B₅ + A₅⋅B₆
        // A₇₊₄⋅B₇₊₄ - A₇⋅B₇ - A₄⋅B₄  <=>  A₇⋅B₄ + A₄⋅B₇
        // A₈₊₃⋅B₈₊₃ - A₈⋅B₈ - A₃⋅B₃  <=>  A₈⋅B₃ + A₃⋅B₈
        // A₆₊₄⋅B₆₊₄ - A₆⋅B₆ - A₄⋅B₄  <=>  A₆⋅B₄ + A₄⋅B₆
        // A₇₊₃⋅B₇₊₃ - A₇⋅B₇ - A₃⋅B₃  <=>  A₇⋅B₃ + A₃⋅B₇
        // A₈₊₂⋅B₈₊₂ - A₈⋅B₈ - A₂⋅B₂  <=>  A₈⋅B₂ + A₂⋅B₈
        // A₅₊₄⋅B₅₊₄ - A₅⋅B₅ - A₄⋅B₄  <=>  A₅⋅B₄ + A₄⋅B₅
        // A₆₊₃⋅B₆₊₃ - A₆⋅B₆ - A₃⋅B₃  <=>  A₆⋅B₃ + A₃⋅B₆
        // A₇₊₂⋅B₇₊₂ - A₇⋅B₇ - A₂⋅B₂  <=>  A₇⋅B₂ + A₂⋅B₇
        // A₈₊₁⋅B₈₊₁ - A₈⋅B₈ - A₁⋅B₁  <=>  A₈⋅B₁ + A₁⋅B₈

        // A₅₊₃⋅B₅₊₃ - A₅⋅B₅ - A₃⋅B₃  <=>  A₅⋅B₃ + A₃⋅B₅
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        OP_12 OP_PICK OP_14 OP_PICK u29x2_sub_noborrow
        OP_8  OP_PICK OP_10 OP_PICK u29x2_sub_noborrow
        // ⋯ (A₅⋅B₃+A₃⋅B₅)₂₈…₀ (A₅⋅B₃+A₃⋅B₅)₅₈…₂₉
        // A₆₊₂⋅B₆₊₂ - A₆⋅B₆ - A₂⋅B₂  <=>  A₆⋅B₂ + A₂⋅B₆
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        OP_16 OP_PICK { 18 } OP_PICK u29x2_sub_noborrow
        OP_8 OP_PICK OP_10 OP_PICK u29x2_sub_noborrow
        // ⋯ (A₆⋅B₂+A₂⋅B₆)₂₈…₀ (A₆⋅B₂+A₂⋅B₆)₅₈…₂₉
        // A₇₊₁⋅B₇₊₁ - A₇⋅B₇ - A₁⋅B₁  <=>  A₇⋅B₁ + A₁⋅B₇
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 20 } OP_PICK { 22 } OP_PICK u29x2_sub_noborrow
        OP_8 OP_PICK OP_10 OP_PICK u29x2_sub_noborrow
        // ⋯ (A₇⋅B₁+A₁⋅B₇)₂₈…₀ (A₇⋅B₁+A₁⋅B₇)₅₈…₂₉
        // A₈₊₀⋅B₈₊₀ - A₈⋅B₈ - A₀⋅B₀  <=>  A₈⋅B₀ + A₀⋅B₈
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 24 } OP_PICK { 26 } OP_PICK u29x2_sub_noborrow
        OP_8 OP_PICK OP_10 OP_PICK u29x2_sub_noborrow
        // ⋯ (A₈⋅B₀+A₀⋅B₈)₂₈…₀ (A₈⋅B₀+A₀⋅B₈)₅₈…₂₉
        // A₄₊₃⋅B₄₊₃ - A₄⋅B₄ - A₃⋅B₃  <=>  A₄⋅B₃ + A₃⋅B₄
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 18 } OP_PICK { 20 } OP_PICK u29x2_sub_noborrow
        OP_16 OP_PICK { 18 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₄⋅B₃+A₃⋅B₄)₂₈…₀ (A₄⋅B₃+A₃⋅B₄)₅₈…₂₉
        // A₅₊₂⋅B₅₊₂ - A₅⋅B₅ - A₂⋅B₂  <=>  A₅⋅B₂ + A₂⋅B₅
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 22 } OP_PICK { 24 } OP_PICK u29x2_sub_noborrow
        OP_16 OP_PICK { 18 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₅⋅B₂+A₂⋅B₅)₂₈…₀ (A₅⋅B₂+A₂⋅B₅)₅₈…₂₉
        // A₆₊₁⋅B₆₊₁ - A₆⋅B₆ - A₁⋅B₁  <=>  A₆⋅B₁ + A₁⋅B₆
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 26 } OP_PICK { 28 } OP_PICK u29x2_sub_noborrow
        OP_16 OP_PICK { 18 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₆⋅B₁+A₁⋅B₆)₂₈…₀ (A₆⋅B₁+A₁⋅B₆)₅₈…₂₉
        // A₇₊₀⋅B₇₊₀ - A₇⋅B₇ - A₀⋅B₀  <=>  A₇⋅B₀ + A₀⋅B₇
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 30 } OP_PICK { 32 } OP_PICK u29x2_sub_noborrow
        OP_16 OP_PICK { 18 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₇⋅B₀+A₀⋅B₇)₂₈…₀ (A₇⋅B₀+A₀⋅B₇)₅₈…₂₉
        // A₄₊₂⋅B₄₊₂ - A₄⋅B₄ - A₂⋅B₂  <=>  A₄⋅B₂ + A₂⋅B₄
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 26 } OP_PICK { 28 } OP_PICK u29x2_sub_noborrow
        { 22 } OP_PICK { 24 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₄⋅B₂+A₂⋅B₄)₂₈…₀ (A₄⋅B₂+A₂⋅B₄)₅₈…₂₉
        // A₅₊₁⋅B₅₊₁ - A₅⋅B₅ - A₁⋅B₁  <=>  A₅⋅B₁ + A₁⋅B₅
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 30 } OP_PICK { 32 } OP_PICK u29x2_sub_noborrow
        { 22 } OP_PICK { 24 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₅⋅B₁+A₁⋅B₅)₂₈…₀ (A₅⋅B₁+A₁⋅B₅)₅₈…₂₉
        // A₆₊₀⋅B₆₊₀ - A₆⋅B₆ - A₀⋅B₀  <=>  A₆⋅B₀ + A₀⋅B₆
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 34 } OP_PICK { 36 } OP_PICK u29x2_sub_noborrow
        { 22 } OP_PICK { 24 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₆⋅B₀+A₀⋅B₆)₂₈…₀ (A₆⋅B₀+A₀⋅B₆)₅₈…₂₉
        // A₃₊₂⋅B₃₊₂ - A₃⋅B₃ - A₂⋅B₂  <=>  A₃⋅B₂ + A₂⋅B₃
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 30 } OP_PICK { 32 } OP_PICK u29x2_sub_noborrow
        { 28 } OP_PICK { 30 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₃⋅B₂+A₂⋅B₃)₂₈…₀ (A₃⋅B₂+A₂⋅B₃)₅₈…₂₉
        // A₄₊₁⋅B₄₊₁ - A₄⋅B₄ - A₁⋅B₁  <=>  A₄⋅B₁ + A₁⋅B₄
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 34 } OP_PICK { 36 } OP_PICK u29x2_sub_noborrow
        { 28 } OP_PICK { 30 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₄⋅B₁+A₁⋅B₄)₂₈…₀ (A₄⋅B₁+A₁⋅B₄)₅₈…₂₉
        // A₅₊₀⋅B₅₊₀ - A₅⋅B₅ - A₀⋅B₀  <=>  A₅⋅B₀ + A₀⋅B₅
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 38 } OP_PICK { 40 } OP_PICK u29x2_sub_noborrow
        { 28 } OP_PICK { 30 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₅⋅B₀+A₀⋅B₅)₂₈…₀ (A₅⋅B₀+A₀⋅B₅)₅₈…₂₉
        // A₃₊₁⋅B₃₊₁ - A₃⋅B₃ - A₁⋅B₁  <=>  A₃⋅B₁ + A₁⋅B₃
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 36 } OP_PICK { 38 } OP_PICK u29x2_sub_noborrow
        { 32 } OP_PICK { 34 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₃⋅B₁+A₁⋅B₃)₂₈…₀ (A₃⋅B₁+A₁⋅B₃)₅₈…₂₉
        // A₄₊₀⋅B₄₊₀ - A₄⋅B₄ - A₀⋅B₀  <=>  A₄⋅B₀ + A₀⋅B₄
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 40 } OP_PICK { 42 } OP_PICK u29x2_sub_noborrow
        { 32 } OP_PICK { 34 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₄⋅B₀+A₀⋅B₄)₂₈…₀ (A₄⋅B₀+A₀⋅B₄)₅₈…₂₉
        // A₂₊₁⋅B₂₊₁ - A₂⋅B₂ - A₁⋅B₁  <=>  A₂⋅B₁ + A₁⋅B₂
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 38 } OP_PICK { 40 } OP_PICK u29x2_sub_noborrow
        { 36 } OP_PICK { 38 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₂⋅B₁+A₁⋅B₂)₂₈…₀ (A₂⋅B₁+A₁⋅B₂)₅₈…₂₉
        // A₃₊₀⋅B₃₊₀ - A₃⋅B₃ - A₀⋅B₀  <=>  A₃⋅B₀ + A₀⋅B₃
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 42 } OP_PICK { 44 } OP_PICK u29x2_sub_noborrow
        { 36 } OP_PICK { 38 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₃⋅B₀+A₀⋅B₃)₂₈…₀ (A₃⋅B₀+A₀⋅B₃)₅₈…₂₉
        // A₂₊₀⋅B₂₊₀ - A₂⋅B₂ - A₀⋅B₀  <=>  A₂⋅B₀ + A₀⋅B₂
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 42 } OP_PICK { 44 } OP_PICK u29x2_sub_noborrow
        { 38 } OP_PICK { 40 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₂⋅B₀+A₀⋅B₂)₂₈…₀ (A₂⋅B₀+A₀⋅B₂)₅₈…₂₉
        // A₁₊₀⋅B₁₊₀ - A₁⋅B₁ - A₀⋅B₀  <=>  A₁⋅B₀ + A₀⋅B₁
        OP_FROMALTSTACK OP_FROMALTSTACK u30_mul_to_u29_carry_31
        { 42 } OP_PICK { 44 } OP_PICK u29x2_sub_noborrow
        { 40 } OP_PICK { 42 } OP_PICK u29x2_sub_noborrow
        // ⋯ (A₁⋅B₀+A₀⋅B₁)₂₈…₀ (A₁⋅B₀+A₀⋅B₁)₅₈…₂₉

        { 40 } OP_ROLL OP_TOALTSTACK
        { 40 } OP_ROLL
        // ⋯ (A₀⋅B₀)₅₇…₂₉

        // (2²⁹⋅(A₁⋅B₁)₂₈…₀+(A₀⋅B₀)₅₇…₂₉)₅₇…₀ + (A₁⋅B₀+A₀⋅B₁)₅₈…₀
        // ⋯ (A₁⋅B₀+A₀⋅B₁)₂₈…₀ (A₁⋅B₀+A₀⋅B₁)₅₈…₂₉ (A₀⋅B₀)₅₇…₂₉
        { 41 } OP_ROLL
        // ⋯ (A₁⋅B₀+A₀⋅B₁)₂₈…₀ (A₁⋅B₀+A₀⋅B₁)₅₈…₂₉ (A₀⋅B₀)₅₇…₂₉ (A₁⋅B₁)₂₈…₀ | (A⋅B)₀
        OP_2SWAP
        // ⋯ (A₀⋅B₀)₅₇…₂₉ (A₁⋅B₁)₂₈…₀ (A₁⋅B₀+A₀⋅B₁)₂₈…₀ (A₁⋅B₀+A₀⋅B₁)₅₈…₂₉
        u29x2_add_u29u30_carry
        // (2²⁹⋅(A₁⋅B₁)₂₈…₀+(A₀⋅B₀)₅₇…₂₉)₅₇…₀ + (A₁⋅B₀+A₀⋅B₁)₅₈…₀  <=>  TEMP₁
        // ⋯ (A⋅B)₁ (TEMP₁)₂₈…₀ (TEMP₁)₅₉…₅₈
        OP_ROT OP_TOALTSTACK
        // ⋯ (TEMP₁)₂₈…₀ (TEMP₁)₅₉…₅₈ | (A⋅B)₁ (A⋅B)₀

        // (2²⁹⋅(A₁⋅B₁)₅₇…₂₉+(⋯)₅₈…₂₉)₅₈…₀ + (A₂⋅B₀+A₀⋅B₂)₅₈…₀
        // ⋯ (A₂⋅B₀+A₀⋅B₂)₂₈…₀ (A₂⋅B₀+A₀⋅B₂)₅₈…₂₉ (TEMP₁)₂₈…₀ (TEMP₁)₅₉…₅₈
        OP_2SWAP
        // ⋯ (TEMP₁)₂₈…₀ (TEMP₁)₅₉…₅₈ (A₂⋅B₀+A₀⋅B₂)₂₈…₀ (A₂⋅B₀+A₀⋅B₂)₅₈…₂₉
        u29x2_add_u29u30_carry
        // ⋯ (TEMP₁)₂₈…₀ (TEMP₁)₅₇…₂₉ (TEMP₁)₅₉…₅₈
        OP_ROT OP_TOALTSTACK

        // ⋯ (TEMP₁)₅₇…₂₉ (TEMP₁)₅₉…₅₈ | (TEMP₁)₂₈…₀
        { 38 } OP_ROLL
        // ⋯ (TEMP₁)₅₇…₂₉ (TEMP₁)₅₉…₅₈ (A₁⋅B₁)₅₇…₂₉
        u29x2_add_u29
        // ⋯ (TEMP₁+(A₁⋅B₁)₅₇…₂₉)₂₈…₀ (TEMP₁+(A₁⋅B₁)₅₇…₂₉)₃₁…₂₉

        // (2²⁹⋅(A₂⋅B₂)₂₈…₀+(⋯)₅₈…₂₉)₅₈…₀ + (A₃⋅B₀+A₀⋅B₃)₅₈…₀ + (A₂⋅B₁+A₁⋅B₂)₅₈…₀
        // ⋯ (A₃⋅B₀+A₀⋅B₃)₂₈…₀ (A₃⋅B₀+A₀⋅B₃)₅₈…₂₉ (TEMP₁+(A₁⋅B₁)₅₇…₂₉)₂₈…₀ (TEMP₁+(A₁⋅B₁)₅₇…₂₉)₃₁…₂₉
        OP_0 OP_TOALTSTACK
        // ⋯ (A₃⋅B₀+A₀⋅B₃)₂₈…₀ (A₃⋅B₀+A₀⋅B₃)₅₈…₂₉ (TEMP₁+(A₁⋅B₁)₅₇…₂₉)₂₈…₀ (TEMP₁+(A₁⋅B₁)₅₇…₂₉)₃₁…₂₉ | 0
        OP_2SWAP u29x2_add_u29u30_carry OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        OP_2SWAP u29x2_add_u29u30_carry OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        // ⋯ (A⋅B)₂ (TEMP₂)₂₈…₀ | (TEMP₂)₅₉…₅₈
        
        OP_FROMALTSTACK
        // ⋯ (A⋅B)₂ (TEMP₂)₂₈…₀ (TEMP₂)₅₉…₅₈
        OP_ROT OP_TOALTSTACK
        // ⋯ (TEMP₂)₂₈…₀ (TEMP₂)₅₉…₅₈ | (A⋅B)₂ (A⋅B)₁ (A⋅B)₀
        { 34 } OP_ROLL
        // ⋯ (TEMP₂)₂₈…₀ (TEMP₂)₅₉…₅₈ (A₂⋅B₂)₂₈…₀
        u29x2_add_u29
        // ⋯ (TEMP₂+(A₂⋅B₂)₂₈…₀)₂₈…₀ (TEMP₂+(A₂⋅B₂)₂₈…₀)₅₉…₅₈

        // (2²⁹⋅(A₂⋅B₂)₅₇…₂₉+(⋯)₅₈…₂₉)₅₈…₀ + (A₄⋅B₀+A₀⋅B₄)₅₈…₀ + (A₃⋅B₁+A₁⋅B₃)₅₈…₀
        OP_0 OP_TOALTSTACK
        OP_2SWAP u29x2_add_u29u30_carry OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        OP_2SWAP u29x2_add_u29u30_carry OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        
        OP_FROMALTSTACK
        OP_ROT OP_TOALTSTACK
        { 30 } OP_ROLL
        u29x2_add_u29

        // (2²⁹⋅(A₃⋅B₃)₂₈…₀+(⋯)₅₈…₂₉)₅₈…₀ + (A₅⋅B₀+A₀⋅B₅)₅₈…₀ + (A₄⋅B₁+A₁⋅B₄)₅₈…₀ + (A₃⋅B₂+A₂⋅B₃)₅₈…₀
        OP_0 OP_TOALTSTACK
        OP_2SWAP u29x2_add_u29u30_carry OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        OP_2SWAP u29x2_add_u29u30_carry OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        OP_2SWAP u29x2_add_u29u30_carry OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        
        OP_FROMALTSTACK
        OP_ROT OP_TOALTSTACK
        { 24 } OP_ROLL
        u29x2_add_u29

        // (2²⁹⋅(A₃⋅B₃)₅₇…₂₉+(⋯)₅₈…₂₉)₅₈…₀ + (A₆⋅B₀+A₀⋅B₆)₅₈…₀ + (A₅⋅B₁+A₁⋅B₅)₅₈…₀ + (A₄⋅B₂+A₂⋅B₄)₅₈…₀
        OP_0 OP_TOALTSTACK
        OP_2SWAP u29x2_add_u29u30_carry OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        OP_2SWAP u29x2_add_u29u30_carry OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        OP_2SWAP u29x2_add_u29u30_carry OP_FROMALTSTACK OP_ADD OP_TOALTSTACK

        OP_FROMALTSTACK
        OP_ROT OP_TOALTSTACK
        { 18 } OP_ROLL
        u29x2_add_u29

        // (2²⁹⋅(A₄⋅B₄)₂₈…₀+(⋯)₅₈…₂₉)₅₈…₀ + (A₇⋅B₀+A₀⋅B₇)₅₈…₀ + (A₆⋅B₁+A₁⋅B₆)₅₈…₀ + (A₅⋅B₂+A₂⋅B₅)₅₈…₀ + (A₄⋅B₃+A₃⋅B₄)₅₈…₀
        OP_0 OP_TOALTSTACK
        OP_2SWAP u29x2_add_u29u30_carry OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        OP_2SWAP u29x2_add_u29u30_carry OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        OP_2SWAP u29x2_add_u29u30_carry OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        OP_2SWAP u29x2_add_u29u30_carry OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        
        OP_FROMALTSTACK
        OP_ROT OP_TOALTSTACK
        OP_10 OP_ROLL
        u29x2_add_u29

        // (2²⁹⋅(A₄⋅B₄)₅₇…₂₉+(⋯)₅₈…₂₉)₅₈…₀ + (A₈⋅B₀+A₀⋅B₈)₅₈…₀ + (A₇⋅B₁+A₁⋅B₇)₅₈…₀ + (A₆⋅B₂+A₂⋅B₆)₅₈…₀ + (A₅⋅B₃+A₃⋅B₅)₅₈…₀
        OP_0 OP_TOALTSTACK
        OP_2SWAP u29x2_add_u29u30_carry OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        OP_2SWAP u29x2_add_u29u30_carry OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        OP_2SWAP u29x2_add_u29u30_carry OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        OP_2SWAP u29x2_add_u29u30_carry OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        
        OP_FROMALTSTACK
        OP_ROT OP_NIP OP_TOALTSTACK
        OP_2DROP OP_2DROP OP_2DROP OP_2DROP OP_2DROP

        // NOTE: Unused high-word
        // (2²⁹⋅(A₅⋅B₅)₂₈…₀+(⋯)₅₈…₂₉)₅₈…₀ + (A₈⋅B₁+A₁⋅B₈)₅₈…₀ + (A₇⋅B₂+A₂⋅B₇)₅₈…₀ + (A₆⋅B₃+A₃⋅B₆)₅₈…₀ + (A₅⋅B₄+A₄⋅B₅)₅₈…₀
        // (2²⁹⋅(A₅⋅B₅)₅₇…₂₉+(⋯)₅₈…₂₉)₅₈…₀ + (A₈⋅B₂+A₂⋅B₈)₅₈…₀ + (A₇⋅B₃+A₃⋅B₇)₅₈…₀ + (A₆⋅B₄+A₄⋅B₆)₅₈…₀
        // (2²⁹⋅(A₆⋅B₆)₂₈…₀+(⋯)₅₈…₂₉)₅₈…₀ + (A₈⋅B₃+A₃⋅B₈)₅₈…₀ + (A₇⋅B₄+A₄⋅B₇)₅₈…₀ + (A₆⋅B₅+A₅⋅B₆)₅₈…₀
        // (2²⁹⋅(A₆⋅B₆)₅₇…₂₉+(⋯)₅₈…₂₉)₅₈…₀ + (A₈⋅B₄+A₄⋅B₈)₅₈…₀ + (A₇⋅B₅+A₅⋅B₇)₅₈…₀
        // (2²⁹⋅(A₇⋅B₇)₂₈…₀+(⋯)₅₈…₂₉)₅₈…₀ + (A₈⋅B₅+A₅⋅B₈)₅₈…₀ + (A₇⋅B₆+A₆⋅B₇)₅₈…₀
        // (2²⁹⋅(A₇⋅B₇)₅₇…₂₉+(⋯)₅₈…₂₉)₅₈…₀ + (A₈⋅B₆+A₆⋅B₈)₅₈…₀
        // (2²⁹⋅(A₈⋅B₈)₂₈…₀+(⋯)₅₈…₂₉)₅₈…₀ + (A₈⋅B₇+A₇⋅B₈)₅₈…₀
        // (2²⁹⋅(A₈⋅B₈)₅₇…₂₉+(⋯)₅₈…₂₉)₅₈…₀
        // (⋯)₅₈…₂₉

        for _ in 0..9 {
            OP_FROMALTSTACK
        }

    }
}

pub fn u29x9_mulhi_karazuba(a: u32, b: u32) -> Script {
    script! {
        // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ A₁ A₀ ⋯ B₈ B₇ B₆ B₅ B₄ B₃ B₂ B₁ B₀ ⋯
        { u29x9_mul_karazuba(a, b) }
        OP_2DROP OP_2DROP OP_2DROP OP_2DROP OP_DROP
    }
}

#[cfg(test)]
mod test {
    use super::*;
    

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

            // Multiply 0x1426971c ⋅ 0x12627bef
            { 0x1426971c }
            { 0x12627bef }
            // 0x1426971c 0x12627bef
            { u30_mul_to_u29_carry_31() }
            // 0xB598724 0xB93B939
            { 0xB93B939 } OP_EQUALVERIFY
            { 0xB598724 } OP_EQUALVERIFY

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
            // a.c0 = 0x1eaea6410b7b58843c06c0d8fca3dc0a7d82b11dfd91b7cb0c0ad3ba0ff345d8
            { 0x1eaea6 }
            { 0x8216f6b }
            { 0x210f01b }
            { 0x6c7e51 }
            { 0x1dc0a7d8 }
            { 0x5623bfb }
            { 0x46df2c3 }
            { 0x569dd0 }
            { 0xff345d8 }
            // b = 0x2adca7063c3e4dd8c35651e75e9feb1d044425f7b9bea3692eb980797d8988a4
            { 0x2adca7 }
            { 0xc787c9 }
            { 0x17630d59 }
            { 0x8f3af4f }
            { 0x1eb1d044 }
            { 0x84bef73 }
            { 0xfa8da4b }
            { 0x15cc03cb }
            { 0x1d8988a4 }
            // a.c0 * b
            { u29x9_mul_karazuba(1, 0) }
            { 0xd8b7e60 } OP_EQUALVERIFY
            { 0xe368872 } OP_EQUALVERIFY
            { 0x19b76105 } OP_EQUALVERIFY
            { 0x11b2d28a } OP_EQUALVERIFY
            { 0x17e1b306 } OP_EQUALVERIFY
            { 0x11217389 } OP_EQUALVERIFY
            { 0x8e5ccd0 } OP_EQUALVERIFY
            { 0x107923b2 } OP_EQUALVERIFY
            { 0xb45035d } OP_EQUALVERIFY
            { 0xf7d973c } OP_EQUALVERIFY
            { 0x109f03ed } OP_EQUALVERIFY
            { 0x2f58350 } OP_EQUALVERIFY
            { 0x6fc1dc1 } OP_EQUALVERIFY
            { 0x7ad1455 } OP_EQUALVERIFY
            { 0x1fc31efb } OP_EQUALVERIFY
            { 0x1aa4308a } OP_EQUALVERIFY
            { 0x1962398c } OP_EQUALVERIFY
            { 0x2918 } OP_EQUALVERIFY
            OP_TRUE
        };

        let exec_result = execute_script(script);
        if !exec_result.success {
            println!("ERROR: {:?} <---", exec_result.last_opcode)
        }
        assert!(exec_result.success);
    }

    #[test]
    fn test_u29x9_mullo_karazuba() {
        println!(
            "u29x9_mullo_karazuba: {} bytes",
            u29x9_mullo_karazuba(1, 0).len()
        );
        let script = script! {
            { 0xFFFFFF } { 0x1FFFFFFF } { 0x1FFFFFFF } { 0x1FFFFFFF } { 0x1FFFFFFF } { 0x1FFFFFFF } { 0x1FFFFFFF } { 0x1FFFFFFF } { 0x1FFFFFFF }
            { 0xFFFFFF } { 0x1FFFFFFF } { 0x1FFFFFFF } { 0x1FFFFFFF } { 0x1FFFFFFF } { 0x1FFFFFFF } { 0x1FFFFFFF } { 0x1FFFFFFF } { 0x1FFFFFFF }
            { u29x9_mullo_karazuba(1, 0) }
            { 0x00000001 } OP_EQUALVERIFY
            { 0x00000000 } OP_EQUALVERIFY
            { 0x00000000 } OP_EQUALVERIFY
            { 0x00000000 } OP_EQUALVERIFY
            { 0x00000000 } OP_EQUALVERIFY
            { 0x00000000 } OP_EQUALVERIFY
            { 0x00000000 } OP_EQUALVERIFY
            { 0x00000000 } OP_EQUALVERIFY
            { 0x1E000000 } OP_EQUALVERIFY
            // p = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
            // Mont(x) = 0xdc83629563d44755301fa84819caa36fb90a6020ce148c34e8384eb157ccc21 * x % p
            // a.c0 = 0x1eaea6410b7b58843c06c0d8fca3dc0a7d82b11dfd91b7cb0c0ad3ba0ff345d8
            // Mont(a.c0) = 0x12a7170d13e68fac161e7bff57ed8bf3edbd028512ed2695148fc5aec2b5266a
            { 0x12a717 }
            { 0x1a27cd1 }
            { 0x1eb05879 }
            { 0x1dffabf6 }
            { 0x18bf3edb }
            { 0x1a050a25 }
            { 0x1b49a545 }
            { 0x47e2d76 }
            { 0x2b5266a }
            // b = 0x2adca7063c3e4dd8c35651e75e9feb1d044425f7b9bea3692eb980797d8988a4
            // Mont(b) = 0x20e60f32a6045965768b2eb95567a9237200ba53b43e88904c79d6cb5b913b1d
            { 0x20e60f }
            { 0x654c08b }
            { 0x595da2c }
            { 0x175caab3 }
            { 0x1a923720 }
            { 0x174a768 }
            { 0xfa22413 }
            { 0x3ceb65a }
            { 0x1b913b1d }
            // Mont(a.c0) * Mont(b)
            { u29x9_mullo_karazuba(1, 0) }
            // hi lo inv261p
            // 0x100a85dd486e7773942750342fe7cc257f6121829ae1359536782df87d1b799c77
            { 0x100A85DD }
            { 0x90DCEEE }
            { 0xE509D40 }
            { 0x1A17F3E6 }
            { 0x257F612 }
            { 0x30535C2 }
            { 0xD654D9E }
            { 0x16FC3E8 }
            { 0x1B799C77 }
            // hi lo p⁻¹
            { u29x9_mullo_karazuba(1, 0) }
            // hi lo*p⁻¹
            // 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
            { 0x30644E }
            { 0xE5C2634 }
            { 0xA6E141 }
            { 0x2DB40C0 }
            { 0x1585D978 }
            { 0x2D522D0 }
            { 0x1C72A34F }
            { 0x10460B6 }
            { 0x187CFD47 }
            // hi lo*p⁻¹ p
            { u29x9_mulhi_karazuba(1, 0) }
            // hi lo*p⁻¹*p
            { 0x12bf1c02 } OP_EQUALVERIFY
            { 0x17b777a } OP_EQUALVERIFY
            { 0x14ac7b2b } OP_EQUALVERIFY
            { 0x163c642 } OP_EQUALVERIFY
            { 0x7b7b2a } OP_EQUALVERIFY
            { 0x15db34f1 } OP_EQUALVERIFY
            { 0xf4eb1d2 } OP_EQUALVERIFY
            { 0x16e7321e } OP_EQUALVERIFY
            { 0xe8746 } OP_EQUALVERIFY
            OP_TRUE
        };

        let exec_result = execute_script(script);
        if !exec_result.success {
            println!("ERROR: {:?} <---", exec_result.last_opcode)
        }
        assert!(exec_result.success);
    }
}
