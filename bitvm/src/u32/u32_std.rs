use crate::pseudo::{push_to_stack, OP_256MUL, OP_4DUP};

use crate::treepp::{script, Script};

/// Pushes a value as u32 element onto the stack
pub fn u32_push(value: u32) -> Script {
    script! {
        //optimization
        if (value >> 24 & 0xff) == (value >> 16 & 0xff) &&
            (value >> 24 & 0xff) == (value >> 8 & 0xff) &&
            (value >> 24 & 0xff) == (value & 0xff) {

                { push_to_stack((value >> 24 & 0xff) as usize, 4) }
        }
        else{

                {value >> 24 & 0xff}
                {value >> 16 & 0xff}
                {value >>  8 & 0xff}
                {value & 0xff}
        }
    }
}

/// Marks transaction as invalid if the top two stack value are not equal
pub fn u32_equalverify() -> Script {
    script! {
        4
        OP_ROLL
        OP_EQUALVERIFY
        3
        OP_ROLL
        OP_EQUALVERIFY
        OP_ROT
        OP_EQUALVERIFY
        OP_EQUALVERIFY
    }
}
/// Returns 1 if the top two u32 are equal, 0 otherwise
pub fn u32_equal() -> Script {
    script! {
        4
        OP_ROLL
        OP_EQUAL OP_TOALTSTACK
        3
        OP_ROLL
        OP_EQUAL OP_TOALTSTACK
        OP_ROT
        OP_EQUAL OP_TOALTSTACK
        OP_EQUAL
        OP_FROMALTSTACK OP_BOOLAND
        OP_FROMALTSTACK OP_BOOLAND
        OP_FROMALTSTACK OP_BOOLAND
    }
}

/// Returns 1 if the top two u32 are not equal, 0 otherwise
pub fn u32_notequal() -> Script {
    script! {
        4
        OP_ROLL
        OP_NUMNOTEQUAL OP_TOALTSTACK
        3
        OP_ROLL
        OP_NUMNOTEQUAL OP_TOALTSTACK
        OP_ROT
        OP_NUMNOTEQUAL OP_TOALTSTACK
        OP_NUMNOTEQUAL
        OP_FROMALTSTACK OP_BOOLOR
        OP_FROMALTSTACK OP_BOOLOR
        OP_FROMALTSTACK OP_BOOLOR
    }
}

/// Puts the top u32 element onto the top of the alt stack. Removes it from the main stack.
pub fn u32_toaltstack() -> Script {
    script! {
        OP_TOALTSTACK
        OP_TOALTSTACK
        OP_TOALTSTACK
        OP_TOALTSTACK
    }
}

/// Puts the top u32 element of the alt stack onto the top of the main stack. Removes it from the alt stack.
pub fn u32_fromaltstack() -> Script {
    script! {
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_FROMALTSTACK
    }
}

/// Duplicates the top u32 stack element
pub fn u32_dup() -> Script {
    script! { OP_4DUP }
}

/// Removes the top u32 element from the stack.
pub fn u32_drop() -> Script {
    script! {
        OP_2DROP
        OP_2DROP
    }
}

/// The u32 element n back in the stack is moved to the top.
pub fn u32_roll(n: u32) -> Script {
    let n = (n + 1) * 4 - 1;
    script! {
        {n} OP_ROLL
        {n} OP_ROLL
        {n} OP_ROLL
        {n} OP_ROLL
    }
}

/// The u32 element n back in the stack is copied to the top.
pub fn u32_pick(n: u32) -> Script {
    let n = (n + 1) * 4 - 1;
    script! {
        {n} OP_PICK
        {n} OP_PICK
        {n} OP_PICK
        {n} OP_PICK
    }
}

// X₃₁…₂₄ X₂₃…₁₆ X₁₅…₉ X₈…₀ → X₃₁…₀
/// The top u32 element is compressed into a single 4-byte word
pub fn u32_compress() -> Script {
    script! {
        // ⋯ X₃₁…₂₄ X₂₃…₁₆ X₁₅…₈ X₇…₀
        OP_SWAP OP_2SWAP OP_SWAP
        // ⋯ X₇…₀ X₁₅…₈ X₂₃…₁₆ X₃₁…₂₄
        0x80
        // ⋯ X₇…₀ X₁₅…₈ X₂₃…₁₆ X₃₁…₂₄ 2⁸
        OP_2DUP OP_GREATERTHANOREQUAL
        // ⋯ X₇…₀ X₁₅…₈ X₂₃…₁₆ X₃₁…₂₄ 2⁸ X₃₁
        OP_DUP OP_TOALTSTACK
        // ⋯ X₇…₀ X₁₅…₈ X₂₃…₁₆ X₃₁…₂₄ 2⁸ X₃₁ | X₃₁
        OP_IF OP_SUB OP_ELSE OP_DROP OP_ENDIF
        // ⋯ X₇…₀ X₁₅…₈ X₂₃…₁₆ X₃₀…₂₄
        OP_256MUL OP_ADD
        // ⋯ X₇…₀ X₁₅…₈ X₃₀…₁₆
        OP_256MUL OP_ADD
        // ⋯ X₇…₀ X₃₀…₈
        OP_256MUL OP_ADD
        // ⋯ X₃₀…₀ | X₃₁
        OP_FROMALTSTACK
        // ⋯ X₃₀…₀ X₃₁
        OP_IF 0x7FFFFFFF OP_SUB OP_1SUB OP_ENDIF
        // ⋯ X₃₁…₀
    }
}

// X₃₁…₀ → X₃₁…₂₄ X₂₃…₁₆ X₁₅…₉ X₈…₀
pub fn u32_uncompress() -> Script {
    script! {
        // ⋯ X₃₁…₀
        OP_SIZE OP_5 OP_EQUAL
        // ⋯ X₃₁…₀ X₃₁…₀=2³¹
        OP_TUCK OP_IF // X₃₁…₀ = 2³¹
            // ⋯ X₃₁…₀=2³¹ X₃₁…₀
            OP_DROP OP_0
            // ⋯ X₃₁ X₃₀…₀
        OP_ELSE // X₃₁…₀ ≠ 2³¹
            // ⋯ X₃₁…₀=2³¹ X₃₁…₀
            OP_TUCK OP_GREATERTHAN
            // ⋯ X₃₁…₀ X₃₁
            OP_TUCK OP_IF 0x7FFFFFFF OP_ADD OP_1ADD OP_ENDIF
            // ⋯ X₃₁ X₃₀…₀
        OP_ENDIF
        // ⋯ X₃₁ X₃₀…₀
        OP_SWAP OP_TOALTSTACK
        // ⋯ X₃₀…₀ | X₃₁
        for i in 1..8 {
            // ⋯ X₃₀…₀
            { 1 << (31 - i) } OP_2DUP OP_GREATERTHANOREQUAL
            // ⋯ X₃₀…₀ 2³⁰ X₃₀
            OP_FROMALTSTACK OP_DUP OP_ADD OP_OVER OP_ADD OP_TOALTSTACK
            // ⋯ X₃₀…₀ 2³⁰ X₃₀ | X₃₁…₃₀
            OP_IF OP_SUB OP_ELSE OP_DROP OP_ENDIF
            // ⋯ X₂₉…₀ | X₃₁…₃₀
        }
        // ⋯ X₂₉…₀ | X₃₁…₃₀
        // ⋯ X₂₈…₀ | X₃₁…₂₉
        // ⋯ X₂₇…₀ | X₃₁…₂₈
        // ⋯ X₂₆…₀ | X₃₁…₂₇
        // ⋯ X₂₅…₀ | X₃₁…₂₆
        // ⋯ X₂₄…₀ | X₃₁…₂₅
        // ⋯ X₂₃…₀ | X₃₁…₂₄
        { 1 << 23 } OP_2DUP OP_GREATERTHANOREQUAL OP_DUP OP_TOALTSTACK
        // ⋯ X₂₃…₀ 2²³ X₂₃ | X₂₃ ⋯
        OP_IF OP_SUB OP_ELSE OP_DROP OP_ENDIF
        // ⋯ X₂₂…₀ | X₂₃ ⋯
        for i in 1..8 {
            // ⋯ X₂₂…₀
            { 1 << (23 - i) } OP_2DUP OP_GREATERTHANOREQUAL
            // ⋯ X₂₂…₀ 2²² X₂₂
            OP_FROMALTSTACK OP_DUP OP_ADD OP_OVER OP_ADD OP_TOALTSTACK
            // ⋯ X₂₂…₀ 2²² X₂₂ | X₂₃…₂₂ ⋯
            OP_IF OP_SUB OP_ELSE OP_DROP OP_ENDIF
            // ⋯ X₂₁…₀ | X₂₃…₂₂ ⋯
        }
        // ⋯ X₂₁…₀ | X₂₃…₂₂ X₃₁…₂₄
        // ⋯ X₂₀…₀ | X₂₃…₂₁ X₃₁…₂₄
        // ⋯ X₁₉…₀ | X₂₃…₂₀ X₃₁…₂₄
        // ⋯ X₁₈…₀ | X₂₃…₁₉ X₃₁…₂₄
        // ⋯ X₁₇…₀ | X₂₃…₁₈ X₃₁…₂₄
        // ⋯ X₁₆…₀ | X₂₃…₁₇ X₃₁…₂₄
        // ⋯ X₁₅…₀ | X₂₃…₁₆ X₃₁…₂₄
        { 1 << 15 } OP_2DUP OP_GREATERTHANOREQUAL OP_DUP OP_TOALTSTACK
        // ⋯ X₁₅…₀ 2¹⁵ X₁₅ | X₁₅ ⋯
        OP_IF OP_SUB OP_ELSE OP_DROP OP_ENDIF
        // ⋯ X₁₄…₀ | X₁₅ ⋯
        for i in 1..8 {
            // ⋯ X₁₄…₀
            { 1 << (15 - i) } OP_2DUP OP_GREATERTHANOREQUAL
            // ⋯ X₁₄…₀ 2¹⁴ X₁₄
            OP_FROMALTSTACK OP_DUP OP_ADD OP_OVER OP_ADD OP_TOALTSTACK
            // ⋯ X₁₄…₀ 2¹⁴ X₁₄ | X₁₅…₁₄ ⋯
            OP_IF OP_SUB OP_ELSE OP_DROP OP_ENDIF
            // ⋯ X₁₃…₀ | X₁₅…₁₄ ⋯
        }
        // ⋯ X₁₃…₀ | X₁₅…₁₄ ⋯
        // ⋯ X₁₂…₀ | X₁₅…₁₃ ⋯
        // ⋯ X₁₁…₀ | X₁₅…₁₂ ⋯
        // ⋯ X₁₀…₀ | X₁₅…₁₁ ⋯
        // ⋯ X₉…₀ | X₁₅…₁₀ ⋯
        // ⋯ X₈…₀ | X₁₅…₉ X₂₃…₁₆ X₃₁…₂₄
        OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK
        // ⋯ X₈…₀ X₁₅…₉ X₂₃…₁₆ X₃₁…₂₄
        OP_SWAP OP_2SWAP OP_SWAP
        // ⋯ X₃₁…₂₄ X₂₃…₁₆ X₁₅…₉ X₈…₀
    }
}

#[cfg(test)]
mod test {

    use crate::run;
    use crate::treepp::script;
    use crate::u32::u32_std::*;
    use rand::Rng;

    #[test]
    fn test_u32_push() {
        let script = script! {
            { u32_push(0x01020304) }
            0x04
            OP_EQUALVERIFY
            0x03
            OP_EQUALVERIFY
            0x02
            OP_EQUALVERIFY
            0x01
            OP_EQUAL
        };
        run(script);
    }

    #[test]
    fn test_with_u32_compress() {
        let mut rng = rand::thread_rng();

        for _ in 0..30 {
            let mut origin_value0: u32 = rng.gen();
            origin_value0 = (origin_value0 % 1) << 31;
            let mut origin_value1: u32 = rng.gen();
            origin_value1 = (origin_value1 % 1) << 31;

            let v = origin_value0 + origin_value1;

            let script = script! {
                { u32_push(origin_value0)}
                { u32_compress()}
                { u32_push(origin_value1)}
                { u32_compress()}
                OP_ADD
                { u32_push(v)}
                { u32_compress()}
                OP_EQUAL

            };

            run(script);
        }
    }

    #[test]
    fn test_uncompress() {
        println!("u32_uncompress: {} bytes", u32_uncompress().len());
        run(script! {
            0x7FFFFFFF           u32_uncompress 0xFF OP_EQUALVERIFY 0xFF OP_EQUALVERIFY 0xFF OP_EQUALVERIFY 0x7F OP_EQUALVERIFY // 2³¹-1
            0x7FFFFFFF OP_NEGATE u32_uncompress OP_1 OP_EQUALVERIFY OP_0 OP_EQUALVERIFY OP_0 OP_EQUALVERIFY 0x80 OP_EQUALVERIFY // 2³¹+1
            0x00000001 OP_NEGATE u32_uncompress 0xFF OP_EQUALVERIFY 0xFF OP_EQUALVERIFY 0xFF OP_EQUALVERIFY 0xFF OP_EQUALVERIFY // 2³²-1
            0x80000000           u32_uncompress OP_0 OP_EQUALVERIFY OP_0 OP_EQUALVERIFY OP_0 OP_EQUALVERIFY 0x80 OP_EQUALVERIFY // 2³¹
            0x00000000           u32_uncompress OP_0 OP_EQUALVERIFY OP_0 OP_EQUALVERIFY OP_0 OP_EQUALVERIFY OP_0 OP_EQUAL // 0
        })
    }

    #[test]
    fn test_compress() {
        println!("u32_compress: {} bytes", u32_compress().len());
        run(script! {
            0x7F 0xFF 0xFF 0xFF u32_compress 0x7FFFFFFF           OP_EQUALVERIFY // 2³¹-1
            0x80 OP_0 OP_0 OP_1 u32_compress 0x7FFFFFFF OP_NEGATE OP_EQUALVERIFY // 2³¹+1
            0xFF 0xFF 0xFF 0xFF u32_compress 0x00000001 OP_NEGATE OP_EQUALVERIFY // 2³²-1
            0x80 OP_0 OP_0 OP_0 u32_compress 0x7FFFFFFF OP_NEGATE OP_1SUB OP_EQUALVERIFY // -2³¹
            OP_0 OP_0 OP_0 OP_0 u32_compress 0x00000000           OP_EQUAL // -2³¹
        })
    }
}
