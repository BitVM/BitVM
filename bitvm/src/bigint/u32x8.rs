
use crate::treepp::*;

// x₀ → (x₀+1)%2³²
pub fn u32_1add_nocarry() -> Script {
    script! {
        // ⋯ x₀
        OP_SIZE OP_5 OP_EQUAL
        // ⋯ x₀ x₀=2³¹
        OP_IF OP_DROP 0x7FFFFFFF OP_NEGATE
        // ⋯ 1-2³¹
        OP_ELSE OP_1ADD OP_ENDIF
        // ⋯ x₀+1
    }
}

// x₀ → (x₀+1)%2³² x₀=-1
pub fn u32_1add_carry() -> Script {
    script! {
        // ⋯ x₀
        OP_SIZE OP_5 OP_EQUAL
        // ⋯ x₀ x₀=2³¹
        OP_IF OP_DROP 0x7FFFFFFF OP_NEGATE
        // ⋯ 1-2³¹
        OP_ELSE OP_1ADD OP_ENDIF
        // ⋯ x₀+1
        OP_DUP OP_0 OP_EQUAL
        // ⋯ x₀+1 x₀=-1
    }
}

// 2³¹-1 x₀ x₁ → 2³¹-1 (x₀+x₁)%2³²
pub fn u32_add_nocarry() -> Script {
    script! {
        // ⋯ 2³¹-1 x₀ x₁
        OP_SIZE OP_5 OP_EQUAL
        // ⋯ 2³¹-1 x₀ x₁ x₁=2³¹
        OP_TUCK OP_IF
            // ⋯ 2³¹-1 x₀ x₁=2³¹ x₁
            OP_DROP OP_0
            // ⋯ 2³¹-1 x₀ x₁=2³¹ 0
        OP_ELSE
            // ⋯ 2³¹-1 x₀ x₁=2³¹ x₁
            OP_TUCK OP_GREATERTHAN
            // ⋯ 2³¹-1 x₀ x₁≥2³¹ x₁
            OP_TUCK OP_IF OP_3 OP_PICK OP_ADD OP_1ADD OP_ENDIF
            // ⋯ 2³¹-1 x₀ x₁≥2³¹ x₁[+2³¹]
        OP_ENDIF
        // ⋯ 2³¹-1 x₀ x₁≥2³¹ x₁[+2³¹]
        OP_ROT OP_SIZE OP_5 OP_EQUAL
        // ⋯ 2³¹-1 x₁≥2³¹ x₁[+2³¹] x₀ x₀=2³¹
        OP_TUCK OP_IF
            // ⋯ 2³¹-1 x₁≥2³¹ x₁[+2³¹] x₀=2³¹ x₀
            OP_DROP OP_0
            // ⋯ 2³¹-1 x₁≥2³¹ x₁[+2³¹] x₀=2³¹ 0
        OP_ELSE
            // ⋯ 2³¹-1 x₁≥2³¹ x₁[+2³¹] x₀=2³¹ x₀
            OP_TUCK OP_LESSTHAN
            // ⋯ 2³¹-1 x₁≥2³¹ x₁[+2³¹] x₀ x₀<2³¹
            OP_TUCK OP_IF OP_4 OP_PICK OP_SUB OP_1SUB OP_ENDIF
            // ⋯ 2³¹-1 x₁≥2³¹ x₁[+2³¹] x₀<2³¹ x₀[-2³¹]
        OP_ENDIF
        // ⋯ 2³¹-1 x₁≥2³¹ x₁[+2³¹] x₀≤2³¹ x₀[-2³¹]
        OP_ROT OP_ADD
        // ⋯ 2³¹-1 x₁≥2³¹ x₀≤2³¹ x₀+x₁[±2³¹]
        OP_ROT OP_ROT OP_NUMNOTEQUAL
        // ⋯ 2³¹-1 x₀+x₁[±2³¹] (x₀≤2³¹)≠(x₁≥2³¹)
        OP_IF //  x₀≤2³¹ ≠ x₁≥2³¹
            // ⋯ 2³¹-1 x₀+x₁[±2³¹]
            OP_2DUP OP_0 OP_LESSTHANOREQUAL
            // ⋯ 2³¹-1 x₀+x₁[±2³¹] x₀+x₁[±2³¹]≥2³¹
            OP_IF OP_ADD OP_1ADD OP_ELSE OP_SUB OP_1SUB OP_ENDIF
            // ⋯ 2³¹-1 (x₀+x₁)%2³²
        OP_ENDIF
        // ⋯ 2³¹-1 (x₀+x₁)%2³²
    }
}

// 2³¹-1 x₀ x₁ → 2³¹-1 (x₀+x₁)%2³² x₀+x₁≥2³²
pub fn u32_add_carry() -> Script {
    script! {
        // ⋯ 2³¹-1 x₀ x₁
        OP_SIZE OP_5 OP_EQUAL
        // ⋯ 2³¹-1 x₀ x₁ x₁=2³¹
        OP_TUCK OP_IF
            // ⋯ 2³¹-1 x₀ x₁=2³¹ x₁
            OP_DROP OP_0
            // ⋯ 2³¹-1 x₀ x₁=2³¹ 0
        OP_ELSE
            // ⋯ 2³¹-1 x₀ x₁=2³¹ x₁
            OP_TUCK OP_LESSTHAN
            // ⋯ 2³¹-1 x₀ x₁≥2³¹ x₁
            OP_TUCK OP_IF OP_3 OP_PICK OP_SUB OP_1SUB OP_ENDIF
            // ⋯ 2³¹-1 x₀ x₁≥2³¹ x₁[-2³¹]
        OP_ENDIF
        // ⋯ 2³¹-1 x₀ x₁≥2³¹ x₁[-2³¹]
        OP_ROT OP_SIZE OP_5 OP_EQUAL
        // ⋯ 2³¹-1 x₁≥2³¹ x₁[-2³¹] x₀ x₀=2³¹
        OP_TUCK OP_IF
            // ⋯ 2³¹-1 x₁≥2³¹ x₁[-2³¹] x₀=2³¹ x₀
            OP_DROP OP_0
            // ⋯ 2³¹-1 x₁≥2³¹ x₁[-2³¹] x₀=2³¹ 0
        OP_ELSE
            // ⋯ 2³¹-1 x₁≥2³¹ x₁[-2³¹] x₀=2³¹ x₀
            OP_TUCK OP_GREATERTHAN
            // ⋯ 2³¹-1 x₁≥2³¹ x₁[-2³¹] x₀ x₀<2³¹
            OP_TUCK OP_IF OP_4 OP_PICK OP_ADD OP_1ADD OP_ENDIF
            // ⋯ 2³¹-1 x₁≥2³¹ x₁[-2³¹] x₀<2³¹ x₀[+2³¹]
        OP_ENDIF
        // ⋯ 2³¹-1 x₁≥2³¹ x₁[-2³¹] x₀≤2³¹ x₀[+2³¹]
        OP_ROT OP_DUP OP_0NOTEQUAL OP_TOALTSTACK OP_ADD
        // ⋯ 2³¹-1 x₁≥2³¹ x₀≤2³¹ x₀+x₁[±2³¹] | x₁[-2³¹]≠0
        OP_DUP OP_2OVER OP_NUMNOTEQUAL OP_GREATERTHANOREQUAL
        // ⋯ 2³¹-1 x₁≥2³¹ x₀≤2³¹ x₀+x₁[±2³¹] x₀+x₁[±2³¹]≥(x₀≤2³¹)≠(x₁≥2³¹) | x₁[-2³¹]≠0
        OP_2SWAP OP_TUCK OP_NUMNOTEQUAL
        // ⋯ 2³¹-1 x₀+x₁[±2³¹] x₀+x₁[±2³¹]≥(x₀≤2³¹)≠(x₁≥2³¹) x₁≥2³¹ x₀≤2³¹ | x₁[-2³¹]≠0
        OP_FROMALTSTACK OP_SWAP
        // ⋯ 2³¹-1 x₀+x₁[±2³¹] x₀+x₁[±2³¹]≥(x₀≤2³¹)≠(x₁≥2³¹) x₁≥2³¹ x₁[-2³¹]≠0 x₀≤2³¹
        OP_IF // x₀ ≤ 2³¹
            // ⋯ 2³¹-1 x₀+x₁[±2³¹] x₀+x₁[±2³¹]≥(x₀≤2³¹)≠(x₁≥2³¹) x₁≥2³¹ x₁[-2³¹]≠0
            OP_BOOLAND
            // ⋯ 2³¹-1 x₀+x₁[±2³¹] x₀+x₁[±2³¹]≥(x₀≤2³¹)≠(x₁≥2³¹) x₁≥2³¹∧x₁[-2³¹]≠0
            OP_3 OP_PICK OP_2SWAP
            // ⋯ 2³¹-1 x₁≥2³¹∧x₁[-2³¹]≠0 2³¹-1 x₀+x₁[±2³¹] x₀+x₁[±2³¹]≥(x₀≤2³¹)≠(x₁≥2³¹)
            OP_IF // x₀+x₁[±2³¹] ≥ (x₀≤2³¹)≠(x₁≥2³¹)
                // ⋯ 2³¹-1 x₁≥2³¹∧x₁[-2³¹]≠0 2³¹-1 x₀+x₁[±2³¹]
                OP_1SUB OP_SWAP OP_SUB
                // ⋯ 2³¹-1 x₁≥2³¹∧x₁[-2³¹]≠0 x₀+x₁[±2³¹]-2³¹
            OP_ELSE
                // ⋯ 2³¹-1 x₁≥2³¹∧x₁[-2³¹]≠0 2³¹-1 x₀+x₁[±2³¹]
                OP_1ADD OP_ADD
                // ⋯ 2³¹-1 x₁≥2³¹∧x₁[-2³¹]≠0 x₀+x₁[±2³¹]+2³¹
            OP_ENDIF
            // ⋯ 2³¹-1 x₀+x₁≥2³² (x₀+x₁)%2³²
            OP_SWAP
            // ⋯ 2³¹-1 (x₀+x₁)%2³² x₀+x₁≥2³²
        OP_ELSE // x₁[-2³¹] = 0
            // ⋯ 2³¹-1 x₀+x₁[±2³¹] x₀+x₁[±2³¹]≥(x₀≤2³¹)≠(x₁≥2³¹) x₁≥2³¹ x₁[-2³¹]≠0
            OP_BOOLOR OP_BOOLAND
            // ⋯ 2³¹-1 x₀+x₁[±2³¹] x₀+x₁[±2³¹]≥(x₀≤2³¹)≠(x₁≥2³¹)∨x₁≥2³¹∧x₁[-2³¹]≠0
        OP_ENDIF
        // ⋯ 2³¹-1 (x₀+x₁)%2³² x₀+x₁≥2³²
    }
}

// 2³¹-1 x₀ x₁ → 2³¹-1 (x₀-x₁)%2³²
pub fn u32_sub_noborrow() -> Script {
    script! {
        // ⋯ 2³¹-1 x₀ x₁
        OP_SIZE OP_5 OP_EQUAL
        // ⋯ 2³¹-1 x₀ x₁ x₁=2³¹
        OP_TUCK OP_IF
            // ⋯ 2³¹-1 x₀ x₁=2³¹ x₁
            OP_DROP OP_0
            // ⋯ 2³¹-1 x₀ x₁=2³¹ 0
        OP_ELSE
            // ⋯ 2³¹-1 x₀ x₁=2³¹ x₁
            OP_TUCK OP_GREATERTHAN
            // ⋯ 2³¹-1 x₀ x₁≥2³¹ x₁
            OP_TUCK OP_IF OP_3 OP_PICK OP_ADD OP_1ADD OP_ENDIF
            // ⋯ 2³¹-1 x₀ x₁≥2³¹ x₁[+2³¹]
        OP_ENDIF
        // ⋯ 2³¹-1 x₀ x₁≥2³¹ x₁[+2³¹]
        OP_ROT OP_SIZE OP_5 OP_EQUAL
        // ⋯ 2³¹-1 x₁≥2³¹ x₁[+2³¹] x₀ x₀=2³¹
        OP_TUCK OP_IF
            // ⋯ 2³¹-1 x₁≥2³¹ x₁[+2³¹] x₀=2³¹ x₀
            OP_DROP OP_0
            // ⋯ 2³¹-1 x₁≥2³¹ x₁[+2³¹] x₀=2³¹ 0
        OP_ELSE
            // ⋯ 2³¹-1 x₁≥2³¹ x₁[+2³¹] x₀=2³¹ x₀
            OP_TUCK OP_LESSTHAN
            // ⋯ 2³¹-1 x₁≥2³¹ x₁[+2³¹] x₀ x₀<2³¹
            OP_TUCK OP_IF OP_4 OP_PICK OP_SUB OP_1SUB OP_ENDIF
            // ⋯ 2³¹-1 x₁≥2³¹ x₁[+2³¹] x₀<2³¹ x₀[-2³¹]
        OP_ENDIF
        // ⋯ 2³¹-1 x₁≥2³¹ x₁[+2³¹] x₀≤2³¹ x₀[-2³¹]
        OP_ROT OP_SUB
        // ⋯ 2³¹-1 x₁≥2³¹ x₀≤2³¹ x₀+x₁[±2³¹]
        OP_ROT OP_ROT OP_NUMNOTEQUAL
        // ⋯ 2³¹-1 x₀+x₁[±2³¹] (x₀≤2³¹)≠(x₁≥2³¹)
        OP_IF //  x₀≤2³¹ ≠ x₁≥2³¹
            // ⋯ 2³¹-1 x₀+x₁[±2³¹]
            OP_2DUP OP_0 OP_LESSTHANOREQUAL
            // ⋯ 2³¹-1 x₀+x₁[±2³¹] x₀+x₁[±2³¹]≥2³¹
            OP_IF OP_ADD OP_1ADD OP_ELSE OP_SUB OP_1SUB OP_ENDIF
            // ⋯ 2³¹-1 (x₀+x₁)%2³²
        OP_ENDIF
        // ⋯ 2³¹-1 (x₀+x₁)%2³²
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_1add_nocarry() {
        println!("u32_1add_nocarry: {} bytes", u32_1add_nocarry().len());
        run(script! {
            0 u32_1add_nocarry 1 OP_EQUALVERIFY // 0 + 1 ⩵ 1 mod 2³²
            0x7FFFFFFF u32_1add_nocarry 0x80000000 OP_EQUALVERIFY // 2³¹-1 + 1 ⩵ 1 mod 2³²
            0x80000000 u32_1add_nocarry 0x7FFFFFFF OP_NEGATE OP_EQUALVERIFY // 2³¹ + 1 ⩵ 2³¹+1 mod 2³²
            0x7FFFFFFF OP_NEGATE u32_1add_nocarry 0x7FFFFFFE OP_NEGATE OP_EQUALVERIFY // 2³¹+1 + 1 ⩵ 2³¹+2 mod 2³²
            1 OP_NEGATE u32_1add_nocarry 0 OP_EQUALVERIFY // 2³²-1 + 1 ⩵ 0 mod 2³²
            OP_TRUE
        })
    }
    #[test]
    fn test_1add_carry() {
        println!("u32_1add_carry: {} bytes", u32_1add_carry().len());
        run(script! {
            0 u32_1add_carry 0 OP_EQUALVERIFY 1 OP_EQUALVERIFY // 0 + 1 ⩵ 1 mod 2³²
            0x7FFFFFFF u32_1add_carry 0 OP_EQUALVERIFY 0x80000000 OP_EQUALVERIFY // 2³¹-1 + 1 ⩵ 2³¹ mod 2³²
            0x7FFFFFFF OP_NEGATE u32_1add_carry 0 OP_EQUALVERIFY 0x7FFFFFFE OP_NEGATE OP_EQUALVERIFY
            1 OP_NEGATE u32_1add_carry 1 OP_EQUALVERIFY 0 OP_EQUALVERIFY // 2³²-1 + 1 ⩵ 0 mod 2³²
            OP_TRUE
        })
    }
    #[test]
    fn test_add_nocarry() {
        println!("u32_add_nocarry: {} bytes", u32_add_nocarry().len());
        run(script! { 0x7FFFFFFF
            0 0 u32_add_nocarry 0 OP_EQUALVERIFY // 0 + 0 ⩵ 0 mod 2³²
            1 0 u32_add_nocarry 1 OP_EQUALVERIFY // 1 + 0 ⩵ 1 mod 2³²
            0 1 u32_add_nocarry 1 OP_EQUALVERIFY // 0 + 1 ⩵ 1 mod 2³²
            1 1 u32_add_nocarry 2 OP_EQUALVERIFY // 1 + 1 ⩵ 2 mod 2³²
            0x40000000 OP_DUP u32_add_nocarry 0x80000000 OP_EQUALVERIFY // 2³⁰ + 2³⁰ ⩵ 2³¹ mod 2³²
            0 0x80000000 u32_add_nocarry 0x80000000 OP_EQUALVERIFY // 0 + 2³¹ ⩵ 2³¹ mod 2³²
            0x80000000 0 u32_add_nocarry 0x80000000 OP_EQUALVERIFY // 2³¹ + 0 ⩵ 2³¹ mod 2³²
            0x80000000 OP_DUP u32_add_nocarry 0 OP_EQUALVERIFY // 2³¹ + 2³¹ ⩵ 0 mod 2³²
            1 OP_NEGATE 1 u32_add_nocarry 0 OP_EQUALVERIFY // 2³²-1 + 1 ⩵ 0 mod 2³²
            1 OP_NEGATE OP_DUP u32_add_nocarry 2 OP_NEGATE OP_EQUALVERIFY // 2³²-1 + 2³²-1 ⩵ 2³²-2 mod 2³²
            0x7FFFFFFF OP_NEGATE 0x80000000 u32_add_nocarry 1 OP_EQUALVERIFY // 2³¹+1 + 2³¹ = 1 mod 2³²
        })
    }
    #[test]
    fn test_sub_noborrow() {
        println!("u32_sub_noborrow: {} bytes", u32_sub_noborrow().len());
        run(script! { 0x7FFFFFFF
            0 0 u32_sub_noborrow 0 OP_EQUALVERIFY // 0 - 0 ⩵ 0 mod 2³²
            1 0 u32_sub_noborrow 1 OP_EQUALVERIFY // 1 - 0 ⩵ 1 mod 2³²
            0 1 u32_sub_noborrow 1 OP_NEGATE OP_EQUALVERIFY // 0 - 1 ⩵ 2³²-1 mod 2³²
            1 1 u32_sub_noborrow 0 OP_EQUALVERIFY // 1 - 1 ⩵ 0 mod 2³²
            0x40000000 OP_DUP u32_sub_noborrow 0 OP_EQUALVERIFY // 2³⁰ - 2³⁰ ⩵ 0 mod 2³²
            0 0x80000000 u32_sub_noborrow 0x80000000 OP_EQUALVERIFY // 0 - 2³¹ ⩵ 2³¹ mod 2³²
            0x80000000 0 u32_sub_noborrow 0x80000000 OP_EQUALVERIFY // 2³¹ - 0 ⩵ 2³¹ mod 2³²
            0x80000000 OP_DUP u32_sub_noborrow 0 OP_EQUALVERIFY // 2³¹ - 2³¹ ⩵ 0 mod 2³²
            1 OP_NEGATE 1 u32_sub_noborrow 2 OP_NEGATE OP_EQUALVERIFY // 2³²-1 - 1 ⩵ 2³²-2 mod 2³²
            1 OP_NEGATE OP_DUP u32_sub_noborrow 0 OP_EQUALVERIFY // 2³²-1 - 2³²-1 ⩵ 0 mod 2³²
            0x7FFFFFFF OP_NEGATE 0x80000000 u32_sub_noborrow 1 OP_EQUALVERIFY // 2³¹+1 - 2³¹ = 1 mod 2³²
        })
    }
    #[test]
    fn test_add_carry() {
        println!("u32_add_carry: {} bytes", u32_add_carry().len());
        run(script! { 0x7FFFFFFF
            0 0 u32_add_carry 0 OP_EQUALVERIFY 0 OP_EQUALVERIFY // 0 + 0 ⩵ 0 mod 2³²
            1 0 u32_add_carry 0 OP_EQUALVERIFY 1 OP_EQUALVERIFY // 1 + 0 ⩵ 1 mod 2³²
            0 1 u32_add_carry 0 OP_EQUALVERIFY 1 OP_EQUALVERIFY // 0 + 1 ⩵ 1 mod 2³²
            1 1 u32_add_carry 0 OP_EQUALVERIFY 2 OP_EQUALVERIFY // 1 + 1 ⩵ 2 mod 2³²
            0x40000000 OP_DUP u32_add_carry 0 OP_EQUALVERIFY 0x80000000 OP_EQUALVERIFY // 2³⁰ + 2³⁰ ⩵ 2³¹ mod 2³²
            OP_0 0x80000000 u32_add_carry 0 OP_EQUALVERIFY 0x80000000 OP_EQUALVERIFY // 0 + 2³¹ ⩵ 2³¹ mod 2³²
            0x80000000 OP_0 u32_add_carry 0 OP_EQUALVERIFY 0x80000000 OP_EQUALVERIFY // 2³¹ + 0 ⩵ 2³¹ mod 2³²
            0x80000000 OP_DUP u32_add_carry 1 OP_EQUALVERIFY 0 OP_EQUALVERIFY // 2³¹ + 2³¹ ⩵ 0 mod 2³²
            1 OP_NEGATE 1 u32_add_carry 1 OP_EQUALVERIFY 0 OP_EQUALVERIFY // 2³²-1 + 1 ⩵ 0 mod 2³²
            1 OP_NEGATE OP_DUP u32_add_carry 1 OP_EQUALVERIFY 2 OP_NEGATE OP_EQUALVERIFY // 2³²-1 + 2³²-1 ⩵ 2³²-2 mod 2³²
            0x7FFFFFFF OP_NEGATE 0x80000000 u32_add_carry 1 OP_EQUALVERIFY 1 OP_EQUALVERIFY // 2³¹+1 + 2³¹ = 1 mod 2³²
        })
    }
}
