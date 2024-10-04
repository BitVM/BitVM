use crate::treepp::*;

const UNSIGNED: bool = true;
const SIGNED: bool = false;

// X₃₁…₀ → [!]X₃₁ X₃₀…₀[-2³¹] „Aufblasen“
fn u32_inflate(unsigned: bool) -> Script {
    script! {
        // X₃₁…₀
        OP_DUP 0x80000000 OP_EQUAL
        // X₃₁…₀ X₃₁…₀⩵2³¹
        OP_IF
            // X₃₁…₀
            OP_DROP 1 0
            // X₃₁ X₃₀…₀
        OP_ELSE
            if unsigned {
                // X₃₁…₀
                OP_DUP 0 OP_LESSTHAN
                // X₃₁…₀ X₃₁
                OP_TUCK
                // X₃₁ X₃₁…₀ X₃₁≥2³¹
                OP_IF
                    // X₃₁ X₃₁…₀
                    OP_1ADD 0x7FFFFFFF OP_ADD
                    // X₃₁ X₃₀…₀
                OP_ENDIF
            } else {
                // X₃₁…₀
                OP_DUP 0 OP_GREATERTHAN
                // X₃₁…₀ [!]X₃₁
                OP_TUCK
                // [!]X₃₁ X₃₁…₀ [!]X₃₁
                OP_IF
                    // [!]X₃₁ X₃₁…₀
                    OP_1SUB 0x7FFFFFFF OP_SUB
                    // [!]X₃₁ X₃₀…₀[-2³¹]
                OP_ENDIF
            }
            // [!]X₃₁ X₃₀…₀[-2³¹]
        OP_ENDIF
    }
}

// [!]X₃₁ X₃₀…₀[-2³¹] → X₃₁…₀ „die Luft herauslassen“
fn u32_deflate() -> Script {
    script! {
        // [!]X₃₁ X₃₀…₀[-2³¹]
        OP_TUCK OP_0NOTEQUAL
        // X₃₀…₀[-2³¹] [!]X₃₁ X₃₀…₀[-2³¹]≠0
        OP_IF
            // X₃₀…₀[-2³¹] [!]X₃₁
            OP_IF
                // X₃₀…₀[-2³¹]
                0x7FFFFFFF
                // X₃₀…₀[-2³¹] 2³¹-1
                OP_OVER OP_0 OP_LESSTHAN
                // X₃₀…₀[-2³¹] 2³¹-1 X₃₀…₀[-2³¹]<0
                OP_IF
                    // X₃₀…₀[-2³¹] 2³¹-1
                    OP_ADD OP_1ADD
                    // X₃₀…₀[-2³¹]+(2³¹-1)
                OP_ELSE
                    // X₃₀…₀[-2³¹] 2³¹-1
                    OP_SUB OP_1SUB
                    // X₃₀…₀[-2³¹]-(2³¹-1)
                OP_ENDIF
                // X₃₁…₀
            OP_ENDIF
            // X₃₁…₀
        OP_ELSE
            // X₃₀…₀[-2³¹] [!]X₃₁
            OP_NIP
            // [!]X₃₁
            OP_IF 0x80000000 OP_ELSE 0 OP_ENDIF 
            // [!]X₃₁⋅2³¹
        OP_ENDIF
        // X₃₁…₀
    }
}

// A₃₁…₀ B₃₁…₀ → [A₃₁…₀+B₃₁…₀]₃₂ [A₃₁…₀+B₃₁…₀]₃₁…₀
pub fn u32_add_carry() -> Script {
    script! {
        // A₃₁…₀ B₃₁…₀
        OP_OVER 0x80000000 OP_EQUAL
        // A₃₁…₀ B₃₁…₀ A₃₁…₀⩵2³¹
        OP_IF OP_SWAP OP_ENDIF
        // A₃₁…₀ B₃₁…₀
        OP_2DUP 0x80000000 OP_EQUAL OP_SWAP 0x80000000 OP_EQUAL OP_BOOLAND
        // A₃₁…₀ B₃₁…₀ A₃₁…₀⩵2³¹&&B₃₁…₀⩵2³¹
        OP_IF
            // A₃₁…₀ B₃₁…₀
            OP_2DROP 1 0
            // [A₃₁…₀+B₃₁…₀]₃₂ [A₃₁…₀+B₃₁…₀]₃₁…₀
        OP_ELSE
            // A₃₁…₀ B₃₁…₀
            { u32_inflate(SIGNED) } OP_ROT
            // [!]B₃₁ B₃₀…₀[-2³¹] A₃₁…₀
            { u32_inflate(UNSIGNED) } OP_ROT
            // [!]B₃₁ A₃₁ A₃₀…₀ B₃₀…₀[-2³¹]
            OP_ADD OP_ROT OP_ROT
            // A₃₀…₀+B₃₀…₀[-2³¹] [!]B₃₁ A₃₁
            OP_2DUP OP_LESSTHAN OP_ROT OP_ROT
            // A₃₀…₀+B₃₀…₀[-2³¹] A₃₁>[!]B₃₁ [!]B₃₁ A₃₁
            OP_2DUP OP_NUMNOTEQUAL OP_ROT OP_ROT
            // A₃₀…₀+B₃₀…₀[-2³¹] A₃₁>[!]B₃₁ [!]B₃₁≠A₃₁ [!]B₃₁ A₃₁
            OP_NUMEQUAL 3 OP_PICK 0 OP_LESSTHAN
            // A₃₀…₀+B₃₀…₀[-2³¹] A₃₁>[!]B₃₁ [!]B₃₁≠A₃₁ [!]B₃₁⩵A₃₁ A₃₀…₀+B₃₀…₀[-2³¹]<0
            OP_BOOLAND OP_ROT OP_BOOLOR
            // A₃₀…₀+B₃₀…₀[-2³¹] [!]B₃₁≠A₃₁ A₃₁>[!]B₃₁||[!]B₃₁⩵A₃₁&&(A₃₀…₀+B₃₀…₀[-2³¹]<0)
            OP_ROT OP_ROT OP_SWAP u32_deflate
            // A₃₁>[!]B₃₁||[!]B₃₁⩵A₃₁&&(A₃₀…₀+B₃₀…₀[-2³¹]<0) [A₃₁…₀+B₃₁…₀]₃₁…₀
        OP_ENDIF
    }
}

// A₃₁…₀ B₃₁…₀ → [A₃₁…₀+B₃₁…₀]₃₁…₀
pub fn u32_add_nocarry() -> Script {
    script! {
        // A₃₁…₀ B₃₁…₀
        { u32_inflate(SIGNED) } OP_SWAP OP_ROT
        // B₃₀…₀[-2³¹] [!]B₃₁ A₃₁…₀
        { u32_inflate(UNSIGNED) } OP_ROT OP_ROT
        // B₃₀…₀[-2³¹] A₃₀…₀ [!]B₃₁ A₃₁
        OP_NUMNOTEQUAL OP_ROT OP_ROT
        // [!]B₃₁≠A₃₁ B₃₀…₀[-2³¹] A₃₀…₀
        OP_ADD
        // [!]B₃₁≠A₃₁ A₃₀…₀+B₃₀…₀[-2³¹]
        u32_deflate
        // [A₃₁…₀+B₃₁…₀]₃₁…₀
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_inflate() {
        println!("u32_inflate(UNSIGNED): {} bytes", u32_inflate(UNSIGNED).len());
        run(script! { 0x00000000 { u32_inflate(UNSIGNED) } 0x00000000 OP_EQUALVERIFY 0 OP_NUMEQUAL }); // 0x00000000
        run(script! { 0x7FFFFFFF { u32_inflate(UNSIGNED) } 0x7FFFFFFF OP_EQUALVERIFY 0 OP_NUMEQUAL }); // 0x7FFFFFFF
        run(script! { 0x80000000 { u32_inflate(UNSIGNED) } 0x00000000 OP_EQUALVERIFY 1 OP_NUMEQUAL }); // 0x80000000
        run(script! { 0x7FFFFFFF OP_NEGATE { u32_inflate(UNSIGNED) } 1 OP_EQUALVERIFY 1 OP_NUMEQUAL }); // 0x80000001
        run(script! { 1 OP_NEGATE { u32_inflate(UNSIGNED) } 0x7FFFFFFF OP_EQUALVERIFY 1 OP_NUMEQUAL }); // 0xFFFFFFFF
        println!("u32_inflate(SIGNED): {} bytes", u32_inflate(SIGNED).len());
        run(script! { 0x00000000 { u32_inflate(SIGNED) } 0x00000000 OP_EQUALVERIFY 0 OP_NUMEQUAL }); // 0x00000000
        run(script! { 0x7FFFFFFF { u32_inflate(SIGNED) } 1 OP_NEGATE OP_EQUALVERIFY 1 OP_NUMEQUAL }); // 0x7FFFFFFF
        run(script! { 0x80000000 { u32_inflate(SIGNED) } 0x00000000 OP_EQUALVERIFY 1 OP_NUMEQUAL }); // 0x80000000
        run(script! { 0x7FFFFFFF OP_NEGATE { u32_inflate(SIGNED) } 0x7FFFFFFF OP_NEGATE OP_EQUALVERIFY 0 OP_NUMEQUAL }); // 0x80000001
        run(script! { 1 OP_NEGATE { u32_inflate(SIGNED) } 1 OP_NEGATE OP_EQUALVERIFY 0 OP_NUMEQUAL }); // 0xFFFFFFFF
    }
    #[test]
    fn test_deflate() {
        println!("u32_deflate: {} bytes", u32_deflate().len());
        run(script! { 0 0x00000000 u32_deflate 0x00000000 OP_EQUAL }); // 0x00000000
        run(script! { 0 0x7FFFFFFF u32_deflate 0x7FFFFFFF OP_EQUAL }); // 0x7FFFFFFF unsigned form
        run(script! { 1 1 OP_NEGATE u32_deflate 0x7FFFFFFF OP_EQUAL }); // 0x7FFFFFFF signed form
        run(script! { 1 0x00000000 u32_deflate 0x80000000 OP_EQUAL }); // 0x80000000
        run(script! { 1 1 u32_deflate 0x7FFFFFFF OP_NEGATE OP_EQUAL }); // 0x80000001 unsigned form
        run(script! { 0 0x7FFFFFFF OP_NEGATE OP_TUCK u32_deflate OP_EQUAL }); // 0x80000001 signed form
        run(script! { 1 0x7FFFFFFF u32_deflate 1 OP_NEGATE OP_EQUAL }); // 0xFFFFFFFF unsigned form
        run(script! { 0 1 OP_NEGATE u32_deflate 1 OP_NEGATE OP_EQUAL }); // 0xFFFFFFFF signed form
    }
    #[test]
    fn test_add_carry() {
        println!("u32_add_carry: {} bytes", u32_add_carry().len());
        run(script! { 0 0 u32_add_carry 0 OP_EQUALVERIFY OP_NOT }); // 0 + 0 ⩵ 0 mod 2³²
        run(script! { 1 0 u32_add_carry 1 OP_EQUALVERIFY OP_NOT }); // 1 + 0 ⩵ 1 mod 2³²
        run(script! { 0 1 u32_add_carry 1 OP_EQUALVERIFY OP_NOT }); // 0 + 1 ⩵ 1 mod 2³²
        run(script! { 1 1 u32_add_carry 2 OP_EQUALVERIFY OP_NOT }); // 1 + 1 ⩵ 2 mod 2³²
        run(script! { 0x40000000 OP_DUP u32_add_carry 0x80000000 OP_EQUALVERIFY OP_NOT }); // 2³⁰ + 2³⁰ ⩵ 2³¹ mod 2³²
        run(script! { 0 0x80000000 u32_add_carry 0x80000000 OP_EQUALVERIFY OP_NOT }); // 0 + 2³¹ ⩵ 2³¹ mod 2³²
        run(script! { 0x80000000 0 u32_add_carry 0x80000000 OP_EQUALVERIFY OP_NOT }); // 2³¹ + 0 ⩵ 2³¹ mod 2³²
        run(script! { 0x80000000 OP_DUP u32_add_carry 0 OP_EQUALVERIFY }); // 2³¹ + 2³¹ ⩵ 0 mod 2³²
        run(script! { 1 OP_NEGATE 1 u32_add_carry 0 OP_EQUALVERIFY OP_NOT }); // -1 + 1 ⩵ 0 mod 2³²
        run(script! { 1 OP_NEGATE OP_DUP u32_add_carry 2 OP_NEGATE OP_EQUALVERIFY }); // 2³¹-1 + 2³¹-1 ⩵ 2³¹-2 mod 2³²
        run(script! { 0x7FFFFFFF OP_NEGATE 0x80000000 u32_add_carry 1 OP_EQUALVERIFY OP_NOT }); // 2³¹+1 + 2³¹ = 1 mod 2³²
    }
    #[test]
    fn test_add_nocarry() {
        println!("u32_add_nocarry: {} bytes", u32_add_nocarry().len());
        run(script! { 0 0 u32_add_nocarry 0 OP_EQUAL }); // 0 + 0 ⩵ 0 mod 2³²
        run(script! { 1 0 u32_add_nocarry 1 OP_EQUAL }); // 1 + 0 ⩵ 1 mod 2³²
        run(script! { 0 1 u32_add_nocarry 1 OP_EQUAL }); // 0 + 1 ⩵ 1 mod 2³²
        run(script! { 1 1 u32_add_nocarry 2 OP_EQUAL }); // 1 + 1 ⩵ 2 mod 2³²
        run(script! { 0x40000000 OP_DUP u32_add_nocarry 0x80000000 OP_EQUAL }); // 2³⁰ + 2³⁰ ⩵ 2³¹ mod 2³²
        run(script! { 0 0x80000000 u32_add_nocarry 0x80000000 OP_EQUAL }); // 0 + 2³¹ ⩵ 2³¹ mod 2³²
        run(script! { 0x80000000 0 u32_add_nocarry 0x80000000 OP_EQUAL }); // 2³¹ + 0 ⩵ 2³¹ mod 2³²
        run(script! { 0x80000000 OP_DUP u32_add_nocarry 0 OP_EQUAL }); // 2³¹ + 2³¹ ⩵ 0 mod 2³²
        run(script! { 1 OP_NEGATE 1 u32_add_nocarry 0 OP_EQUAL }); // -1 + 1 ⩵ 0 mod 2³²
        run(script! { 1 OP_NEGATE OP_DUP u32_add_nocarry 2 OP_NEGATE OP_EQUAL }); // 2³¹-1 + 2³¹-1 ⩵ 2³¹-2 mod 2³²
        run(script! { 0x7FFFFFFF OP_NEGATE 0x80000000 u32_add_nocarry 1 OP_EQUAL }); // 2³¹+1 + 2³¹ = 1 mod 2³²
    }
}