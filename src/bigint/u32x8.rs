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
    script! {                                                       // a b
        { u32_inflate(SIGNED) } OP_ROT { u32_inflate(UNSIGNED) }    // b_div' b_rem' a_div a_rem
        OP_ROT OP_DUP OP_0NOTEQUAL OP_TOALTSTACK OP_ADD             // b_div' a_div c=a_rem+b_rem' | b_rem'!=0
        OP_DUP OP_2OVER OP_NUMNOTEQUAL OP_GREATERTHANOREQUAL        // b_div' a_div c c>=(a_div!=b_div') | b_rem'!=0
        OP_2SWAP OP_TUCK OP_NUMNOTEQUAL                             // c c>=(a_div!=b_div') a_div a_div!=b_div' | b_rem'!=0
        OP_FROMALTSTACK OP_SWAP                                     // c c>=(a_div!=b_div') a_div b_rem'!=0 a_div!=b_div'
        OP_IF
            OP_BOOLAND                                              // c c>=(a_div!=b_div') carry=(a_div&&b_rem'!=0)
            0x7fffffff OP_2SWAP                                     // carry 0x7fffffff c c>=(a_div!=b_div')
            OP_IF
                OP_1SUB OP_SWAP OP_SUB                              // carry result=c-2^31
            OP_ELSE
                OP_1ADD OP_ADD                                      // carry result=c+2^31
            OP_ENDIF
        OP_ELSE
            OP_BOOLOR OP_BOOLAND                                    // c carry=(c>=(a_div!=b_div'))&&(a_div||b_rem'!=0)
            OP_SWAP                                                 // carry result=c
        OP_ENDIF
    }
}

// A₃₁…₀ B₃₁…₀ → [A₃₁…₀+B₃₁…₀]₃₁…₀
pub fn u32_add_nocarry() -> Script {
    script! {
        { u32_inflate(SIGNED) } OP_ROT { u32_inflate(UNSIGNED) }    // b_div' b_rem' a_div a_rem
        OP_ROT OP_ADD                                               // b_div' a_div c=a_rem+b_rem'
        OP_DUP OP_2OVER OP_NUMNOTEQUAL OP_GREATERTHANOREQUAL        // b_div' a_div c c>=(a_div!=b_div')
        OP_2SWAP OP_NUMNOTEQUAL                                     // c c>=(a_div!=b_div') a_div!=b_div'
        OP_IF
            0x7fffffff OP_SWAP                                      // c 0x7fffffff c>=(a_div!=b_div')
            OP_IF
                OP_SUB OP_1SUB                                      // result=c-2^31
            OP_ELSE
                OP_ADD OP_1ADD                                      // result=c+2^31
            OP_ENDIF
        OP_ELSE
            OP_DROP                                                 // result=c
        OP_ENDIF
    }
}

// A₃₁…₀ B₃₁…₀ → [A₃₁…₀-B₃₁…₀]₃₁…₀
pub fn u32_sub_noborrow() -> Script {
    script! {
        { u32_inflate(UNSIGNED) } OP_ROT { u32_inflate(UNSIGNED) }  // b_div' b_rem' a_div a_rem
        OP_ROT OP_SUB                                               // b_div' a_div c=a_rem-b_rem'
        OP_DUP OP_2OVER OP_NUMNOTEQUAL OP_GREATERTHANOREQUAL        // b_div' a_div c c>=(a_div!=b_div')
        OP_2SWAP OP_NUMNOTEQUAL                                     // c c>=(a_div!=b_div') a_div!=b_div'
        OP_IF
            0x7fffffff OP_SWAP                                      // c 0x7fffffff c>=(a_div!=b_div')
            OP_IF
                OP_SUB OP_1SUB                                      // result=c-2^31
            OP_ELSE
                OP_ADD OP_1ADD                                      // result=c+2^31
            OP_ENDIF
        OP_ELSE
            OP_DROP                                                 // result=c
        OP_ENDIF
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
        run(script! { 1 OP_NEGATE 1 u32_add_carry 0 OP_EQUALVERIFY }); // 2³²-1 + 1 ⩵ 0 mod 2³²
        run(script! { 1 OP_NEGATE OP_DUP u32_add_carry 2 OP_NEGATE OP_EQUALVERIFY }); // 2³²-1 + 2³²-1 ⩵ 2³²-2 mod 2³²
        run(script! { 0x7FFFFFFF OP_NEGATE 0x80000000 u32_add_carry 1 OP_EQUALVERIFY }); // 2³¹+1 + 2³¹ = 1 mod 2³²
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
        run(script! { 1 OP_NEGATE 1 u32_add_nocarry 0 OP_EQUAL }); // 2³²-1 + 1 ⩵ 0 mod 2³²
        run(script! { 1 OP_NEGATE OP_DUP u32_add_nocarry 2 OP_NEGATE OP_EQUAL }); // 2³²-1 + 2³²-1 ⩵ 2³²-2 mod 2³²
        run(script! { 0x7FFFFFFF OP_NEGATE 0x80000000 u32_add_nocarry 1 OP_EQUAL }); // 2³¹+1 + 2³¹ = 1 mod 2³²
    }
    #[test]
    fn test_sub_nocarry() {
        println!("u32_sub_noborrow: {} bytes", u32_sub_noborrow().len());
        run(script! { 0 0 u32_sub_noborrow 0 OP_EQUAL }); // 0 - 0 ⩵ 0 mod 2³²
        run(script! { 1 0 u32_sub_noborrow 1 OP_EQUAL }); // 1 - 0 ⩵ 1 mod 2³²
        run(script! { 0 1 u32_sub_noborrow 1 OP_NEGATE OP_EQUAL }); // 0 - 1 ⩵ 2³²-1 mod 2³²
        run(script! { 1 1 u32_sub_noborrow 0 OP_EQUAL }); // 1 - 1 ⩵ 0 mod 2³²
        run(script! { 0x40000000 OP_DUP u32_sub_noborrow 0 OP_EQUAL }); // 2³⁰ - 2³⁰ ⩵ 0 mod 2³²
        run(script! { 0 0x80000000 u32_sub_noborrow 0x80000000 OP_EQUAL }); // 0 - 2³¹ ⩵ 2³¹ mod 2³²
        run(script! { 0x80000000 0 u32_sub_noborrow 0x80000000 OP_EQUAL }); // 2³¹ - 0 ⩵ 2³¹ mod 2³²
        run(script! { 0x80000000 OP_DUP u32_sub_noborrow 0 OP_EQUAL }); // 2³¹ - 2³¹ ⩵ 0 mod 2³²
        run(script! { 1 OP_NEGATE 1 u32_sub_noborrow 2 OP_NEGATE OP_EQUAL }); // 2³²-1 - 1 ⩵ -2 mod 2³²
        run(script! { 1 OP_NEGATE OP_DUP u32_sub_noborrow 0 OP_EQUAL }); // 2³²-1 - (2³²-1) ⩵ 0 mod 2³²
        run(script! { 0x7FFFFFFF OP_NEGATE 0x80000000 u32_sub_noborrow 1 OP_EQUAL }); // 2³¹+1 - 2³¹ = 1 mod 2³²
    }
}