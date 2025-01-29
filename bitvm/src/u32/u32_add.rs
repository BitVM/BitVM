use crate::treepp::*;
use crate::u32::u32_zip::{u32_copy_zip, u32_zip};

/// Addition of two u8 elements at the top of the stack, pushing the carry after the sum
pub fn u8_add_carry() -> Script {
    script! {
        OP_ADD
        256
        OP_2DUP
        OP_GREATERTHANOREQUAL
        OP_IF
            OP_SUB
            1
        OP_ELSE
            OP_DROP
            0
        OP_ENDIF
    }
}

/// Addition of two u8 elements at the top of the stack, without minding the carry
pub fn u8_add() -> Script {
    script! {
        OP_ADD
        256
        OP_2DUP
        OP_GREATERTHANOREQUAL
        OP_IF
            OP_SUB
            OP_0
        OP_ENDIF
        OP_DROP
    }
}

/// Modulo 2^32 addition of a-th and b-th u32 values, keeps the a-th element at stack
pub fn u32_add(a: u32, b: u32) -> Script {
    assert_ne!(a, b); 
    script! {
        {u32_copy_zip(a, b)}

        // A0 + B0
        u8_add_carry
        OP_SWAP
        OP_TOALTSTACK

        // A1 + B1 + carry_0
        OP_ADD
        u8_add_carry
        OP_SWAP
        OP_TOALTSTACK

        // A2 + B2 + carry_1
        OP_ADD
        u8_add_carry
        OP_SWAP
        OP_TOALTSTACK

        // A3 + B3 + carry_2
        OP_ADD
        u8_add

        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_FROMALTSTACK

        // Now there's the result C_3 C_2 C_1 C_0 on the stack
    }
}

/// Modulo 2^32 addition of a-th and b-th u32 values
pub fn u32_add_drop(a: u32, b: u32) -> Script {
    assert_ne!(a, b);
    script! {
        {u32_zip(a, b)}

        // A0 + B0
        u8_add_carry
        OP_SWAP
        OP_TOALTSTACK

        // A1 + B1 + carry_0
        OP_ADD
        u8_add_carry
        OP_SWAP
        OP_TOALTSTACK

        // A2 + B2 + carry_1
        OP_ADD
        u8_add_carry
        OP_SWAP
        OP_TOALTSTACK

        // A3 + B3 + carry_2
        OP_ADD
        u8_add

        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_FROMALTSTACK

        // Now there's the result C_3 C_2 C_1 C_0 on the stack
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::u32::u32_std::{u32_equal, u32_equalverify, u32_push};
    use rand::Rng;

    #[test]
    fn test_u32_add() {
        println!("u32_len: {}", u32_add_drop(1,0).len());
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            let x = rng.gen();
            let y = rng.gen_range(0..=u32::MAX - x);
            let script_add_drop = script! {
                { u32_push(x) }
                { u32_push(y) }
                { u32_add_drop(1, 0) }
                { u32_push(x + y) }
                { u32_equal() }
            };
            let script_add = script! {
                { u32_push(x) }
                { u32_push(y) }
                { u32_add(1, 0) }
                { u32_push(x + y) }
                { u32_equalverify() }
                { u32_push(x) }
                { u32_equal() }
            };
            run(script_add_drop);
            run(script_add);
        }
    }
    #[test]
    fn test_u8_adds_exhaustive() {
        for a in 0..256 {
            for b in 0..256 {
                let script_without_carry = script! {
                  { a }
                  { b }
                  { u8_add() }
                  { (a + b) % 256 }
                  OP_EQUAL
                };
                let script_with_carry = script! {
                    { a }
                    { b }
                    { u8_add_carry() }
                    { ((a + b) >= 256) as u32 } 
                    OP_EQUAL 
                    OP_TOALTSTACK
                    { (a + b) % 256 }
                    OP_EQUAL
                    OP_FROMALTSTACK
                    OP_BOOLAND
                };
                run(script_without_carry);
                run(script_with_carry);
            }
        } 
    }
}
