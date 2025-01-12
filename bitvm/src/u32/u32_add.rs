use crate::treepp::{script, Script};
use crate::u32::u32_zip::{u32_copy_zip, u32_zip};

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

/// Addition of a-th and b-th u32 values, keeps the a-th element at stack
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

/// Addition of a-th and b-th u32 values
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
    use crate::run;
    use crate::treepp::script;
    use crate::u32::u32_add::*;
    use crate::u32::u32_std::u32_push;

    #[test]
    fn test_u32_add() {
        println!("u32_len: {}", u32_add_drop(1,0).len());
        let u32_value_a = 0xFFEEFFEEu32;
        let u32_value_b = 0xEEFFEEFFu32;

        let script = script! {
            { u32_push(u32_value_a) }
            { u32_push(u32_value_b) }
            { u32_add_drop(1, 0) }
            0xed OP_EQUALVERIFY
            0xee OP_EQUALVERIFY
            0xee OP_EQUALVERIFY
            0xee OP_EQUAL
        };
        run(script);
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
