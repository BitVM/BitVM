use crate::treepp::{pushable, script, Script};
use crate::u32::u32_zip::{u32_copy_zip, u32_zip};

pub fn u8_add_carry() -> Script {
    script! {
        OP_ADD
        OP_DUP
        255
        OP_GREATERTHAN
        OP_IF
            256
            OP_SUB
            1
        OP_ELSE
            0
        OP_ENDIF
    }
}

pub fn u8_add() -> Script {
    script! {
        OP_ADD
        OP_DUP
        255
        OP_GREATERTHAN
        OP_IF
            256
            OP_SUB
        OP_ENDIF
    }
}

/// Addition of two u32 values represented as u8
/// Copies the first summand `a` and drops `b`
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

/// Addition of two u32 values represented as u8
/// Drops both summands `a` and `b`
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
    use crate::treepp::{execute_script, script};
    use crate::u32::u32_add::*;
    use crate::u32::u32_std::u32_push;

    #[test]
    fn test_u32_add() {
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
        let exec_result = execute_script(script);
        assert!(exec_result.success)
    }
}
