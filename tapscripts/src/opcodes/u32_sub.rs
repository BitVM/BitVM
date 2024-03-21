#![allow(dead_code)]
use crate::opcodes::u32_zip::u32_zip;

use super::pushable;
use super::u32_zip::u32_copy_zip;
use bitcoin::ScriptBuf as Script;
use bitcoin_script::bitcoin_script as script;

pub fn u8_sub_carry() -> Script {
    script! {
        OP_SUB
        OP_DUP
        0
        OP_LESSTHAN
        OP_IF
            256
            OP_ADD
            1
        OP_ELSE
            0
        OP_ENDIF
    }
}

pub fn u8_sub() -> Script {
    script! {
        OP_SUB
        OP_DUP
        0
        OP_LESSTHAN
        OP_IF
            256
            OP_ADD
        OP_ENDIF
    }
}

/// Subtraction of two u32 values represented as u8
/// Copies the first summand `a` and drops `b`
pub fn u32_sub(a: u32, b: u32) -> Script {
    assert_ne!(a, b);

    script! {
        {u32_copy_zip(a, b)}

        // A0 - B0
        u8_sub_carry
        OP_SWAP
        OP_TOALTSTACK

        // A1 - (B1 + carry_0)
        OP_ADD
        u8_sub_carry
        OP_SWAP
        OP_TOALTSTACK

        // A2 - (B2 + carry_1)
        OP_ADD
        u8_sub_carry
        OP_SWAP
        OP_TOALTSTACK

        // A3 - (B3 + carry_2)
        OP_ADD
        u8_sub

        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_FROMALTSTACK

        // Now there's the result C_3 C_2 C_1 C_0 on the stack
    }
}

///
/// Subtraction of two u32 values represented as u8
/// Drops both summands `a` and `b`
pub fn u32_sub_drop(a: u32, b: u32) -> Script {
    assert_ne!(a, b);
    script! {
        {u32_zip(a,b)}

        // A0 - B0
        u8_sub_carry
        OP_SWAP
        OP_TOALTSTACK

        // A1 - (B1 + carry_0)
        OP_ADD
        u8_sub_carry
        OP_SWAP
        OP_TOALTSTACK

        // A2 - (B2 + carry_1)
        OP_ADD
        u8_sub_carry
        OP_SWAP
        OP_TOALTSTACK

        // A3 - (B3 + carry_2)
        OP_ADD
        u8_sub

        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_FROMALTSTACK

        // Now there's the result C_3 C_2 C_1 C_0 on the stack
    }
}
