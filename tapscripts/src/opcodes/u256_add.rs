use crate::opcodes::u32_add::{u8_add, u8_add_carry};
use crate::opcodes::u256_zip::{u256_zip, u256_copy_zip};

use super::{pushable, unroll};
use bitcoin::ScriptBuf as Script;
use bitcoin_script::bitcoin_script as script;

/// Addition of two u256 values represented as u8
/// Copies the first summand `a` and drops `b`
pub fn u256_add(a: u32, b: u32) -> Script {
    assert_ne!(a, b);
    script! {
        {u256_copy_zip(a, b)}

        // A0 + B0
        u8_add_carry
        OP_SWAP
        OP_TOALTSTACK

        {unroll(30, |_| script! {    
            // A1 + B1 + carry_0
            OP_ADD
            u8_add_carry
            OP_SWAP
            OP_TOALTSTACK
        })}

        // A31 + B31 + carry_30
        OP_ADD
        u8_add

        {unroll(31, |_| script! {OP_FROMALTSTACK})}

        // Now there's the result C_31 ... C_3 C_2 C_1 C_0 on the stack
    }
}

/// Addition of two u256 values represented as u8
/// Drops both summands `a` and `b`
pub fn u256_add_drop(a: u32, b: u32) -> Script {
    assert_ne!(a, b);
    script! {
        {u256_zip(a, b)}

        // A0 + B0
        u8_add_carry
        OP_SWAP
        OP_TOALTSTACK

        {unroll(30, |_| script! {    
            // A1 + B1 + carry_0
            OP_ADD
            u8_add_carry
            OP_SWAP
            OP_TOALTSTACK
        })}

        // A31 + B31 + carry_30
        OP_ADD
        u8_add

        {unroll(31, |_| script! {OP_FROMALTSTACK})}

        // Now there's the result C_31 ... C_3 C_2 C_1 C_0 on the stack
    }
}
