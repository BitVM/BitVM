use crate::opcodes::u16_add::{u16_add, u16_add_carry};
use crate::opcodes::u256_zip_16x16::{u256_zip, u256_copy_zip};

use super::{pushable, unroll};
use bitcoin::ScriptBuf as Script;
use bitcoin_script::bitcoin_script as script;


const NUMBER_LIMBS: u32 = 16;


/// Addition of two u256 values represented as u16
/// Copies the first summand `a` and drops `b`
pub fn u256_add(a: u32, b: u32) -> Script {
    assert_ne!(a, b);
    script! {
        {u256_copy_zip(a, b)}

        // A0 + B0
        u16_add_carry
        OP_SWAP
        OP_TOALTSTACK

        {unroll(NUMBER_LIMBS - 2, |_| script! {    
            // A_{i+1} + B_{i+1} + carry_i
            OP_ADD
            u16_add_carry
            OP_SWAP
            OP_TOALTSTACK
        })}

        // A15 + B15 + carry_14
        OP_ADD
        u16_add

        {unroll(NUMBER_LIMBS - 1, |_| script! {OP_FROMALTSTACK})}

        // Now there's the result C_15 ... C_3 C_2 C_1 C_0 on the stack
    }
}

/// Addition of two u256 values represented as u16
/// Drops both summands `a` and `b`
pub fn u256_add_drop(a: u32, b: u32) -> Script {
    assert_ne!(a, b);
    script! {
        {u256_zip(a, b)}

        // A0 + B0
        u16_add_carry
        OP_SWAP
        OP_TOALTSTACK

        {unroll(NUMBER_LIMBS - 2, |_| script! {    
            // A_{i+1} + B_{i+1} + carry_i
            OP_ADD
            u16_add_carry
            OP_SWAP
            OP_TOALTSTACK
        })}

        // A15 + B15 + carry_14
        OP_ADD
        u16_add

        {unroll(NUMBER_LIMBS - 1, |_| script! {OP_FROMALTSTACK})}

        // Now there's the result C_15 ... C_3 C_2 C_1 C_0 on the stack
    }
}
