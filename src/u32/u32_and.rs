#![allow(dead_code)]

use crate::u32::u32_zip::{u32_copy_zip, u32_zip};
use crate::treepp::{pushable, script, Script};

/// The bitwise AND of two u8 elements.
/// Expects the u8_xor_table to be on the stack
pub fn u8_and(i: u32) -> Script {
    script! {
        // f_A = f(A)
        OP_DUP
        {i}
        OP_ADD
        OP_PICK

        // A_even = f_A << 1
        OP_DUP
        OP_DUP
        OP_ADD

        // A_odd = A - A_even
        OP_ROT
        OP_SWAP
        OP_SUB

        // f_B = f(B)
        OP_ROT
        OP_DUP
        {i + 1}
        OP_ADD
        OP_PICK

        // B_even = f_B << 1
        OP_DUP
        OP_DUP
        OP_ADD

        // B_odd = B - B_even
        OP_ROT
        OP_SWAP
        OP_SUB

        // A_andxor_B_even = f_A + f_B
        OP_SWAP
        3
        OP_ROLL
        OP_ADD
        // A_and_B_even = f(A_andxor_B_even)
        {i}
        OP_ADD
        OP_PICK

        // A_andxor_B_odd = A_odd + B_odd
        OP_SWAP
        OP_ROT
        OP_ADD

        // A_and_B_odd = f(A_andxor_B_odd)
        {i - 1}
        OP_ADD
        OP_PICK

        // A_and_B = A_and_B_odd + (A_and_B_even << 1)
        OP_SWAP
        OP_DUP
        OP_ADD
        OP_ADD
    }
}

/// The bitwise AND of the u32 elements at address a and at address b. Drops a and b
/// 
/// Expects the u8_xor_table to be on the stack
pub fn u32_and(a: u32, b: u32, stack_size: u32) -> Script {
    assert_ne!(a, b);
    script! {
        {u32_copy_zip(a, b)}

        {u8_and(8 + (stack_size - 2) * 4)}

        OP_TOALTSTACK

        {u8_and(6 + (stack_size - 2) * 4)}

        OP_TOALTSTACK

        {u8_and(4 + (stack_size - 2) * 4)}

        OP_TOALTSTACK

        {u8_and(2 + (stack_size - 2) * 4)}

        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_FROMALTSTACK
    }
}