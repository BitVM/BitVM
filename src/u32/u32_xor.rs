#![allow(dead_code)]

use crate::treepp::{script, Script};
use crate::u32::u32_zip::u32_copy_zip;

/// Bitwise XOR of two u8 elements
///
/// Expects the u8_xor_table on the stack
///
/// Explanation of the algorithm: https://github.com/BitVM/BitVM/blob/main/tapscripts/docs/u8_xor.md
pub fn u8_xor(i: u32) -> Script {
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

        // A_xor_B_even = A_andxor_B_even - (f(A_andxor_B_even) << 1)
        OP_DUP
        {i + 1}
        OP_ADD
        OP_PICK
        OP_DUP
        OP_ADD
        OP_SUB

        // A_andxor_B_odd = A_odd + B_odd
        OP_SWAP
        OP_ROT
        OP_ADD

        // A_xor_B_odd = A_andxor_B_odd - (f(A_andxor_B_odd) << 1)
        OP_DUP
        {i}
        OP_ADD
        OP_PICK
        OP_DUP
        OP_ADD
        OP_SUB

        // A_xor_B = A_xor_B_odd + (A_xor_B_even << 1)
        OP_OVER
        OP_ADD
        OP_ADD
    }.add_stack_hint(-(i as i32 + 256), -1)
}

/// Bitwise XOR of two u32 elements
///
/// Expects u8_xor_table on the stack
pub fn u32_xor(a: u32, b: u32, stack_size: u32) -> Script {
    assert_ne!(a, b);
    script! {
        {u32_copy_zip(a, b)}

        //
        // XOR
        //

        {u8_xor(8 + (stack_size - 2) * 4)}

        OP_TOALTSTACK

        {u8_xor(6 + (stack_size - 2) * 4)}

        OP_TOALTSTACK

        {u8_xor(4 + (stack_size - 2) * 4)}

        OP_TOALTSTACK

        {u8_xor(2 + (stack_size - 2) * 4)}


        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_FROMALTSTACK
    }
}

/// Push the u8 XOR table
///
/// It's a lookup table for the function f(x) = (x & 0b10101010) >> 1
pub fn u8_push_xor_table() -> Script {
    script! {
        85
        OP_DUP
        84
        OP_DUP
        OP_2OVER
        OP_2OVER
        81
        OP_DUP
        80
        OP_DUP
        OP_2OVER
        OP_2OVER

        85
        OP_DUP
        84
        OP_DUP
        OP_2OVER
        OP_2OVER
        81
        OP_DUP
        80
        OP_DUP
        OP_2OVER
        OP_2OVER

        69
        OP_DUP
        68
        OP_DUP
        OP_2OVER
        OP_2OVER
        65
        OP_DUP
        64
        OP_DUP
        OP_2OVER
        OP_2OVER

        69
        OP_DUP
        68
        OP_DUP
        OP_2OVER
        OP_2OVER
        65
        OP_DUP
        64
        OP_DUP
        OP_2OVER
        OP_2OVER

        85
        OP_DUP
        84
        OP_DUP
        OP_2OVER
        OP_2OVER
        81
        OP_DUP
        80
        OP_DUP
        OP_2OVER
        OP_2OVER

        85
        OP_DUP
        84
        OP_DUP
        OP_2OVER
        OP_2OVER
        81
        OP_DUP
        80
        OP_DUP
        OP_2OVER
        OP_2OVER

        69
        OP_DUP
        68
        OP_DUP
        OP_2OVER
        OP_2OVER
        65
        OP_DUP
        64
        OP_DUP
        OP_2OVER
        OP_2OVER

        69
        OP_DUP
        68
        OP_DUP
        OP_2OVER
        OP_2OVER
        65
        OP_DUP
        64
        OP_DUP
        OP_2OVER
        OP_2OVER

        21
        OP_DUP
        20
        OP_DUP
        OP_2OVER
        OP_2OVER
        17
        OP_DUP
        16
        OP_DUP
        OP_2OVER
        OP_2OVER

        21
        OP_DUP
        20
        OP_DUP
        OP_2OVER
        OP_2OVER
        17
        OP_DUP
        16
        OP_DUP
        OP_2OVER
        OP_2OVER

        5
        OP_DUP
        4
        OP_DUP
        OP_2OVER
        OP_2OVER
        1
        OP_DUP
        0
        OP_DUP
        OP_2OVER
        OP_2OVER

        5
        OP_DUP
        4
        OP_DUP
        OP_2OVER
        OP_2OVER
        1
        OP_DUP
        0
        OP_DUP
        OP_2OVER
        OP_2OVER

        21
        OP_DUP
        20
        OP_DUP
        OP_2OVER
        OP_2OVER
        17
        OP_DUP
        16
        OP_DUP
        OP_2OVER
        OP_2OVER

        21
        OP_DUP
        20
        OP_DUP
        OP_2OVER
        OP_2OVER
        17
        OP_DUP
        16
        OP_DUP
        OP_2OVER
        OP_2OVER

        5
        OP_DUP
        4
        OP_DUP
        OP_2OVER
        OP_2OVER
        1
        OP_DUP
        0
        OP_DUP
        OP_2OVER
        OP_2OVER

        5
        OP_DUP
        4
        OP_DUP
        OP_2OVER
        OP_2OVER
        1
        OP_DUP
        0
        OP_DUP
        OP_2OVER
        OP_2OVER
    }
}

/// Drop the u8 XOR table
pub fn u8_drop_xor_table() -> Script {
    script! {
        for _ in 0..128{
            OP_2DROP
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::run;
    use crate::treepp::script;
    use crate::u32::u32_std::*;
    use crate::u32::u32_xor::{u32_xor, u8_drop_xor_table, u8_push_xor_table};
    use rand::Rng;

    fn xor(x: u32, y: u32) -> u32 { x ^ y }

    #[test]
    fn test_xor() {
        println!("u32 xor: {} bytes", u32_xor(0, 1, 3).len());
        for _ in 0..100 {
            let mut rng = rand::thread_rng();
            let x: u32 = rng.gen();
            let y: u32 = rng.gen();
            let script = script! {
                {u8_push_xor_table()}
                {u32_push(x)}
                {u32_push(y)}
                {u32_xor(0, 1, 3)}
                {u32_push(xor(x, y))}
                {u32_equal()}
                OP_TOALTSTACK
                {u32_drop()} // drop y
                {u8_drop_xor_table()}
                OP_FROMALTSTACK
            };
            run(script);
        }
    }
}
