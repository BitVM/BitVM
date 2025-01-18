use crate::treepp::{script, Script};
use crate::u32::u32_zip::u32_copy_zip;

/// Bitwise XOR of two u8 elements, i denoting how many values are there in the stack after the table (including the input numbers A and B)
/// Expects the u8_xor_table on the stack and uses it to process even and odd bits seperatey
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

/// Bitwise XOR of a-th and b-th u32 elements from the top, keeps a-th element in the stack
/// Expects u8_xor_table on the stack to use u8_xor, and stack_size as a parameter to locate the table (which should be equal to 1 + number of the u32 elements in the stack after the table)
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

/// Pushes the u8 XOR table, for the function f(x) = (x & 0b10101010) >> 1
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

/// Drops the u8 XOR table
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
    use crate::u32::u32_xor::*;
    use rand::Rng;

    #[test]
    fn test_xor_table() {
        let script = script! {
            { u8_push_xor_table() }
            { 1 } OP_TOALTSTACK
            for x in 0..1<<8 {
                { x }
                OP_PICK
                { (x & 0b10101010) >> 1 }
                OP_EQUAL
                OP_FROMALTSTACK
                OP_BOOLAND
                OP_TOALTSTACK
            }
            { u8_drop_xor_table() }
            OP_FROMALTSTACK
        };
        run(script);
    }

    #[test]
    fn test_u32_xor() {
        println!("u32 xor: {} bytes", u32_xor(0, 1, 3).len());
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            let x: u32 = rng.gen();
            let y: u32 = rng.gen();
            let script = script! {
                {u8_push_xor_table()}
                {u32_push(x)}
                {u32_push(y)}
                {u32_xor(0, 1, 3)}
                { u32_push(x ^ y) }
                {u32_equal()}
                OP_TOALTSTACK
                {u32_drop()} // drop y
                {u8_drop_xor_table()}
                OP_FROMALTSTACK
            };
            run(script);
        }
    }

    #[test]
    fn test_u8_xor_exhaustive() {
        for a in 0..256 {
            for b in 0..256 {
                let script = script! {
                  { u8_push_xor_table() }
                  { a }
                  { b }
                  { u8_xor(2) }
                  { a ^ b }
                  OP_EQUAL
                  OP_TOALTSTACK
                  { u8_drop_xor_table() }
                  OP_FROMALTSTACK
                };
                run(script);
            }
        }
    }
}
