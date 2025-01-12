use crate::treepp::{script, Script};
use crate::u32::u32_zip::u32_copy_zip;

/// Bitwise AND of two u8 elements, i denoting how deep the table is in the stack
/// Expects the u8_xor_table on the stack and uses it to process even and odd bits seperately
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
        OP_OVER
        OP_ADD
        OP_ADD
    }.add_stack_hint(-(i as i32 + 256), -1)
}

/// Bitwise AND of a-th and b-th u32 elements from the top, keeps a-th element in the stack
/// Expects u8_xor_table on the stack to use u8_and, and stack_size as a parameter to locate the table
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

#[cfg(test)]
mod tests {

    use crate::run;
    use crate::treepp::script;
    use crate::u32::u32_and::*;
    use crate::u32::u32_std::*;
    use crate::u32::u32_xor::{u8_drop_xor_table, u8_push_xor_table};
    use rand::Rng;

    #[test]
    fn test_and() {
        println!("u32 and: {} bytes", u32_and(0, 1, 3).len());
        for _ in 0..100 {
            let mut rng = rand::thread_rng();
            let x: u32 = rng.gen();
            let y: u32 = rng.gen();
            let exec_script = script! {
                {u8_push_xor_table()}
                {u32_push(x)}
                {u32_push(y)}
                {u32_and(0, 1, 3)}
                {u32_push(x & y)}
                {u32_equal()}
                OP_TOALTSTACK
                {u32_drop()} // drop y
                {u8_drop_xor_table()}
                OP_FROMALTSTACK
            };
            run(exec_script);
        }
    }
    #[test]
    fn test_u8_and_exhaustive() {
        for a in 0..256 {
            for b in 0..256 {
                let script = script! {
                  { u8_push_xor_table() }
                  { a }
                  { b }
                  { u8_and(2) }
                  { a & b }
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
