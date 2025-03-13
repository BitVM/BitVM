use crate::treepp::{script, Script};

/// Zips the a-th and b-th u32 elements from the top (without preserving order)
/// Assuming a is smaller than b and x_i denoting the i-th part of the x-th number:
/// Input:  ... (a u32 elements) a_0 a_1 a_2 a_3 ... (b - a - 1 u32 elements) b_0 b_1 b_2 b_3
/// Output: b_0 a_0 b_1 a_1 b_2 a_2 b_3 a_3 ... (b - 1 u32 elements and rest of the stack)
pub fn u32_zip(mut a: u32, mut b: u32) -> Script {
    assert_ne!(a, b);
    if a > b {
        (a, b) = (b, a);
    }

    a = (a + 1) * 4 - 1;
    b = (b + 1) * 4 - 1;

    script! {
        {a} OP_ROLL {b} OP_ROLL
        {a+1} OP_ROLL {b} OP_ROLL
        {a+2} OP_ROLL {b} OP_ROLL
        {a+3} OP_ROLL {b} OP_ROLL
    }
}

/// Zips the a-th and b-th u32 elements from the top and keep the one chosen (given as the first parameter) in the stack (without preserving order)
/// Assuming a is smaller than b and x_i denoting the i-th part of the x-th number:
/// Input:  ... (a u32 elements) a_0 a_1 a_2 a_3 ... (b - a - 1 u32 elements) b_0 b_1 b_2 b_3
/// Output: b_0 a_0 b_1 a_1 b_2 a_2 b_3 a_3 ... (b u32 elements including the element that is chosen to stay and rest of the stack)
pub fn u32_copy_zip(a: u32, b: u32) -> Script {
    if a < b {
        _u32_copy_zip(a, b)
    } else {
        _u32_zip_copy(b, a)
    }
}

/// Helper for u32_copy_zip
pub fn _u32_copy_zip(mut a: u32, mut b: u32) -> Script {
    assert!(a < b);
    a = (a + 1) * 4 - 1;
    b = (b + 1) * 4 - 1;

    script! {
        {a} OP_PICK {b+1} OP_ROLL
        {a+1} OP_PICK {b+2} OP_ROLL
        {a+2} OP_PICK {b+3} OP_ROLL
        {a+3} OP_PICK {b+4} OP_ROLL
    }
}

///Helper for u32_copy_zip
pub fn _u32_zip_copy(mut a: u32, mut b: u32) -> Script {
    assert!(a < b);

    a = (a + 1) * 4 - 1;
    b = (b + 1) * 4 - 1;
    script! {
        {a} OP_ROLL {b} OP_PICK
        {a+1} OP_ROLL {b} OP_PICK
        {a+2} OP_ROLL {b} OP_PICK
        {a+3} OP_ROLL {b} OP_PICK
    }
}
