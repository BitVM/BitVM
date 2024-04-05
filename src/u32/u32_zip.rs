#![allow(dead_code)]
use crate::treepp::{pushable, script, Script};

/// Zip the top two u32 elements
/// input:  a0 a1 a2 a3 b0 b1 b2 b3
/// output: a0 b0 a1 b1 a2 b2 a3 b3
pub fn u32_zip(mut a: u32, mut b: u32) -> Script {
    if a > b {
        (a, b) = (b, a);
    }

    a = (a + 1) * 4 - 1;
    b = (b + 1) * 4 - 1;

    script! {
        {a+0} OP_ROLL {b} OP_ROLL
        {a+1} OP_ROLL {b} OP_ROLL
        {a+2} OP_ROLL {b} OP_ROLL
        {a+3} OP_ROLL {b} OP_ROLL
    }
}

/// Copy and zip the top two u32 elements
/// input:  a0 a1 a2 a3 b0 b1 b2 b3
/// output: a0 b0 a1 b1 a2 b2 a3 b3 a0 a1 a2 a3
pub fn u32_copy_zip(a: u32, b: u32) -> Script {
    if a < b {
        _u32_copy_zip(a, b)
    } else {
        _u32_zip_copy(b, a)
    }
}

pub fn _u32_copy_zip(mut a: u32, mut b: u32) -> Script {
    assert!(a < b);

    a = (a + 1) * 4 - 1;
    b = (b + 1) * 4 - 1;

    script! {
        {a+0} OP_PICK {b+1} OP_ROLL
        {a+1} OP_PICK {b+2} OP_ROLL
        {a+2} OP_PICK {b+3} OP_ROLL
        {a+3} OP_PICK {b+4} OP_ROLL
    }
}

pub fn _u32_zip_copy(mut a: u32, mut b: u32) -> Script {
    assert!(a < b);

    a = (a + 1) * 4 - 1;
    b = (b + 1) * 4 - 1;
    script! {
        {a+0} OP_ROLL {b} OP_PICK
        {a+1} OP_ROLL {b} OP_PICK
        {a+2} OP_ROLL {b} OP_PICK
        {a+3} OP_ROLL {b} OP_PICK
    }
}
