#![allow(dead_code)]
use super::{pushable, unroll};
use bitcoin::ScriptBuf as Script;
use bitcoin_script::bitcoin_script as script;

/// Zip the top two u256 elements
/// input:  a0 a1 a2 a3 .. a31 b0 b1 b2 b3 .. b31
/// output: a0 b0 a1 b1 a2 b2 a3 b3 .. a31 b31
pub fn u256_zip(mut a: u32, mut b: u32) -> Script {
    if a > b {
        (a, b) = (b, a);
    }

    a = (a + 1) * 32 - 1;
    b = (b + 1) * 32 - 1;

    script! {
        {unroll(32, |i| script! {
            {a+i} OP_ROLL {b} OP_ROLL
        })}
    }
}

/// Copy and zip the top two u32 elements
/// input:  a0 a1 a2 a3 .. a31 b0 b1 b2 b3 .. b31
/// output: a0 b0 a1 b1 a2 b2 a3 b3 .. a31 b31 a0 a1 a2 a3 .. a31
pub fn u256_copy_zip(a: u32, b: u32) -> Script {
    if a < b {
        _u256_copy_zip(a, b)
    } else {
        _u256_zip_copy(b, a)
    }
}

pub fn _u256_copy_zip(mut a: u32, mut b: u32) -> Script {
    assert!(a < b);

    a = (a + 1) * 32 - 1;
    b = (b + 1) * 32 - 1;

    script! {
        { unroll(32, |i| script! {
            {a+i} OP_PICK {b+i+1} OP_ROLL
        }) }
    }
}

pub fn _u256_zip_copy(mut a: u32, mut b: u32) -> Script {
    assert!(a < b);

    a = (a + 1) * 32 - 1;
    b = (b + 1) * 32 - 1;
    script! {
        { unroll(32, |i| script! {
            {a+i} OP_ROLL {b} OP_PICK
        }) }
    }
}
