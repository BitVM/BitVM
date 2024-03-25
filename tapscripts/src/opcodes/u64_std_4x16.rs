#![allow(dead_code)]

use super::pushable;
use bitcoin::ScriptBuf as Script;
use bitcoin_script::bitcoin_script as script;

// NOTE: The following code has been copied from u32_std.rs

pub fn u64_swap() -> Script {
    u64_roll(1)
}

/// The u64 element n back in the stack is moved to the top.
pub fn u64_roll(n: u32) -> Script {
    let n = (n + 1) * 4 - 1;
    script! {
        {n} OP_ROLL
        {n} OP_ROLL
        {n} OP_ROLL
        {n} OP_ROLL
    }
}

/// Returns 1 if the top two u64 are equal, 0 otherwise
pub fn u64_equal() -> Script {
    script! {
        4
        OP_ROLL
        OP_EQUAL OP_TOALTSTACK
        3
        OP_ROLL
        OP_EQUAL OP_TOALTSTACK
        OP_ROT
        OP_EQUAL OP_TOALTSTACK
        OP_EQUAL
        OP_FROMALTSTACK OP_BOOLAND
        OP_FROMALTSTACK OP_BOOLAND
        OP_FROMALTSTACK OP_BOOLAND
    }
}