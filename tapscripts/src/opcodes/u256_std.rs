#![allow(dead_code)]
use bitcoin::ScriptBuf as Script;
use super::vec::vec_equalverify;
use super::{pushable, unroll};
use bitcoin_script::bitcoin_script as script;

const U256_BYTE_SIZE: u32 = 32;

pub fn u256_equalverify() -> Script {
    vec_equalverify(U256_BYTE_SIZE)
}

/// Pushes a value as u256 element onto the stack
pub fn u256_push(value: [u8; 32]) -> Script {
    script! {
        {unroll(32, |i| script! { {value[31 - i as usize]} })}
    }
}
// NOTE: May chunk input value as [u32; 5]