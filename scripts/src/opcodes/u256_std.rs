#![allow(dead_code)]
use bitcoin::ScriptBuf as Script;
use super::vec::vec_equalverify;

const U256_BYTE_SIZE: u32 = 32;

pub fn u256_equalverify() -> Script {
    vec_equalverify(U256_BYTE_SIZE)
}
