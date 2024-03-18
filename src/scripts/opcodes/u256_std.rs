#![allow(dead_code)]
use super::vec::vec_equalverify;
use bitcoin::ScriptBuf as Script;

const U256_BYTE_SIZE: u32 = 32;

pub fn u256_equalverify() -> Script {
    vec_equalverify(U256_BYTE_SIZE)
}
