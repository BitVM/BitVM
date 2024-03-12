#![allow(dead_code)]
use super::pushable;
use crate::scripts::opcodes::{
    u32_std::{u32_equalverify, u32_roll},
    unroll,
};
use bitcoin::ScriptBuf as Script;
use bitcoin_script::bitcoin_script as script;

pub fn u256_equalverify() -> Script {
    script! {
        {unroll(8, |i| script! {
            {u32_roll(8 - i)}
            u32_equalverify
        })}
    }
}
