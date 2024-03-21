#![allow(dead_code)]
use core::fmt;
use std::ops::{Index, IndexMut};

use super::pushable;
use super::vec::{vec_equal, vec_equalverify, vec_fromaltstack, vec_not_equal, vec_toaltstack};
use crate::actor::{Actor, HashDigest};
use crate::opcodes::u32_state::{u32_state, u32_state_commit, u32_state_unlock};
use crate::opcodes::u32_std::{u32_fromaltstack, u32_push, u32_toaltstack};
use crate::opcodes::unroll;
use bitcoin::ScriptBuf as Script;
use bitcoin_script::bitcoin_script as script;

#[derive(Clone)]
pub struct U160(pub [u32; 5]);

impl Index<usize> for U160 {
    type Output = u32;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl IndexMut<usize> for U160 {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl fmt::Display for U160 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Format the U160 as hex string
        write!(
            f,
            "0x{:08x}{:08x}{:08x}{:08x}{:08x}",
            self[0], self[1], self[2], self[3], self[4]
        )
    }
}

impl From<&str> for U160 {
    fn from(hex_string: &str) -> Self {
        let hex_string = hex_string.trim_start_matches("0x");
        if hex_string.len() != 40 {
            panic!("Hexadecimal string must be exactly 40 characters long");
        }

        let mut values = [0u32; 5];
        for i in 0..5 {
            let start = i * 8;
            let end = (i + 1) * 8;
            values[i] = u32::from_str_radix(&hex_string[start..end], 16)
                .expect("Failed to parse hexadecimal string");
        }

        U160(values)
    }
}

impl From<HashDigest> for U160 {
    fn from(bytes: HashDigest) -> Self {
        let mut values = [0u32; 5];
        for i in 0..5 {
            let start = i * 4;
            values[i] = u32::from_be_bytes([
                bytes[start],
                bytes[start + 1],
                bytes[start + 2],
                bytes[start + 3],
            ]);
        }

        U160(values)
    }
}

impl U160 {
    pub fn new() -> Self {
        U160([0; 5])
    }
}

const U160_BYTE_SIZE: u32 = 20;
const U160_U32_SIZE: u32 = 5;
const U160_HEX_SIZE: u32 = U160_BYTE_SIZE * 2;

fn u32_identifier(identifier: &str, index: u32) -> String {
    format!("{}_{}", identifier, index)
}

pub fn u160_state(actor: &dyn Actor, identifier: &str) -> Script {
    script! {
        { u32_state(actor, &u32_identifier(identifier, 5)) }
        u32_toaltstack
        { u32_state(actor, &u32_identifier(identifier, 4)) }
        u32_toaltstack
        { u32_state(actor, &u32_identifier(identifier, 3)) }
        u32_toaltstack
        { u32_state(actor, &u32_identifier(identifier, 2)) }
        u32_toaltstack
        { u32_state(actor, &u32_identifier(identifier, 1)) }
        u32_fromaltstack
        u32_fromaltstack
        u32_fromaltstack
        u32_fromaltstack
    }
}

pub fn u160_state_commit(actor: &dyn Actor, identifier: &str) -> Script {
    unroll(U160_U32_SIZE, |i| {
        u32_state_commit(actor, &u32_identifier(identifier, U160_U32_SIZE - i))
    })
}

pub fn u160_state_unlock(actor: &dyn Actor, identifier: &str, value: U160) -> Script {
    unroll(U160_U32_SIZE, |i| {
        u32_state_unlock(actor, &u32_identifier(identifier, i + 1), value[i as usize])
    })
}

pub fn u160_equalverify() -> Script {
    vec_equalverify(U160_BYTE_SIZE)
}

pub fn u160_equal() -> Script {
    vec_equal(U160_BYTE_SIZE)
}

pub fn u160_notequal() -> Script {
    vec_not_equal(U160_BYTE_SIZE)
}

// TODO: confirm correct endiannes with js version
pub fn u160_push(value: U160) -> Script {
    unroll(U160_U32_SIZE, |i| {
        u32_push(value[(U160_U32_SIZE - i - 1) as usize])
    })
}

pub fn u160_swap_endian() -> Script {
    unroll(U160_BYTE_SIZE, |i| script! {
        { i / 4 * 4 + 3 }
        OP_ROLL
    })
}

pub fn u160_toaltstack() -> Script {
    vec_toaltstack(U160_BYTE_SIZE)
}

pub fn u160_fromaltstack() -> Script {
    vec_fromaltstack(U160_BYTE_SIZE)
}
