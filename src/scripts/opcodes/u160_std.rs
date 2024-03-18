#![allow(dead_code)]
use core::fmt;
use std::ops::{Index, IndexMut};

use super::vec::{vec_equal, vec_not_equal, vec_equalverify, vec_toaltstack, vec_fromaltstack};
use super::pushable;
use crate::scripts::actor::{Actor, HashDigest};
use crate::scripts::opcodes::u32_state::{u32_state, u32_state_commit, u32_state_unlock};
use crate::scripts::opcodes::u32_std::{ u32_toaltstack, u32_fromaltstack, u32_push };
use crate::scripts::opcodes::unroll;
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

pub fn u160_state(actor: &mut dyn Actor, identifier: &str) -> Script {
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

pub fn u160_state_commit(actor: &mut dyn Actor, identifier: &str) -> Script {
    script! {
        { unroll(U160_U32_SIZE, |i| u32_state_commit(
                actor,
                &u32_identifier(identifier, U160_U32_SIZE - i)
            ))
        }
    }
}

pub fn u160_state_unlock(actor: &mut dyn Actor, identifier: &str, value: U160) -> Script {
    script! {
        { unroll(U160_U32_SIZE, |i| u32_state_unlock(
                actor,
                &u32_identifier(identifier, i + 1), value[i as usize]
            ))
        }
    }
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
    script! {
        { unroll(U160_U32_SIZE, |i| u32_push(value[(U160_U32_SIZE - i - 1) as usize])) }
    }
}

pub fn u160_swap_endian() -> Script {
    unroll(U160_BYTE_SIZE, |i| script!{
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

#[cfg(test)]
mod tests {
    use crate::scripts::{actor::tests::test_player, opcodes::execute_script};
    use super::*;

    #[test]
    fn test_from_hex_string() {
        // Test valid input
        let hex_string = "0x0123456789abcdef0123456789abcdef01234567";
        let u160 = U160::from(hex_string);
        assert_eq!(
            format!("{}", u160),
            "0x0123456789abcdef0123456789abcdef01234567"
        );

        // Test invalid input (wrong length)
        let invalid_hex_string = "0123456789abcdef0123456789abcdef012345";
        assert!(std::panic::catch_unwind(|| U160::from(invalid_hex_string)).is_err());
    }

    #[test]
    fn test_from_bytes() {
        let bytes: [u8; 20] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        ];
        let u160 = U160::from(bytes);
        assert_eq!(
            format!("{}", u160),
            "0x0102030405060708090a0b0c0d0e0f1011121314"
        );
    }

    #[test]
    fn test_u160_state() {
        let hex_string = "0x0123456789abcdef0123456789abcdef01234567";
        let u160 = U160::from(hex_string);
        let mut player = test_player();
        let script = script! {
            { u160_state_unlock(&mut player, "TEST_U160", u160.clone()) }
            { u160_state(&mut player, "TEST_U160") }
            { u160_push(u160) }
            u160_equalverify
            1
        };
        assert!(execute_script(script).success)
    }

    #[test]
    fn test_u160_push() {
        let u160_value = U160::from("0x0123456789abcdef0123456789abcdef01234567");
        let script = script! {
            { u160_push(u160_value) }

            // TODO: Removing the { } escape around hex values throws InvalidScript(NonMinimalPush)
            // in the interpreter so the macro seems to create wrong opcodes for this case
            0x67
            OP_EQUALVERIFY
            0x45
            OP_EQUALVERIFY
            0x23
            OP_EQUALVERIFY
            0x01
            OP_EQUALVERIFY
            0xef
            OP_EQUALVERIFY
            0xcd
            OP_EQUALVERIFY
            0xab
            OP_EQUALVERIFY
            0x89
            OP_EQUALVERIFY

            0x67
            OP_EQUALVERIFY
            0x45
            OP_EQUALVERIFY
            0x23
            OP_EQUALVERIFY
            0x01
            OP_EQUALVERIFY
            0xef
            OP_EQUALVERIFY
            0xcd
            OP_EQUALVERIFY
            0xab
            OP_EQUALVERIFY
            0x89
            OP_EQUALVERIFY

            0x67
            OP_EQUALVERIFY
            0x45
            OP_EQUALVERIFY
            0x23
            OP_EQUALVERIFY
            0x01
            OP_EQUAL
        };
        assert!(execute_script(script).success)
    }
}
