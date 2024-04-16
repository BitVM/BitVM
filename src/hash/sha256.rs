#![allow(non_snake_case)]
use std::collections::HashMap;

use crate::treepp::{pushable, script, Script};
use crate::u32::u32_add::u32_add_drop;
use crate::u32::u32_std::{u32_dup, u32_equalverify, u32_roll};
use crate::u32::{
    u32_add::u32_add,
    u32_and::u32_and,
    u32_rrot::u32_rrot,
    u32_std::{u32_drop, u32_fromaltstack, u32_pick, u32_push, u32_toaltstack},
    u32_xor::{u32_xor, u8_drop_xor_table, u8_push_xor_table},
    // unroll,
};

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const INITSTATE: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// sha256 take indefinite length input on the top of statck and return 256 bit (64 byte)
pub fn sha256(num_bytes: usize) -> Script {
    // TODO: calculate chunks_size
    let chunks_size: usize = 0;
    script! {
        {u8_push_xor_table}

        // top of stack: [ [n bytes input] ]
        {padding_and_split(num_bytes)}
        // top of stack: [ [64 byte chunks]... ]
        {sha256_init()}
        // top of statck: [ [64 byte chunks]..., state[0-7]]
        for _ in 0..chunks_size {
            {sha256_transform()}
        }

        {u8_drop_xor_table()}
    }
}

/// TODO:
/// reorder bytes for u32
pub fn padding_and_split(num_bytes: usize) -> Script {
    script! {}
}

/// push all init state into stack
pub fn sha256_init() -> Vec<Script> {
    let mut state: [u32; 8] = INITSTATE;
    state.reverse();
    state.iter().map(|x: &u32| u32_push(*x)).collect::<Vec<_>>()
}

/// sha256 transform
/// stack: [64byte chunk: 16; u32] state[0-7]
pub fn sha256_transform(stack_depth: u32) -> Script {
    script! {
        // push old state to alt stack
        for _ in 0..8 {
            {u32_toaltstack()}
        }

        // reverse for the first 16 states
        for i in 1..16 {
            {u32_roll(i)}
        }

        // reorg data
        for _ in 16..64 {
            { 0 } // delimiter, may be optimized

            {u32_pick(2)}
            {sig1(stack_depth - 6)}
            {u32_add_drop(0, 1)}

            {u32_pick(7)}
            {u32_add_drop(0, 1)}

            {u32_pick(15)}
            {sig0(stack_depth - 6)}
            {u32_add_drop(0, 1)}

            {u32_pick(16)}
            {u32_add_drop(0, 1)}
        }

        // get a copy of states from altstack
        for _ in 0..8 {
            {u32_fromaltstack()}
        }

        for _ in 0..8 {
            {u32_pick(7)}
        }

        for _ in 0..8 {
            {u32_toaltstack()}
        }

        // loop for transform

    }
}

/// shift right the top u32
pub fn u32_shr(rot_num: usize, stack_depth: u32) -> Script {
    script! {
        {u32_rrot(rot_num)}
        {u32_push(0xffffffff >> rot_num)}
        {u32_and(0, 1, stack_depth + 1)}
        {u32_toaltstack()}
        {u32_drop()}
        {u32_fromaltstack()}
    }
}

/// Change top element x to ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3)
pub fn sig0(stack_depth: u32) -> Script {
    script! {
        {u32_dup()}
        {u32_dup()}
        {u32_toaltstack()}
        {u32_toaltstack()}

        {u32_shr(3, stack_depth)}
        {u32_fromaltstack()}
        {u32_rrot(7)}
        {u32_fromaltstack()}
        {u32_rrot(18)}
        {u32_xor(0, 1, stack_depth + 2)}
        {u32_xor(0, 2, stack_depth + 2)}

        // clean stack
        {u32_toaltstack()}
        {u32_drop()}
        {u32_drop()}
        {u32_fromaltstack()}
    }
}

/// Change top element x to (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))
pub fn sig1(stack_depth: u32) -> Script {
    script! {
        {u32_dup()}
        {u32_dup()}
        {u32_toaltstack()}
        {u32_toaltstack()}

        {u32_shr(10, stack_depth)}
        {u32_fromaltstack()}
        {u32_rrot(19)}
        {u32_fromaltstack()}
        {u32_rrot(17)}
        {u32_xor(0, 1, stack_depth + 2)}
        {u32_xor(0, 2, stack_depth + 2)}

        // clean stack
        {u32_toaltstack()}
        {u32_drop()}
        {u32_drop()}
        {u32_fromaltstack()}
    }
}

pub fn ep0() -> Script { script!() }

pub fn ep1() -> Script { script!() }

/// Push (((x) & (y)) ^ (~(x) & (z))) into stack
pub fn ch(x: u32, y: u32, z: u32, stack_depth: u32) -> Script { script!() }

/// Push (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z))) into stack
pub fn maj(x: u32, y: u32, z: u32, stack_depth: u32) -> Script { script!() }

#[cfg(test)]
mod tests {

    use crate::hash::sha256::*;
    use crate::treepp::pushable;
    use crate::treepp::{execute_script, script};

    fn rrot(x: u32, n: usize) -> u32 {
        if n == 0 {
            return x;
        }
        (x >> n) | (x << (32 - n))
    }

    #[test]
    fn test_sig0() {
        let x: u32 = 12;
        let result: u32 = rrot(x, 7) ^ rrot(x, 18) ^ (x >> 3);
        let script = script! {
            {u8_push_xor_table()}
            {u32_push(x)}
            {sig0(2)}
            {u32_toaltstack()}
            {u8_drop_xor_table()}
            {u32_fromaltstack()}
        };
        let res = execute_script(script);
        println!("stack: {:100}, result: {:X}", res, result);
    }
}
