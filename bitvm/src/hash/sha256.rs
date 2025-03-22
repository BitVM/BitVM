#![allow(non_snake_case)]

use crate::pseudo::push_to_stack;
use crate::treepp::{script, Script};
use crate::u32::u32_add::u32_add_drop;
use crate::u32::u32_std::{u32_dup, u32_roll};
use crate::u32::{
    u32_and::u32_and,
    u32_rrot::u32_rrot,
    u32_std::{u32_drop, u32_fromaltstack, u32_pick, u32_push, u32_toaltstack},
    u32_xor::{u32_xor, u8_drop_xor_table, u8_push_xor_table},
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

/// sha256 take indefinite length input on the top of stack and return 256 bit (64 byte)
pub fn sha256(num_bytes: usize) -> Script {
    if num_bytes == 32 {
        return sha256_32bytes();
    }
    if num_bytes == 80 {
        return sha256_80bytes();
    }
    let mut chunks_size: usize = num_bytes / 64 + 1;
    if (num_bytes % 64) > 55 {
        chunks_size += 1;
    }

    script! {
        {push_reverse_bytes_to_alt(num_bytes)}

        // top of stack: [ [n bytes input] ]
        {u8_push_xor_table()}
        {sha256_k()}
        // top of stack: [ [64 byte chunks]... ]
        {padding_add_roll(num_bytes)}
        {sha256_init()}
        // top of stack: [ [64 byte chunks]..., state[0-7]]
        for i in 0..chunks_size {
            {sha256_transform(8 + ((chunks_size as u32) - i as u32) *16 + 64 + 1, 8 + ((chunks_size as u32) - i as u32)  *16)}
        }

        {sha256_final()}
        for _ in 0..8 {
            {u32_toaltstack()}
        }
        for _ in 0..64 {
            {u32_drop()}
        }
        {u8_drop_xor_table()}

        for _ in 0..8 {
            {u32_fromaltstack()}
        }
    }
}

pub fn sha256_32bytes() -> Script {
    script! {
        {push_reverse_bytes_to_alt(32)}

        // top of stack: [ [n bytes input] ]
        {u8_push_xor_table()}
        {sha256_k()}
        // top of stack: [ [64 byte chunks]... ]
        {padding_add_roll(32)}
        {sha256_init()}
        // top of stack: [ [64 byte chunks]..., state[0-7]]
        {sha256_transform_32bytes(8 + 16 + 64 + 1, 8 + 16)}

        {sha256_final()}
        for _ in 0..8 {
            {u32_toaltstack()}
        }
        for _ in 0..64 {
            {u32_drop()}
        }
        {u8_drop_xor_table()}

        for _ in 0..8 {
            {u32_fromaltstack()}
        }
    }
}

pub fn sha256_80bytes() -> Script {
    script! {
        {push_reverse_bytes_to_alt(80)}

        // top of stack: [ [n bytes input] ]
        {u8_push_xor_table()}
        {sha256_k()}
        // top of stack: [ [64 byte chunks]... ]
        {padding_add_roll(80)}
        {sha256_init()}
        // top of stack: [ [64 byte chunks]..., state[0-7]]
        // chunk 1
        {sha256_transform(8 + 2 * 16 + 64 + 1, 8 + 2 * 16)}
        // chunk 2
        {sha256_transform_80bytes_chunk2(8 + 16 + 64 + 1, 8 + 16)}

        {sha256_final()}
        for _ in 0..8 {
            {u32_toaltstack()}
        }
        for _ in 0..64 {
            {u32_drop()}
        }
        {u8_drop_xor_table()}

        for _ in 0..8 {
            {u32_fromaltstack()}
        }
    }
}

/// reorder bytes for u32
pub fn padding_add_roll(num_bytes: usize) -> Script {
    assert!(num_bytes < 512);
    let padding_num = if (num_bytes % 64) < 56 {
        55 - (num_bytes % 64)
    } else {
        64 + 55 - (num_bytes % 64)
    };

    let u32_num = (num_bytes + padding_num + 9) / 4;
    script! {
        for _ in 0..num_bytes {
            OP_FROMALTSTACK
        }
        {0x80}
        {push_to_stack(0,padding_num)}
        {u32_push(0)}
        {u32_push((num_bytes as u32) * 8)}

        for i in 1..u32_num {
            {u32_roll(i as u32)}
        }
    }
}

/// push all init state into stack
pub fn sha256_init() -> Vec<Script> {
    let mut state: [u32; 8] = INITSTATE;
    state.reverse();
    state.iter().map(|x: &u32| u32_push(*x)).collect::<Vec<_>>()
}

/// Change byte order, because SHA uses big endian.
pub fn sha256_final() -> Script {
    script! {
        for _ in 0..8 {
            OP_SWAP
            OP_2SWAP
            OP_SWAP
            {u32_toaltstack()}
        }
        for _ in 0..8 {
            {u32_fromaltstack()}
        }
    }
}

/// push other necessary state into stack
pub fn sha256_k() -> Vec<Script> {
    let mut state: [u32; 64] = K;
    state.reverse();
    state.iter().map(|x: &u32| u32_push(*x)).collect::<Vec<_>>()
}

/// sha256 transform
/// input: [m[15], m[14], ..., m[0], state[7], state[6], ..., state[0]]
/// output: [state[7], state[6], ..., state[0]]
pub fn sha256_transform(xor_depth: u32, k_depth: u32) -> Script {
    script! {
        // push old state to alt stack
        for _ in 0..8 {
            {u32_toaltstack()}
        }

        // reverse for 16 u32 data
        for i in 1..16 {
            {u32_roll(i)}
        }

        // reorg data
        for i in 16..64 {
            {u32_pick(1)}
            {sig1(xor_depth - 6 + i-16 - 1)}

            {u32_pick(7)}
            {u32_add_drop(0, 1)}

            {u32_pick(15)}
            {sig0(xor_depth - 6 + i-16)}
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

        // already increase 48 elements in the stack
        // now loop for transform [h, g, f, e, d, c, b, a]
        for i in 0..64 {
            // t1 for reuse
            {u32_toaltstack()}
            {u32_toaltstack()}
            {u32_toaltstack()}
            {u32_toaltstack()}

            // [h, g, f, e]
            {u32_roll(3)} // [g, f, e, h]
            {u32_pick(1)} // [g, f, e, h, e]
            {ep1(xor_depth+45)}
            {u32_add_drop(0, 1)} // [g, f, e, tmp_t1]
            {ch(1, 2, 3, xor_depth+44)}
            {u32_add_drop(0, 1)}

            {u32_pick(k_depth+44+i)} // pick k
            {u32_add_drop(0, 1)}

            {u32_pick(4+63-i)} // pick m
            {u32_add_drop(0, 1)}

            // [g, f, e, t1]

            {u32_dup()}
            {u32_fromaltstack()} // [g, f, e, t1, t1, d]
            {u32_add_drop(0, 1)} // [g, f, e, t1, t1 + d]

            {u32_fromaltstack()}
            {u32_fromaltstack()}
            {u32_fromaltstack()} // [g, f, e, t1, t1+d, c, b, a]
            {u32_roll(4)} // [g, f, e, t1+d, c, b, a, t1]

            {u32_pick(1)}
            {ep0(xor_depth+49)}
            {u32_add_drop(0, 1)}

            {maj(1, 2, 3, xor_depth+48)}
            {u32_add_drop(0, 1)}
            // [g, f, e, t1+d, c, b, a, t1+t2]
        }

        for _ in 0..8 {
            {u32_fromaltstack()} // get old state
        }

        // add new state and old state
        for i in 0..8 {
            {u32_roll(8-i)}
            {u32_add_drop(0, 1)}
            {u32_toaltstack()}
        }

        for _ in 0..64 {
            {u32_drop()} // drop m table
        }

        for _ in 0..8 {
            {u32_fromaltstack()}
        }
    }
}

pub fn sha256_transform_32bytes(xor_depth: u32, k_depth: u32) -> Script {
    script! {
        // push old state to alt stack
        for _ in 0..8 {
            {u32_toaltstack()}
        }

        // reverse for 16 u32 data
        for i in 1..16 {
            {u32_roll(i)}
        }

        // reorg data

        // i = 16, m_16 = m_0 + sig0(m_1)
        {u32_pick(14)}
        {sig0(xor_depth - 7)}

        {u32_pick(16)}
        {u32_add_drop(0, 1)}

        // i = 17, m_17 = m_1 + sig0(m_2) + sig1(256)
        {u32_push(0x00a00000)} // sig1(256)

        {u32_pick(15)}
        {sig0(xor_depth - 5)}
        {u32_add_drop(0, 1)}

        {u32_pick(16)}
        {u32_add_drop(0, 1)}

        // i = 18, m_18 = m_2 + sig0(m_3) + sig1(m_16)
        {u32_pick(1)}
        {sig1(xor_depth - 5)}

        {u32_pick(15)}
        {sig0(xor_depth - 4)}
        {u32_add_drop(0, 1)}

        {u32_pick(16)}
        {u32_add_drop(0, 1)}

        // i = 19, m_19 = m_3 + sig0(m_4) + sig1(m_17)
        {u32_pick(1)}
        {sig1(xor_depth - 4)}

        {u32_pick(15)}
        {sig0(xor_depth - 3)}
        {u32_add_drop(0, 1)}

        {u32_pick(16)}
        {u32_add_drop(0, 1)}

        // i = 20, m_20 = m_4 + sig0(m_5) + sig1(m_18)
        {u32_pick(1)}
        {sig1(xor_depth - 3)}

        {u32_pick(15)}
        {sig0(xor_depth - 2)}
        {u32_add_drop(0, 1)}

        {u32_pick(16)}
        {u32_add_drop(0, 1)}

        // i = 21, m_21 = m_5 + sig0(m_6) + sig1(m_19)
        {u32_pick(1)}
        {sig1(xor_depth - 2)}

        {u32_pick(15)}
        {sig0(xor_depth - 1)}
        {u32_add_drop(0, 1)}

        {u32_pick(16)}
        {u32_add_drop(0, 1)}

        // i = 22, m_22 = m_6 + sig0(m_7) + 256 + sig1(m_20)
        {u32_pick(1)}
        {sig1(xor_depth - 1)}

        {u32_push(256)}
        {u32_add_drop(0, 1)}

        {u32_pick(15)}
        {sig0(xor_depth)}
        {u32_add_drop(0, 1)}

        {u32_pick(16)}
        {u32_add_drop(0, 1)}

        // i = 23, m_23 = m_7 + sig0(0b10...0) + m_16 + sig1(m_21)
        {u32_pick(1)}
        {sig1(xor_depth)}

        {u32_pick(7)}
        {u32_add_drop(0, 1)}

        {u32_push(0x11002000)} // sig0(0b10...0)
        {u32_add_drop(0, 1)}

        {u32_pick(16)}
        {u32_add_drop(0, 1)}

        // i = 24, m_24 = 0b10...0 + m_17 + sig1(m_22)
        {u32_pick(1)}
        {sig1(xor_depth + 1)}

        {u32_pick(7)}
        {u32_add_drop(0, 1)}

        {u32_push(0x80000000)}
        {u32_add_drop(0, 1)}

        // i = 25..30, m_i = m_{i-7} + sig1(m_{i-2})
        for i in 25..30 {
            {u32_pick(1)}
            {sig1(xor_depth - 6 + i - 16 - 1)}

            {u32_pick(7)}
            {u32_add_drop(0, 1)}
        }

        // i = 30, m_30 = sig0(256) + m_23 + sig1(m_28)
        {u32_pick(1)}
        {sig1(xor_depth + 7)}

        {u32_pick(7)}
        {u32_add_drop(0, 1)}

        {u32_push(0x00400022)}  // sig0(256)
        {u32_add_drop(0, 1)}

        // i = 31, m_31 = 256 + sig0(m_16) + m_24 + sig1(m_29)
        {u32_pick(1)}
        {sig1(xor_depth + 8)}

        {u32_pick(7)}
        {u32_add_drop(0, 1)}

        {u32_pick(15)}
        {sig0(xor_depth + 9)}
        {u32_add_drop(0, 1)}

        {u32_push(256)}
        {u32_add_drop(0, 1)}

        for i in 32..64 {
            {u32_pick(1)}
            {sig1(xor_depth - 6 + i - 16 - 1)}

            {u32_pick(7)}
            {u32_add_drop(0, 1)}

            {u32_pick(15)}
            {sig0(xor_depth - 6 + i - 16)}
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

        // already increase 48 elements in the stack
        // now loop for transform [h, g, f, e, d, c, b, a]
        for i in 0..64 {
            // t1 for reuse
            {u32_toaltstack()}
            {u32_toaltstack()}
            {u32_toaltstack()}
            {u32_toaltstack()}

            // [h, g, f, e]
            {u32_roll(3)} // [g, f, e, h]
            {u32_pick(1)} // [g, f, e, h, e]
            {ep1(xor_depth+45)}
            {u32_add_drop(0, 1)} // [g, f, e, tmp_t1]
            {ch(1, 2, 3, xor_depth+44)}
            {u32_add_drop(0, 1)}

            {u32_pick(k_depth+44+i)} // pick k
            {u32_add_drop(0, 1)}

            {u32_pick(4+63-i)} // pick m
            {u32_add_drop(0, 1)}

            // [g, f, e, t1]

            {u32_dup()}
            {u32_fromaltstack()} // [g, f, e, t1, t1, d]
            {u32_add_drop(0, 1)} // [g, f, e, t1, t1 + d]

            {u32_fromaltstack()}
            {u32_fromaltstack()}
            {u32_fromaltstack()} // [g, f, e, t1, t1+d, c, b, a]
            {u32_roll(4)} // [g, f, e, t1+d, c, b, a, t1]

            {u32_pick(1)}
            {ep0(xor_depth+49)}
            {u32_add_drop(0, 1)}

            {maj(1, 2, 3, xor_depth+48)}
            {u32_add_drop(0, 1)}
            // [g, f, e, t1+d, c, b, a, t1+t2]
        }

        for _ in 0..8 {
            {u32_fromaltstack()} // get old state
        }

        // add new state and old state
        for i in 0..8 {
            {u32_roll(8-i)}
            {u32_add_drop(0, 1)}
            {u32_toaltstack()}
        }

        for _ in 0..64 {
            {u32_drop()} // drop m table
        }

        for _ in 0..8 {
            {u32_fromaltstack()}
        }
    }
}

pub fn sha256_transform_80bytes_chunk2(xor_depth: u32, k_depth: u32) -> Script {
    script! {
        // push old state to alt stack
        for _ in 0..8 {
            {u32_toaltstack()}
        }

        // reverse for 16 u32 data
        for i in 1..16 {
            {u32_roll(i)}
        }

        // reorg data

        // i = 16, m_16 = m_0 + sig0(m_1)
        {u32_pick(14)}
        {sig0(xor_depth - 7)}

        {u32_pick(16)}
        {u32_add_drop(0, 1)}

        // i = 17, m_17 = m_1 + sig0(m_2) + sig1(640)
        {u32_push(0x01100000)} // sig1(640)

        {u32_pick(15)}
        {sig0(xor_depth - 5)}
        {u32_add_drop(0, 1)}

        {u32_pick(16)}
        {u32_add_drop(0, 1)}

        // i = 18, m_18 = m_2 + sig0(m_3) + sig1(m_16)
        {u32_pick(1)}
        {sig1(xor_depth - 5)}

        {u32_pick(15)}
        {sig0(xor_depth - 4)}
        {u32_add_drop(0, 1)}

        {u32_pick(16)}
        {u32_add_drop(0, 1)}

        // i = 19, m_19 = m_3 + sig0(0b10...0) + sig1(m_17)
        {u32_pick(1)}
        {sig1(xor_depth - 4)}

        {u32_push(0x11002000)} // sig0(0b10...0)
        {u32_add_drop(0, 1)}

        {u32_pick(16)}
        {u32_add_drop(0, 1)}

        // i = 20, m_20 = 0b10...0 + sig1(m_18)
        {u32_pick(1)}
        {sig1(xor_depth - 3)}

        {u32_push(0x80000000)}
        {u32_add_drop(0, 1)}

        // i = 21, m_21 = sig1(m_19)
        {u32_pick(1)}
        {sig1(xor_depth - 2)}

        // i = 22, m_22 = 640 + sig1(m_20)
        {u32_pick(1)}
        {sig1(xor_depth - 1)}

        {u32_push(640)}
        {u32_add_drop(0, 1)}

        // i = 23..30, m_i = m_{i-7} + sig1(m_{i-2})
        for i in 23..30 {
            {u32_pick(1)}
            {sig1(xor_depth - 6 + i - 16 - 1)}

            {u32_pick(7)}
            {u32_add_drop(0, 1)}
        }

        // i = 30, m_30 = sig0(640) + m_23 + sig1(m_28)
        {u32_pick(1)}
        {sig1(xor_depth + 7)}

        {u32_pick(7)}
        {u32_add_drop(0, 1)}

        {u32_push(0x00a00055)}  // sig0(640)
        {u32_add_drop(0, 1)}

        // i = 31, m_31 = 640 + sig0(m_16) + m_24 + sig1(m_29)
        {u32_pick(1)}
        {sig1(xor_depth + 8)}

        {u32_pick(7)}
        {u32_add_drop(0, 1)}

        {u32_pick(15)}
        {sig0(xor_depth + 9)}
        {u32_add_drop(0, 1)}

        {u32_push(640)}
        {u32_add_drop(0, 1)}

        for i in 32..64 {
            {u32_pick(1)}
            {sig1(xor_depth - 6 + i - 16 - 1)}

            {u32_pick(7)}
            {u32_add_drop(0, 1)}

            {u32_pick(15)}
            {sig0(xor_depth - 6 + i - 16)}
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

        // already increase 48 elements in the stack
        // now loop for transform [h, g, f, e, d, c, b, a]
        for i in 0..64 {
            // t1 for reuse
            {u32_toaltstack()}
            {u32_toaltstack()}
            {u32_toaltstack()}
            {u32_toaltstack()}

            // [h, g, f, e]
            {u32_roll(3)} // [g, f, e, h]
            {u32_pick(1)} // [g, f, e, h, e]
            {ep1(xor_depth+45)}
            {u32_add_drop(0, 1)} // [g, f, e, tmp_t1]
            {ch(1, 2, 3, xor_depth+44)}
            {u32_add_drop(0, 1)}

            {u32_pick(k_depth+44+i)} // pick k
            {u32_add_drop(0, 1)}

            {u32_pick(4+63-i)} // pick m
            {u32_add_drop(0, 1)}

            // [g, f, e, t1]

            {u32_dup()}
            {u32_fromaltstack()} // [g, f, e, t1, t1, d]
            {u32_add_drop(0, 1)} // [g, f, e, t1, t1 + d]

            {u32_fromaltstack()}
            {u32_fromaltstack()}
            {u32_fromaltstack()} // [g, f, e, t1, t1+d, c, b, a]
            {u32_roll(4)} // [g, f, e, t1+d, c, b, a, t1]

            {u32_pick(1)}
            {ep0(xor_depth+49)}
            {u32_add_drop(0, 1)}

            {maj(1, 2, 3, xor_depth+48)}
            {u32_add_drop(0, 1)}
            // [g, f, e, t1+d, c, b, a, t1+t2]
        }

        for _ in 0..8 {
            {u32_fromaltstack()} // get old state
        }

        // add new state and old state
        for i in 0..8 {
            {u32_roll(8-i)}
            {u32_add_drop(0, 1)}
            {u32_toaltstack()}
        }

        for _ in 0..64 {
            {u32_drop()} // drop m table
        }

        for _ in 0..8 {
            {u32_fromaltstack()}
        }
    }
}

/// Shift right the top u32 element
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

/// Change top element x to (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
pub fn ep0(stack_depth: u32) -> Script {
    script! {
        {u32_dup()}
        {u32_dup()}
        {u32_toaltstack()}
        {u32_toaltstack()}

        {u32_rrot(2)}
        {u32_fromaltstack()}
        {u32_rrot(13)}
        {u32_fromaltstack()}
        {u32_rrot(22)}

        {u32_xor(0, 1, stack_depth+2)}
        {u32_xor(0, 2, stack_depth+2)}

        // clean stack
        {u32_toaltstack()}
        {u32_drop()}
        {u32_drop()}
        {u32_fromaltstack()}
    }
}

/// Change top element x to (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
pub fn ep1(stack_depth: u32) -> Script {
    script! {
        {u32_dup()}
        {u32_dup()}
        {u32_toaltstack()}
        {u32_toaltstack()}

        {u32_rrot(6)}
        {u32_fromaltstack()}
        {u32_rrot(11)}
        {u32_fromaltstack()}
        {u32_rrot(25)}

        {u32_xor(0, 1, stack_depth+2)}
        {u32_xor(0, 2, stack_depth+2)}

        // clean stack
        {u32_toaltstack()}
        {u32_drop()}
        {u32_drop()}
        {u32_fromaltstack()}
    }
}

pub fn u32_not() -> Script {
    script! {
        for _ in 0..4 {
            0xff
            4 OP_ROLL OP_SUB
        }
    }
}

/// Push reversed bytes to the alt stack.
pub fn push_reverse_bytes_to_alt(num_bytes: usize) -> Script {
    script! {
        for i in 1..=num_bytes {
            {num_bytes-i} OP_ROLL
            OP_TOALTSTACK
        }
    }
}

/// Push (((x) & (y)) ^ (~(x) & (z))) into stack
pub fn ch(x: u32, y: u32, z: u32, stack_depth: u32) -> Script {
    script! {
        {u32_pick(x)}
        {u32_pick(y+1)}
        {u32_and(0, 1, stack_depth+2)}
        {u32_toaltstack()}
        {u32_drop()}
        {u32_fromaltstack()}

        {u32_pick(x+1)}
        {u32_not()}
        {u32_pick(z+2)}
        {u32_and(0, 1, stack_depth+3)}
        {u32_toaltstack()}
        {u32_drop()}
        {u32_fromaltstack()}

        {u32_xor(0, 1, stack_depth+2)}
        {u32_toaltstack()}
        {u32_drop()}
        {u32_fromaltstack()}
    }
}

/// Push (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z))) into stack
pub fn maj(x: u32, y: u32, z: u32, stack_depth: u32) -> Script {
    script! {
        {u32_pick(x)}
        {u32_pick(y+1)}
        {u32_and(0, 1, stack_depth+2)}
        {u32_toaltstack()}
        {u32_drop()}
        {u32_fromaltstack()}

        {u32_pick(x+1)}
        {u32_pick(z+2)}
        {u32_and(0, 1, stack_depth+3)}
        {u32_toaltstack()}
        {u32_drop()}
        {u32_fromaltstack()}

        {u32_pick(y+2)}
        {u32_pick(z+3)}
        {u32_and(0, 1, stack_depth+4)}
        {u32_toaltstack()}
        {u32_drop()}
        {u32_fromaltstack()}

        {u32_xor(0, 1, stack_depth+3)}
        {u32_xor(0, 2, stack_depth+3)}

        // clean stack
        {u32_toaltstack()}
        {u32_drop()}
        {u32_drop()}
        {u32_fromaltstack()}

    }
}

pub fn sha256_verify_output_script(expected_output: [u8; 32]) -> Script {
    script! {
        for byte in expected_output.iter().take(31) {
            {*byte}            
            OP_EQUALVERIFY
        }

        {expected_output[31]}
        OP_EQUAL
    }
}

pub fn sha256_push_message(message: &[u8]) -> Script {
    script! {
        for byte in message.iter().rev() { // SHA takes input as BE
            {*byte}
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::hash::sha256::*;
    use crate::treepp::{execute_script, script};
    use crate::u32::u32_std::{u32_equal, u32_equalverify};
    use sha2::{Digest, Sha256};

    fn push_bytes_hex(hex: &str) -> Script {
        let hex: String = hex
            .chars()
            .filter(|c| c.is_ascii_digit() || c.is_ascii_alphabetic())
            .collect();

        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect::<Vec<u8>>();
        
        script! {
            for byte in bytes.iter().rev() {
                { *byte }
            }
        }
    }

    fn rrot(x: u32, n: usize) -> u32 {
        if n == 0 {
            return x;
        }
        (x >> n) | (x << (32 - n))
    }

    #[test]
    fn test_sha256() {
        println!("sha256(32): {} bytes", sha256(32).len());
        println!("sha256(80): {} bytes", sha256(80).len());
        println!(
            "sha256 chunk: {} bytes",
            sha256_transform(8 + 16 + 64 + 1, 8 + 16).len()
        );
        let hex_in = "6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f70716f7071727071727371727374727374757374757674757677";
        let mut hasher = Sha256::new();
        let data = hex::decode(hex_in).unwrap();
        hasher.update(&data);
        let mut result = hasher.finalize();
        hasher = Sha256::new();
        hasher.update(result);
        result = hasher.finalize();
        let res = hex::encode(result);
        let script = script! {
            {push_bytes_hex(hex_in)}
            {sha256(hex_in.len()/2)}
            {sha256(32)}
            {push_bytes_hex(res.as_str())}
            for _ in 0..32 {
                OP_TOALTSTACK
            }

            for i in 1..32 {
                {i}
                OP_ROLL
            }

            for _ in 0..32 {
                OP_FROMALTSTACK
                OP_EQUALVERIFY
            }
            OP_TRUE
        };
        let res = execute_script(script);
        assert!(res.success);
    }

    #[test]
    fn test_padding_add_roll() {
        let hex_in = "6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071";

        let stack_out: [u32; 32] = [
            0x61626364, 0x62636465, 0x63646566, 0x64656667, 0x65666768, 0x66676869, 0x6768696a,
            0x68696a6b, 0x696a6b6c, 0x6a6b6c6d, 0x6b6c6d6e, 0x6c6d6e6f, 0x6d6e6f70, 0x6e6f7071,
            0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000000, 0x00000000, 0x000001c0,
        ];

        let script = script! {
            {push_bytes_hex(hex_in)}
            {push_reverse_bytes_to_alt(hex_in.len()/2)}
            {u8_push_xor_table()}
            {sha256_k()}
            {padding_add_roll(hex_in.len()/2)}
            for i in 0..32 {
                {u32_push(stack_out[i])}
                {u32_equalverify()} //
            }
        };
        execute_script(script);
        // assert!(res.success);
        // println!("result {:100}", res);
    }

    #[test]
    fn test_maj() {
        let x: u32 = 12;
        let y: u32 = 38;
        let z: u32 = 97;
        let result: u32 = (x & y) ^ (x & z) ^ (y & z);
        let script = script! {
            {u8_push_xor_table()}
            {u32_push(z)}
            {u32_push(y)}
            {u32_push(x)}
            {maj(0, 1, 2, 4)}
            {u32_toaltstack()}
            {u32_drop()}
            {u32_drop()}
            {u32_drop()}
            {u8_drop_xor_table()}
            {u32_fromaltstack()}

            {u32_push(result)}
            {u32_equal()}
        };
        let res = execute_script(script);
        assert!(res.success);
    }

    #[test]
    fn test_ch() {
        let x: u32 = 12;
        let y: u32 = 38;
        let z: u32 = 97;
        let result: u32 = (x & y) ^ ((!x) & z);
        let script = script! {
            {u8_push_xor_table()}
            {u32_push(z)}
            {u32_push(y)}
            {u32_push(x)}
            {ch(0, 1, 2, 4)}
            {u32_toaltstack()}
            {u32_drop()}
            {u32_drop()}
            {u32_drop()}
            {u8_drop_xor_table()}
            {u32_fromaltstack()}

            {u32_push(result)}
            {u32_equal()}
        };
        let res = execute_script(script);
        assert!(res.success);
    }

    #[test]
    fn test_ep1() {
        let x: u32 = 12;
        let result: u32 = rrot(x, 6) ^ rrot(x, 11) ^ rrot(x, 25);
        let script = script! {
            {u8_push_xor_table()}
            {u32_push(x)}
            {ep1(2)}
            {u32_toaltstack()}
            {u8_drop_xor_table()}
            {u32_fromaltstack()}

            {u32_push(result)}
            {u32_equal()}
        };
        let res = execute_script(script);
        assert!(res.success);
    }

    #[test]
    fn test_ep0() {
        let x: u32 = 12;
        let result: u32 = rrot(x, 2) ^ rrot(x, 13) ^ rrot(x, 22);
        let script = script! {
            {u8_push_xor_table()}
            {u32_push(x)}
            {ep0(2)}
            {u32_toaltstack()}
            {u8_drop_xor_table()}
            {u32_fromaltstack()}

            {u32_push(result)}
            {u32_equal()}
        };
        let res = execute_script(script);
        assert!(res.success);
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

            {u32_push(result)}
            {u32_equal()}
        };
        let res = execute_script(script);
        assert!(res.success);
    }

    #[test]
    fn test_sig1() {
        let x: u32 = 12;
        let result: u32 = rrot(x, 17) ^ rrot(x, 19) ^ (x >> 10);
        let script = script! {
            {u8_push_xor_table()}
            {u32_push(x)}
            {sig1(2)}
            {u32_toaltstack()}
            {u8_drop_xor_table()}
            {u32_fromaltstack()}

            {u32_push(result)}
            {u32_equal()}
        };
        let res = execute_script(script);
        assert!(res.success);
    }

    #[test]
    fn test_transform_data() {
        let input: [u32; 16] = [
            0x61626364, 0x62636465, 0x63646566, 0x64656667, 0x65666768, 0x66676869, 0x6768696a,
            0x68696a6b, 0x696a6b6c, 0x6a6b6c6d, 0x6b6c6d6e, 0x6c6d6e6f, 0x6d6e6f70, 0x6e6f7071,
            0x80000000, 0x00000000,
        ];

        let output: [u32; 8] = [
            0x85e655d6, 0x417a1795, 0x3363376a, 0x624cde5c, 0x76e09589, 0xcac5f811, 0xcc4b32c1,
            0xf20e533a,
        ];

        let script = script! {

            // push xor table
            {u8_push_xor_table()}

            // push k
            for i in 0..64 {
                {u32_push(K[63-i])}
            }

            for i in 0..16 {
                {u32_push(input[15-i])}
            }
            for i in 0..8 {
                {u32_push(INITSTATE[7-i])}
            }

            {sha256_transform(89, 24)}

            for i in 0..8 {
                {u32_push(output[i])}
                {u32_equalverify()} // panic if verify fail
            }

            for _ in 0..64 {
                {u32_drop()}
            }

            {u8_drop_xor_table()}
        };

        let res = execute_script(script);
        assert_eq!(res.final_stack.len(), 0);
    }

    #[test]
    fn test_genesis_block() {
        // the genesis block header of bitcoin
        // version previous-block merkle-root time bits nonce
        // 01000000 0000000000000000000000000000000000000000000000000000000000000000 3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a 29ab5f49 ffff001d 1dac2b7c
        let block_header = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c";
        let mut hasher = Sha256::new();
        let data = hex::decode(block_header).unwrap();
        hasher.update(&data);
        let mut result = hasher.finalize();
        hasher = Sha256::new();
        hasher.update(result);
        result = hasher.finalize();
        let res = hex::encode(result);
        let genesis_block_hash = "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000";
        assert_eq!(res.as_str(), genesis_block_hash);
        let script = script! {
            {push_bytes_hex(block_header)}
            {sha256(80)}
            {sha256(32)}
            {push_bytes_hex(res.as_str())}
            for _ in 0..32 {
                OP_TOALTSTACK
            }

            for i in 1..32 {
                {i}
                OP_ROLL
            }

            for _ in 0..32 {
                OP_FROMALTSTACK
                OP_EQUALVERIFY
            }
            OP_TRUE
        };
        let res = execute_script(script);
        assert!(res.success);
    }
}
