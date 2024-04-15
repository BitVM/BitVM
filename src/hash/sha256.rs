#![allow(non_snake_case)]
use std::collections::HashMap;

use crate::treepp::{pushable, script, Script};
use crate::u32::u32_std::{u32_equalverify, u32_roll};
use crate::u32::{
    u32_add::u32_add,
    u32_rrot::*,
    u32_std::*,
    u32_and::*,
    u32_xor::{u32_xor, u8_drop_xor_table, u8_push_xor_table},
    // unroll,
};

//
// Environment
//

// A pointer to address elements on the stack
#[derive(Eq, Hash, PartialEq, Debug, Clone, Copy)]
pub enum Ptr {
    State(u32),
    Message(u32),
    Tmp(u32),
    K32(u32),
}

pub fn S(i: u32) -> Ptr { Ptr::State(i) }

pub fn M(i: u32) -> Ptr { Ptr::Message(i) }

pub fn T(i: u32) -> Ptr { Ptr::Tmp(i) }
pub fn K(i: u32) -> Ptr { Ptr::K32(i) }

// An environment to track elements on the stack
type Env = HashMap<Ptr, u32>;

// make the stack as: [K32] [xor_table] [State] [Message]
// The script size is: 809743
// while [Message] [K32] [xor_table] [State], the script size is: 901769
// while [K32] [xor_table] [Message] [State], the script size is: 802441
pub fn ptr_init_1() -> Env { 
    // Initial positions for state and message
    let mut env: Env = Env::new();
    // make the stack as: [K32] [xor_table] [State] [Message]
    for i in 0..MESSAGE_SIZE {
        env.insert(M(i), i);
    }

    for i in 0..INITIAL_STATE_SIZE {
        // The State's offset is the Message size
        env.insert(S(i), i + MESSAGE_SIZE);     
    }
    
    for i in 0..K32_SIZE {
        // The k32's offset is the size of the state
        // plus the u32 size of our XOR table, plus the K32_SIZE
        env.insert(K(i), i + MESSAGE_SIZE + INITIAL_STATE_SIZE + XOR_TABLE_SIZE);
    }
    
    env
}

// make the stack as: [K32] [xor_table] [Message] [State] 
pub fn ptr_init() -> Env { 
    // Initial positions for state and message
    let mut env: Env = Env::new();
    // make the stack as: [K32] [xor_table] [Message] [State] 
    for i in 0..INITIAL_STATE_SIZE {
        env.insert(S(i), i );     
    }

    for i in 0..MESSAGE_SIZE {
        // The Message's offset is the State size
        env.insert(M(i), i + INITIAL_STATE_SIZE);
    }

    
    for i in 0..K32_SIZE {
        // The k32's offset is the size of the state
        // plus the u32 size of our XOR table, plus the K32_SIZE
        env.insert(K(i), i + MESSAGE_SIZE + INITIAL_STATE_SIZE + XOR_TABLE_SIZE);
    }
    
    env
}

pub trait EnvTrait {
    // Get the position of `ptr`
    fn ptr(&mut self, ptr: Ptr) -> u32;

    /// Get the position of `ptr`, then delete it
    fn ptr_extract(&mut self, ptr: Ptr) -> u32;

    /// Set the position of `ptr` to the top stack ptr
    fn ptr_insert(&mut self, ptr: Ptr);
}

impl EnvTrait for Env {
    fn ptr_insert(&mut self, ptr: Ptr) {
        for (_, value) in self.iter_mut() {
            *value += 1;
        }
        self.insert(ptr, 0);
    }

    fn ptr_extract(&mut self, ptr: Ptr) -> u32 {
        match self.remove(&ptr) {
            Some(index) => {
                for (_, value) in self.iter_mut() {
                    if index < *value {
                        *value -= 1;
                    }
                }
                index
            }
            None => panic!("{:?}", ptr),
        }
    }

    fn ptr(&mut self, ptr: Ptr) -> u32 { *self.get(&ptr).unwrap() }
}

//
// SHA256 Algorithm
//

const IV: [u32; 8] = [ //The initial value of SHA256 is the same as BLAKE3.
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

/// Round constants for SHA-256 family of digests
const K32: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const MSG_PERMUTATION: [u32; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];
const INITIAL_STATE_SIZE: u32 = 8;
const K32_SIZE: u32 = 64;
const MESSAGE_SIZE: u32 = 16;
const XOR_TABLE_SIZE: u32 = 256 / 4;
// for stack: [K32] [xor_table] [State] [Message]
//const STATE_TO_TOP_SIZE: u32 = MESSAGE_SIZE; 
//const XOR_TABLE_TO_TOP_SIZE: u32 = MESSAGE_SIZE + INITIAL_STATE_SIZE;

// for stack: [K32] [xor_table] [Message] [State] 
const STATE_TO_TOP_SIZE: u32 = 0; 
const XOR_TABLE_TO_TOP_SIZE: u32 = MESSAGE_SIZE + INITIAL_STATE_SIZE;

pub fn initial_state() -> Vec<Script> {
    let mut state = [
        IV[0]/* a */, IV[1]/* b */, IV[2]/* c */, IV[3]/* d */, IV[4]/* e */,           IV[5]/* f */, IV[6]/* g */, IV[7]/* h */,
       // 0,            0,            0,            0,            0/* \Sigma_1(e) */,     0/* Ch(e,f,g) */,     0,     0,    //reserved for free use
    ];

    state.reverse();//let state[0] be topper
    state.iter().map(|x| u32_push(*x)).collect::<Vec<_>>()
}

pub fn initial_message(message: &mut [u32;16]) -> Vec<Script> {
    //SHA256 is big-endian. Let m0 be topper.
    message.reverse();
    message.iter().map(|x| u32_push(*x)).collect::<Vec<_>>()
}

pub fn push_u8_to_mainstack(message: &mut [u8]) -> Script {
    message.reverse();
    script! {
        for i in (0..message.len()).step_by(4) {
            { message[i+3] }
            { message[i+2] }
            { message[i+1] }
            { message[i] }
        }
    }
}

pub fn push_u8_to_altstack(message: &[u8]) -> Script {
    //message.reverse(); // do not reverse for alt stack.
    script! {
        for i in (0..message.len()).step_by(4) {
            { message[i] } // different order from main stack
            { message[i+1] }
            { message[i+2] }
            { message[i+3] }
            
            {u32_toaltstack()}
        }
    }
}

pub fn push_K32() -> Vec<Script> {
    let mut k32 = K32.clone();

    k32.reverse();//let k32[0] be topper
    k32.iter().map(|x| u32_push(*x)).collect::<Vec<_>>()
}

// calc Ch(e,f,g)
fn Ch(env: &mut Env, ap: u32, e: Ptr, f: Ptr, g: Ptr, delta: u32) -> Script {
    let n_e = env.ptr(e) + delta;
    let n_f = env.ptr(f) + delta;
    let n_g = env.ptr(g) + delta;
    let script = script! {
        {u32_pick(n_g)} //stack: h g f e d c b a T0 | g 
        {u32_pick(n_e + 1)} //stack: h g f e d c b a T0 | g e
        {u32_pick(n_f + 2)} //stack: h g f e d c b a T0 | g e f
        
        // t1 = e & f
        {u32_and(1, 0, ap + 1 + 3)} //now already added 3 more elements on stack
        
        {u32_roll(1)} //pick `e` to top
        {u32_push(0xffff_ffff)} 

        // use xor to get !e
        {u32_xor(1, 0, ap + 1 + 4)} //now already added 4 more elements on stack
        
        {u32_roll(1)} //pick `e` to top
        {u32_drop()} //delete e
        {u32_roll(2)} //pick `g` to top

        // !e & g
        {u32_and(1, 0, ap + 1 + 3)} //now already added 3 more elements on stack
        
        {u32_roll(1)} //pick `!e` to top
        {u32_drop()} //delete !e

        //(e & f) ^ (!e & g)
        {u32_xor(1, 0, ap + 1 + 2)} //now already added 2 more elements on stack
        
        {u32_roll(1)} //pick `t1` to top
        {u32_drop()} //delete t1
        
    };
    
    //env.ptr_insert(result);

    script
}

// calc \Sigma_1(X)=RotR(X,6)\oplus RotR(X,11)\oplus RotR(X,25)
fn BIG_S1(env: &mut Env, ap: u32, e: Ptr, delta: u32) -> Script {
    let n = env.ptr(e) + delta;
    let script = script! {
        {u32_pick(n)} //stack: h g f e d c b a [delta]| e
        {u32_dup()} //stack: h g f e d c b a [delta]| e e
        {u32_dup()} //stack: h g f e d c b a [delta]| e e e
        u32_rrot25
        {u32_roll(1)} //move `e` to top
        u32_rrot11
        {u32_roll(2)} //move `e` to top
        u32_rrot6

        // RotR(X,6)\oplus RotR(X,11)
        {u32_xor(0, 1, ap + 1 + 3)} //now already added 3 more elements on stack
        {u32_roll(1)} //remove the duplicate value
        {u32_drop()}

        // RotR(X,6)\oplus RotR(X,11)\oplus RotR(X,25)
        {u32_xor(0, 1, ap + 1 + 2)} //now already added 2 more elements on stack
        {u32_roll(1)} //remove the duplicate value
        {u32_drop()}

    };
    script
}

// calc \Sigma_1(X)=RotR(X,2)\oplus RotR(X,13)\oplus RotR(X,22)
fn BIG_S0(env: &mut Env, ap: u32, a: Ptr, delta: u32) -> Script {
    let n = env.ptr(a) + delta;
    let script = script! {
        {u32_pick(n)} //stack: h g f e d c b a T0| a
        {u32_dup()} //stack: h g f e d c b a T0| a a 
        {u32_dup()} //stack: h g f e d c b a T0| a a a
        u32_rrot22
        {u32_roll(1)} //pick `a` to top
        u32_rrot13
        {u32_roll(2)} //pick `a` to top
        u32_rrot2

        // RotR(X,2)\oplus RotR(X,13)
        {u32_xor(0, 1, ap + 1 + 3)} //now already added 3 more elements on stack
        {u32_roll(1)} //remove the duplicate value
        {u32_drop()}

        // RotR(X,2)\oplus RotR(X,13)\oplus RotR(X,22)
        {u32_xor(0, 1, ap + 1 + 2)} //now already added 2 more elements on stack
        {u32_roll(1)} //remove the duplicate value
        {u32_drop()}

    };

    script
}

// calc temp1 = h + \Sigma_1(e) + Ch(e,f,g) + K_i + w
pub fn temp1(env: &mut Env, i: u32, i16: u32, delta: u32) -> Script {
    let n_h = env.ptr(S(7)) + delta;
    let n_Ki = env.ptr(K(i)) + delta;
    let n_Mi = env.ptr(M(i16)) + delta;
    let script = script! {
        //calc T2 = h + \Sigma_1(e) + Ch(e,f,g) + K_i + w
        //stack: h g f e d c b a T0 T1
        // calc t1 = h + T1
        {u32_pick(n_h)} //pick `h` to top
        {u32_add(1, 0)} //stack: h g f e d c b a T0 T1 | t1
        {u32_roll(1)}
        {u32_drop()}
        //stack: h g f e d c b a T0 | t1
        // calc t2 = t1 + T0
        {u32_add(0, 1)} //stack: h g f e d c b a | t1 t2

        // calc t3 = t2 + K_i
        {u32_pick(n_Ki)} //pick K_i
        {u32_add(0, 1)} //stack: h g f e d c b a | t1 K_i t3
        {u32_roll(1)}
        {u32_drop()}

        //stack: h g f e d c b a | t1 t3
        // calc t4 = t3 + M_i
        {u32_pick(n_Mi)} //pick M_i
        {u32_add(0, 1)} //stack: h g f e d c b a | t1 M_i t4
        {u32_roll(1)}
        {u32_drop()}
        //stack: h g f e d c b a | t1 t4

        {u32_roll(1)}
        {u32_drop()} //stack: h g f e d c b a | t4

    };

    script
}
// calc maj = (a & b) ^ (a & c) ^ (b & c)
pub fn maj(env: &mut Env, ap: u32, a: Ptr, b: Ptr, c: Ptr, delta: u32) -> Script {
    let n_a = env.ptr(a) + delta;
    let n_b = env.ptr(b) + delta;
    let n_c = env.ptr(c) + delta;
    let script = script! {
        
        //stack: h g f e d c b a T0 T1
        // while T0 is temp1, T1 is big_s0

        {u32_pick(n_a)} //stack: h g f e d c b a T0 T1| a
        {u32_pick(n_b+1)} //stack: h g f e d c b a T0 T1| a b
        {u32_pick(n_c+2)} //stack: h g f e d c b a T0 T1| a b c
        {u32_dup()}//stack: h g f e d c b a T0 T1| a b c c
        {u32_toaltstack()}
        //stack: h g f e d c b a T0 T1| a b c 
        //alt: c
        
        // t1 = b & c
        {u32_and(1, 0, ap + 1 + 3)} //now already added 3 more elements on stack
        //stack: h g f e d c b a T0 T1| a b t1
        {u32_roll(2)} //stack: h g f e d c b a T0 T1| b t1 a
        {u32_roll(2)} //stack: h g f e d c b a T0 T1| t1 a b

        // t2 = a & b
        {u32_and(1, 0, ap + 1 + 3)} //now already added 3 more elements on stack
        //stack: h g f e d c b a T0 T1| t1 a t2

        {u32_roll(1)} //stack: h g f e d c b a T0 T1| t1 t2 a
        {u32_fromaltstack()} //stack: h g f e d c b a T0 T1| t1 t2 a c
        //alt: 
        // t3 = a & c
        {u32_and(1, 0, ap + 1 + 4)} //now already added 4 more elements on stack
        //stack: h g f e d c b a T0 T1| t1 t2 a t3
        {u32_roll(1)} 
        {u32_drop()}
        //stack: h g f e d c b a T0 T1| t1 t2 t3

        // t4 = t2 ^ t3
        {u32_xor(1, 0, ap + 1 + 3)} //now already added 3 more elements on stack
        //stack: h g f e d c b a T0 T1| t1 t2 t4
        {u32_roll(1)} 
        {u32_drop()}
        //stack: h g f e d c b a T0 T1| t1 t4

        // t5 = t1 ^ t4
        {u32_xor(1, 0, ap + 1 + 2)} //now already added 2 more elements on stack
        //stack: h g f e d c b a T0 T1| t1 t5
        {u32_roll(1)} 
        {u32_drop()}
        //stack: h g f e d c b a T0 T1| t5 
    };
    script
}

pub fn round(env: &mut Env, ap: u32, i: u32, i16: u32) -> Script {
    let script = script! {
        // calc T0 = \Sigma_1(e)
        {BIG_S1(env, ap, S(4), 0) } // S(4)->e
        
        // now 1 more element on stack 
        // calc T1 = Ch(e,f,g)
        {Ch(env, ap + 1, S(4), S(5), S(6), 1)}

        // now 2 more element on stack 
        {temp1(env, i, i16, 2)}

        // now 1 more element on stack 
        {BIG_S0(env, ap + 1, S(0), 1) } // S(0)->a

        // now 2 more element on stack 
        {maj(env, ap + 2, S(0), S(1), S(2), 2) }

        // now 3 more element on stack 
        //stack: h g f e d c b a [STATE_TO_TOP_SIZE] T0 T1 T2
        // while T0 is temp1, T1 is big_s0, T2 is maj
        // calc T3=temp2=big_20+maj=T1+T2
        {u32_add(1, 0)} // stack: h g f e d c b a [STATE_TO_TOP_SIZE] T0 T1 | T3
        {u32_roll(1)}
        {u32_drop()} // stack: h g f e d c b a [STATE_TO_TOP_SIZE] T0 | T3

        //calc a'=temp1+temp2
        {u32_add(1, 0)}  // stack: h g f e d c b a [STATE_TO_TOP_SIZE] T0 | a'
        {u32_toaltstack()} // stack: h g f e d c b a [STATE_TO_TOP_SIZE] T0 
        // alt: a'

        // now 1 more element on stack
        {u32_pick(env.ptr(S(0))+1)} //a, 
        {u32_toaltstack()} // alt: a' b'

        {u32_pick(env.ptr(S(1))+1)} //b
        {u32_toaltstack()} // alt: a' b' c'

        {u32_pick(env.ptr(S(2))+1)} //c
        {u32_toaltstack()} // alt: a' b' c' d'

        // stack: h g f e d c b a T0 
        {u32_pick(env.ptr(S(3))+1)} //d
        {u32_add(1, 0)} //d+temp1
        {u32_toaltstack()} // alt: a' b' c' d' e'
        
        {u32_pick(env.ptr(S(4))+1)} //e
        {u32_toaltstack()} // alt: a' b' c' d' e' f'

        {u32_pick(env.ptr(S(5))+1)} //f
        {u32_toaltstack()} // alt: a' b' c' d' e' f' g'

        {u32_pick(env.ptr(S(6))+1)} //g
        {u32_toaltstack()} // alt: a' b' c' d' e' f' g' h'

        // stack: h g f e d c b a T0 
        {u32_drop()} // stack: h g f e d c b a

        for _ in 0..INITIAL_STATE_SIZE {
            {u32_fromaltstack()}
        }
        
        // stack: h g f e d c b a [STATE_TO_TOP_SIZE]| h‘ g’ f‘ e’ d‘ c’ b‘ a’
        // now 8 more elements on stack
        for _ in 0..INITIAL_STATE_SIZE {
            {u32_roll(INITIAL_STATE_SIZE + STATE_TO_TOP_SIZE)}
            {u32_drop()}
        }

        // TODO: can be optimized with env?
        // stack: [STATE_TO_TOP_SIZE] | h‘ g’ f‘ e’ d‘ c’ b‘ a’
        for _ in 0..STATE_TO_TOP_SIZE {
            {u32_roll(INITIAL_STATE_SIZE+STATE_TO_TOP_SIZE-1)}
        }
        // stack: h‘ g’ f‘ e’ d‘ c’ b‘ a’ [STATE_TO_TOP_SIZE] 
    };

    script

}

fn copy_state_to_altstack() -> Script {
    script!(
        for i in 0..INITIAL_STATE_SIZE {
            // stack: h g f e d c b a [STATE_TO_TOP_SIZE]
            {u32_pick(i + STATE_TO_TOP_SIZE)}
            {u32_toaltstack()} //alt: a b c d e f g h
        }
    )
}

//Script added cause we are getting Non pushable error otherwise, not sure how to...
pub fn permute(env: &mut Env) -> Script {
    let mut prev_env = Vec::new();
    for i in 0..16 {
        prev_env.push(env.ptr(M(i)));
    }

    for i in 0..16 {
        env.insert(M(i as u32), prev_env[MSG_PERMUTATION[i] as usize]);
    }

    return script! {};
}

fn u32_shr3(ap: u32) -> Script{
    let script = script!(
        u32_rrot3
        {u32_push(0xffff_ffff >> 3)}
        {u32_and(1, 0, ap + 1)} // 1 more element on stack
        {u32_roll(1)}
        {u32_drop()}
    );
    script
}
// calc \sigma_0(X)=RotR(X, 7)\oplus RotR(X,18)\oplus ShR(X,3)
fn SMALL_S0(env: &mut Env, ap: u32, m: Ptr, delta: u32) -> Script {
    let n = env.ptr(m) + delta;
    let script = script! {
        {u32_pick(n)} //stack: h g f e d c b a | m
        {u32_dup()} //stack: h g f e d c b a | m m
        {u32_dup()} //stack: h g f e d c b a | m m m
        {u32_shr3(ap + 1 + 3)} // already 3 more elements
        {u32_roll(1)} //move `m` to top
        u32_rrot18
        {u32_roll(2)} //move `m` to top
        u32_rrot7

        // RotR(X,7)\oplus RotR(X,18)
        {u32_xor(0, 1, ap + 1 + 3)} //now already added 3 more elements on stack
        {u32_roll(1)} //remove the duplicate value
        {u32_drop()}

        // RotR(X,7)\oplus RotR(X,18)\oplus ShR(X,3)
        {u32_xor(0, 1, ap + 1 + 2)} //now already added 2 more elements on stack
        {u32_roll(1)} //remove the duplicate value
        {u32_drop()}

    };

    script
}
fn u32_shr10(ap: u32) -> Script{
    let script = script!(
        u32_rrot10
        {u32_push(0xffff_ffff >> 10)}
        {u32_and(1, 0, ap + 1)} // 1 more element on stack
        {u32_roll(1)}
        {u32_drop()}
    );
    script
}
// calc \sigma_1(X)=RotR(X, 17)\oplus RotR(X,19)\oplus ShR(X,10)
fn SMALL_S1(env: &mut Env, ap: u32, m: Ptr, delta: u32) -> Script {
    let n = env.ptr(m) + delta;
    let script = script! {
        {u32_pick(n)} //stack: h g f e d c b a S0 | m
        {u32_dup()} //stack: h g f e d c b a S0 | m m
        {u32_dup()} //stack: h g f e d c b a S0 | m m m
        {u32_shr10(ap + 1 + 3)} // already 3 more elements
        {u32_roll(1)} //move `m` to top
        u32_rrot19
        {u32_roll(2)} //move `m` to top
        u32_rrot17

        // RotR(X,17)\oplus RotR(X,19)
        {u32_xor(0, 1, ap + 1 + 3)} //now already added 3 more elements on stack
        {u32_roll(1)} //remove the duplicate value
        {u32_drop()}

        // RotR(X,17)\oplus RotR(X,119)\oplus ShR(X,10)
        {u32_xor(0, 1, ap + 1 + 2)} //now already added 2 more elements on stack
        {u32_roll(1)} //remove the duplicate value
        {u32_drop()}

    };

    script
}

// for 16=<i<64, W[i]=\sigma_1(W[i-2]) + W[i-7] + \simga_0(W[i-15]) + W[i-16] 
fn calc_Wi(env: &mut Env, i: u32, i16: u32, delta: u32) -> Script {
    let n_mi16 = env.ptr(M(i16)) + delta;
    let n_m_i_9 = env.ptr(M((i+9) & 0xF)) + delta;
    let script = script! {
        // now 2 more elements on stack
        // stack: h g f e d c b a | S0 S1 
        {u32_pick(n_mi16)} //get w[i16]
        {u32_pick(n_m_i_9+1)} //get w[(i + 9) & 0xF]
        // stack: h g f e d c b a | S0 S1 w16 w9
        {u32_add(1, 0)} // t1=w16+w9
        {u32_roll(1)}
        {u32_drop()}
        //now 3 more element on stack
        // stack: h g f e d c b a | S0 S1 t1
        {u32_add(1, 0)} // t2=S1+t1
        {u32_roll(1)}
        {u32_drop()}
        //now 2 more element on stack
        // stack: h g f e d c b a | S0 t2
        {u32_add(1, 0)} // t3=S0+t2
        //now 2 more element on stack
        // stack: h g f e d c b a | S0 t3
        {u32_roll(1)}
        {u32_drop()}
        //now 1 more element on stack
        // stack: h g f e d c b a | t3

    };

    script
}
fn final_add() -> Script {
    script!(
        // stack: h g f e d c b a [STATE_TO_TOP_SIZE]
        // alt: a' b' c' d' e' f' g' h'
        for _ in 0..INITIAL_STATE_SIZE {
            {u32_roll(7 + STATE_TO_TOP_SIZE)} //h
            {u32_fromaltstack()} //h'
            {u32_add(1,0)}
            {u32_roll(1)}
            {u32_drop()}
        }
        // stack: [Message] h g f e d c b a
        // alt: 
    )
}

fn compress(env: &mut Env, ap: u32) -> Script {
    script! {
        for i in 0..16{ //16
            {round(env, ap, i, i & 0xF)}
        }

        for i in 16..64{ //64
            {SMALL_S0(env, ap, M((i+1) & 0xF), 0)}
            // now 1 more element on stack
            {SMALL_S1(env, ap+1, M((i+14) & 0xF), 1)}
            // now 2 more elements on stack
            // stack: h g f e d c b a | S0 S1 
            
            {calc_Wi(env, i, i & 0xF, 2)}
            
            //now 1 more element on stack
            // stack: h g f e d c b a | t3
            {save_wi16_swap(env, M(i & 0xF), 1)}
            
            //now no additional elements on stack
            // stack: h g f e d c b a wi16
            {round(env, ap, i, i & 0xF)}
        }

        {final_add()}
    }
}

fn save_wi16_swap(env: &mut Env, m: Ptr, delta: u32) -> Script {
    let n = env.ptr(m) + delta;

    let script = script!(
        for _ in 0..(n-1){
            {u32_roll(1)}
            {u32_toaltstack()}
        }
        //drop the specific element
        {u32_roll(1)}
        {u32_drop()}
        //put back others
        for _ in 0..(n-1){
            {u32_fromaltstack()}
        }
    );
    script
}

/// SHA256 taking a 64-byte padded message and returning a 32-byte digest
pub fn sha256(chunk_size: u32, message: &mut [u8], message_bak: &[u8]) -> Script {
    let mut env = ptr_init();
    let message_array: Vec<&[u8]> = message_bak.chunks(64).collect();
    let mut first_chunk =message[0..64].as_mut();

    let alt_message: Vec<&[u8]> = message_array[1..].to_vec();
    let script = script! {
        // Initialize K32 const
        {push_K32()}
        // Initialize our lookup table
        // We have to do that only once per program
        u8_push_xor_table

        // put first chunk message to main stack
        // back up the other chunks in alt stack
        {push_u8_to_mainstack(&mut first_chunk)}
        for i in 0..alt_message.len() {
            {push_u8_to_altstack(alt_message[alt_message.len()-1-i])} 
        }
        //{push_u8_to_altstack(alt_message[0])} // TODO. Only works for 2 chunks

        // Push the initial Blake state onto the stack
        {initial_state()}

        {copy_state_to_altstack()} //copy initial block state to alt stack

        // stack now is: [K32] [XOR_Table] [Message] [State]
        // Perform a round of SHA256
        {compress(&mut env, XOR_TABLE_TO_TOP_SIZE)}

        // stack now is: [K32] [XOR_Table] [Message] [State]
        for _ in 1..chunk_size{
            // put the previous state to alt stack
            for _ in 0..8{
                {u32_toaltstack()}
            }
            //drop the previous message chunk
            for _ in 0..MESSAGE_SIZE {
                {u32_drop()}
            }

            //put the previous state back to stack
            for _ in 0..8{
                {u32_fromaltstack()}
            }

            for _ in 0..MESSAGE_SIZE {
                {u32_fromaltstack()}
            }

            // stack now is: [K32] [XOR_Table] [State] [Message]
            for _ in 0..INITIAL_STATE_SIZE{
                {u32_roll(MESSAGE_SIZE+INITIAL_STATE_SIZE-1)}
            }

            // stack now is: [K32] [XOR_Table] [Message] [State]
            // alt stack: [uncompressed rest Message]
            // copy previous block state to alt stack
            {copy_state_to_altstack()}

            // stack now is: [K32] [XOR_Table] [Message] [State]
            // alt stack: [uncompressed rest Message] [State]
            // Perform a round of SHA256
            {compress(&mut env, XOR_TABLE_TO_TOP_SIZE)}
        }

        // Save the hash
        for _ in 0..8{
            {u32_toaltstack()}
        }

        // Clean up the input data and the other half of the state
        for _ in 0..K32_SIZE+MESSAGE_SIZE {
            {u32_drop()}
        }

        // Drop the lookup table
        u8_drop_xor_table

        // Load the hash
        for _ in 0..8{
            {u32_fromaltstack()}
        }
    };

    script
}

pub fn push_bytes_hex(hex: &str) -> Script {
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


pub fn push_sha256_bytes_hex(hex: &str) -> Script {
    let hex: String = hex
        .chars()
        .filter(|c| c.is_ascii_digit() || c.is_ascii_alphabetic())
        .collect();

    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect::<Vec<u8>>();

    script! {
        for byte in bytes.iter() {
            { *byte }
        }
    }
}

// follow this [padding algorithm](https://github.com/TheAlgorithms/Rust/blob/master/src/ciphers/sha256.rs#L165C13-L179C50)
pub fn pad(message: Vec<u8>) -> Vec<u8> { 
    let message_bit_len = message.len() * 8;
    let mut result = message.clone();
    let clen = (message_bit_len + 8) & 511;
    let num_0 = match clen.cmp(&448) {
        std::cmp::Ordering::Greater => (448 + 512 - clen) >> 3,
        _ => (448 - clen) >> 3,
    };
    let mut padding: Vec<u8> = vec![0_u8; (num_0 + 9) as usize];
    let len = padding.len();
    padding[0] = 0x80;
    padding[len - 8] = (message_bit_len >> 56) as u8;
    padding[len - 7] = (message_bit_len >> 48) as u8;
    padding[len - 6] = (message_bit_len >> 40) as u8;
    padding[len - 5] = (message_bit_len >> 32) as u8;
    padding[len - 4] = (message_bit_len >> 24) as u8;
    padding[len - 3] = (message_bit_len >> 16) as u8;
    padding[len - 2] = (message_bit_len >> 8) as u8;
    padding[len - 1] = message_bit_len as u8;
    
    result.extend(padding);
    result
}



#[cfg(test)]
mod tests {
    use crate::hash::sha256::*;

    use crate::treepp::{execute_script, script};
    use sha2::{Sha256, Digest};

    #[test]
    fn test_sha256_1_block() {
        //3 block size
        //let s = String::from("hello world hello world hello world hello world hello world hello world hello world hello world hello world hello world hello world hello world hello world hello world hello world");
        //2 block size
        //let s = String::from("hello world hello world hello world hello world hello world");
        //1 block size
        let s = String::from("hello world");
        
        let mut hasher = Sha256::new();
        hasher.update(s.clone());
        // Note that calling `finalize()` consumes hasher
        let expected_hash = hasher.finalize();
        println!("Expected hash: {:x}", expected_hash);

        // change [u8] to [u32]
        let mut hash_out: Vec<u32> = Vec::new();
        let hash_u8_array: Vec<&[u8]> = expected_hash.chunks(4).collect();
        for i in 0..hash_u8_array.len() {
            let b = hex::encode(&hash_u8_array[i]);
            hash_out.extend([(i64::from_str_radix(&b, 16).unwrap()) as u32 ])
        }

        let input = s.into_bytes();

        let message = pad(input);
        let msg_len = message.len() * 8; // multiply 8 for is u8 vector
        assert_eq!( msg_len % 512, 0);
        let chunk_size = (msg_len / 512) as u32;
        let script = script! {
            {sha256(chunk_size, &mut message.clone(), & message)}
            for i in 0..8{
                {u32_push(hash_out[i])}
                {u32_equalverify()}
            }
            OP_TRUE
        };
        let res = execute_script(script);
        assert!(res.success);
    }

    #[test]
    fn test_sha256_2_block() {
        //3 block size
        //let s = String::from("hello world hello world hello world hello world hello world hello world hello world hello world hello world hello world hello world hello world hello world hello world hello world");
        //2 block size
        let s = String::from("hello world hello world hello world hello world hello world");
        //1 block size
        //let s = String::from("hello world");
        
        let mut hasher = Sha256::new();
        hasher.update(s.clone());
        // Note that calling `finalize()` consumes hasher
        let expected_hash = hasher.finalize();
        println!("Expected hash: {:x}", expected_hash);

        // change [u8] to [u32]
        let mut hash_out: Vec<u32> = Vec::new();
        let hash_u8_array: Vec<&[u8]> = expected_hash.chunks(4).collect();
        for i in 0..hash_u8_array.len() {
            let b = hex::encode(&hash_u8_array[i]);
            hash_out.extend([(i64::from_str_radix(&b, 16).unwrap()) as u32 ])
        }

        let input = s.into_bytes();

        let message = pad(input);
        let msg_len = message.len() * 8; // multiply 8 for is u8 vector
        assert_eq!( msg_len % 512, 0);
        let chunk_size = (msg_len / 512) as u32;
        let script = script! {
            {sha256(chunk_size, &mut message.clone(), & message)}
            for i in 0..8{
                {u32_push(hash_out[i])}
                {u32_equalverify()}
            }
            OP_TRUE
        };
        let res = execute_script(script);
        assert!(res.success);
    }

    #[test]
    fn test_sha256_3_block() {
        //3 block size
        let s = String::from("hello world hello world hello world hello world hello world hello world hello world hello world hello world hello world hello world hello world hello world hello world hello world");
        //2 block size
        //let s = String::from("hello world hello world hello world hello world hello world");
        //1 block size
        //let s = String::from("hello world");
        
        let mut hasher = Sha256::new();
        hasher.update(s.clone());
        // Note that calling `finalize()` consumes hasher
        let expected_hash = hasher.finalize();
        println!("Expected hash: {:x}", expected_hash);

        // change [u8] to [u32]
        let mut hash_out: Vec<u32> = Vec::new();
        let hash_u8_array: Vec<&[u8]> = expected_hash.chunks(4).collect();
        for i in 0..hash_u8_array.len() {
            let b = hex::encode(&hash_u8_array[i]);
            hash_out.extend([(i64::from_str_radix(&b, 16).unwrap()) as u32 ])
        }

        let input = s.into_bytes();

        let message = pad(input);
        let msg_len = message.len() * 8; // multiply 8 for is u8 vector
        assert_eq!( msg_len % 512, 0);
        let chunk_size = (msg_len / 512) as u32;
        let script = script! {
            {sha256(chunk_size, &mut message.clone(), & message)}
            for i in 0..8{
                {u32_push(hash_out[i])}
                {u32_equalverify()}
            }
            OP_TRUE
        };
        let res = execute_script(script);
        assert!(res.success);
    }
}
