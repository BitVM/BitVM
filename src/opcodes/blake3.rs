#![allow(non_snake_case)]
#![allow(dead_code)]
use std::collections::HashMap;

use crate::opcodes::{
    u32_add::u32_add,
    u32_rrot::{u32_rrot12, u32_rrot16, u32_rrot7, u32_rrot8},
    u32_std::{u32_drop, u32_fromaltstack, u32_push, u32_roll, u32_toaltstack},
    u32_xor::{u32_drop_xor_table, u32_push_xor_table, u32_xor},
    unroll,
};

use super::pushable;
use bitcoin::ScriptBuf as Script;
use bitcoin_script::bitcoin_script as script;


// 
// Environment
// 

#[derive(Eq, Hash, PartialEq, Debug, Clone, Copy)]
enum Identifier {
    S(u32),
    M(u32)
}

type Env = HashMap<Identifier, u32>;


fn S(i: u32) -> Identifier {
    Identifier::S(i)
}

fn M(i: u32) -> Identifier {
    Identifier::M(i)
}

fn ptr_init() -> Env {
    // Initial positions for state and message
    let mut env: Env = Env::new();
    for i in 0..16 {
        env.insert(S(i), i);
        // The message's offset is the size of the state
        // plus the u32 size of our XOR table
        env.insert(M(i), i + 16 + 256 / 4);
    }
    env
}

fn ptr_init_160() -> Env {
    // Initial positions for state and message
    let mut env: Env = Env::new();
    for i in 0..16 {
        env.insert(S(i), i);
        // The message's offset is the size of the state
        // plus the u32 size of our XOR table
        let value: i32 = i as i32
            + 16
            + 256 / 4
            + match i < 10 {
                true => 6,
                false => -10,
            };
        env.insert(M(i), value as u32);
    }
    env
}

trait EnvTrait {
    /// Set the position of `identifier` to the top stack Identifier
    fn ptr_insert(&mut self, identifier: Identifier);
    
    /// Get the position of `identifier`, then delete it
    fn ptr_extract(&mut self, identifier: Identifier) -> u32;

    // Get the memory address of `identifier`
    fn address(&mut self, identifier: Identifier) -> u32;
}

impl EnvTrait for Env {
    fn ptr_insert(&mut self, identifier: Identifier) {
        for (_, value) in self.iter_mut() {
            *value += 1;
        }
        self.insert(identifier, 0);
    }

    fn ptr_extract(&mut self, identifier: Identifier) -> u32 {
        match self.remove(&identifier) {
            Some(index) => {
                for (_, value) in self.iter_mut() {
                    if index < *value {
                        *value -= 1;
                    }
                }
                index
            }
            None => panic!("{:?}", identifier),
        }
    }

    fn address(&mut self, identifier: Identifier) -> u32 {
        *self.get(&identifier).unwrap()
    }

}


// 
// Blake 3 
// 


const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

const MSG_PERMUTATION: [u32; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

fn initial_state(block_len: u32) -> Vec<Script> {
    let mut state = [
        IV[0], IV[1], IV[2], IV[3], IV[4], IV[5], IV[6], IV[7], IV[0], IV[1], IV[2], IV[3], 0, 0,
        block_len, 0b00001011,
    ];
    state.reverse();
    state.iter().map(|x| u32_push(*x)).collect::<Vec<_>>()
}




fn G(env: &mut Env, _ap: u32, a: Identifier, b: Identifier, c: Identifier, d: Identifier, m0: Identifier, m1: Identifier) -> Script {
    let script = script! {
        // z = a+b+m0
        {u32_add(env.address(b), env.ptr_extract(a))}
        {u32_add(env.address(m0) + 1, 0)}
        // Stack:  m1 m0 d c b  |  z

        // y = (d^z) >>> 16
        {u32_xor(0, env.ptr_extract(d) + 1, _ap + 1)}
        u32_rrot16
        // Stack:  m1 m0 c b  |  z y


        // x = y+c
        {u32_add(0, env.ptr_extract(c) + 2)}
        // Stack:  m1 m0 b  |  z y x

        // w = (b^x) >>> 12
        {u32_xor(0, env.ptr_extract(b) + 3, _ap + 1)}
        u32_rrot12
        // Stack:  m1 m0 |  z y x w


        // v = z+w+m1
        {u32_add(0, 3)}
        {u32_add(env.address(m1) + 4, 0)}
        // Stack: m1 m0 |  y x w v

        // u = (y^v) >>> 8
        {u32_xor(0, 3, _ap + 1)}
        u32_rrot8
        // Stack: m1 m0 |  x w v u

        // t = x+u
        {u32_add(0, 3)}
        // Stack: m1 m0 |  w v u t

        // s = (w^t) >>> 7
        {u32_xor(0, 3, _ap + 1)}
        u32_rrot7
        // Stack: m1 m0 |  v u t s
    };

    env.ptr_insert(a);
    env.ptr_insert(d);
    env.ptr_insert(c);
    env.ptr_insert(b);
    script
}


fn round(env: &mut Env, _ap: u32) -> Script {
    script! {
        { G(env, _ap, S(0), S(4), S(8),  S(12), M(0),  M(1)) }
        { G(env, _ap, S(1), S(5), S(9),  S(13), M(2),  M(3)) }
        { G(env, _ap, S(2), S(6), S(10), S(14), M(4),  M(5)) }
        { G(env, _ap, S(3), S(7), S(11), S(15), M(6),  M(7)) }

        { G(env, _ap, S(0), S(5), S(10), S(15), M(8),  M(9)) }
        { G(env, _ap, S(1), S(6), S(11), S(12), M(10), M(11)) }
        { G(env, _ap, S(2), S(7), S(8),  S(13), M(12), M(13)) }
        { G(env, _ap, S(3), S(4), S(9),  S(14), M(14), M(15)) }
    }
}


fn permute(env: &mut Env) {
    let mut prev_env = Vec::new();
    for i in 0..16 {
        prev_env.push(env.address(M(i)));
    }

    for i in 0..16 {
        env.insert(
            M(i as u32),
            prev_env[MSG_PERMUTATION[i] as usize],
        );
    }
}


fn compress(env: &mut Env, _ap: u32) -> Script {
    script! {
        // Perform 7 rounds and permute after each round,
        // except for the last round
        {{
            let mut round_permute_script = Vec::new();
            for _ in 0..6 {
                round_permute_script.push(round(env, _ap));
                permute(env);
                }
            round_permute_script.push(round(env, _ap));
            round_permute_script
        }}

        // XOR states [0..7] with states [8..15]
        {{
            let mut xor_script = Vec::new();
            for i in 0..8 {
                xor_script.push(u32_xor(env.address(S(i)) + i, env.ptr_extract(S(i + 8)) + i, _ap + 1));
            }
            xor_script
        }}
    }
}


fn compress_160(env: &mut Env, _ap: u32) -> Script {
    script! {
        // Perform 7 rounds and permute after each round,
        // except for the last round
        {{
            let mut final_script = Vec::new();
            for _ in 0..6 {
                final_script.push(round(env, _ap));
                permute(env);
            }
            final_script.push(round(env, _ap));
            final_script
        }}

        // XOR states [0..4] with states [8..12]
        {{
            let mut xor_script = Vec::new();
            for i in 0..5 {
                xor_script.push(u32_xor(env.address(S(i)) + i, env.ptr_extract(S(i + 8)) + i, _ap + 1));
            }
            xor_script
        }}
    }
}



/// Blake3 taking a 64-byte message and returning a 32-byte digest
pub fn blake3() -> Script {
    let mut env = ptr_init();
    script! {
        // Initialize our lookup table
        // We have to do that only once per program
        u32_push_xor_table

        // Push the initial Blake state onto the stack
        {initial_state(64)}

        // Perform a round of Blake3
        {compress(&mut env, 16)}

        // Clean up the stack
        {unroll(32, |_| u32_toaltstack())}
        u32_drop_xor_table
        {unroll(32, |_| u32_fromaltstack())}

        {unroll(24, |i| u32_roll(i + 8))}
        {unroll(24, |_| u32_drop())}
    }
}


/// Blake3 taking a 40-byte message and returning a 20-byte digest
pub fn blake3_160() -> Script {
    let mut env = ptr_init_160();
    script! {
        // Message zero-padding to 64-byte block
        {unroll(6, |_| u32_push(0))}

        // Initialize our lookup table
        // We have to do that only once per program
        u32_push_xor_table

        // Push the initial Blake state onto the stack
        {initial_state(40)}

        // Perform a round of Blake3
        {compress_160(&mut env, 16)}

        // Clean up the stack
        {unroll(5, |_| u32_toaltstack())}
        {unroll(27, |_| u32_drop())}
        u32_drop_xor_table

        {unroll(5, |_| u32_fromaltstack())}
    }
}





#[cfg(test)]
mod tests {
    use bitcoin::{hashes::Hash, TapLeafHash, Transaction};
    use bitcoin_script::bitcoin_script as script;
    use bitcoin_scriptexec::{Exec, ExecCtx, Options, TxTemplate};

    use crate::opcodes::blake3::{blake3_160, permute, round, EnvTrait};
    use crate::opcodes::u32_std::{u32_equal, u32_equalverify, u32_push};
    use crate::opcodes::unroll;

    use super::{blake3, initial_state, ptr_init, pushable, M};

    #[test]
    fn test_permute() {
        let mut env = ptr_init();
        println!("Start env: {}", round(&mut env, 16).to_hex_string());
        permute(&mut env);
        println!("Permuted env: {:?}", env);
        assert!(env.address(M(0)) == 82);
        assert!(env.address(M(1)) == 86);
        assert!(env.address(M(2)) == 83);
        assert!(env.address(M(3)) == 90);
        assert!(env.address(M(4)) == 87);
        assert!(env.address(M(5)) == 80);
        assert!(env.address(M(6)) == 84);
        assert!(env.address(M(7)) == 93);
        assert!(env.address(M(8)) == 81);
        assert!(env.address(M(9)) == 91);
        assert!(env.address(M(10)) == 92);
        assert!(env.address(M(11)) == 85);
        assert!(env.address(M(12)) == 89);
        assert!(env.address(M(13)) == 94);
        assert!(env.address(M(14)) == 95);
        assert!(env.address(M(15)) == 88);
    }

    #[test]
    fn test_initial_state() {
        let script = script! {
            {initial_state(64)}
        };
        let mut exec = Exec::new(
            ExecCtx::Tapscript,
            Options::default(),
            TxTemplate {
                tx: Transaction {
                    version: bitcoin::transaction::Version::TWO,
                    lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
                    input: vec![],
                    output: vec![],
                },
                prevouts: vec![],
                input_idx: 0,
                taproot_annex_scriptleaf: Some((TapLeafHash::all_zeros(), None)),
            },
            script,
            vec![],
        )
        .expect("error creating exec");

        loop {
            if exec.exec_next().is_err() {
                break;
            }
        }
        let res = exec.result().unwrap();
        if !res.success {
            println!(
                "Remaining script: {}",
                exec.remaining_script().to_asm_string()
            );
            println!("Remaining stack: {:?}", exec.stack());
            println!("{:?}", res.clone().error.map(|e| format!("{:?}", e)));
        }
        assert!(res.final_stack[17][0] == 79);
    }

    #[test]
    fn test_blake3() {
        let script = script! {
            {unroll(16, |_| u32_push(1))}
            blake3
            {u32_push(0x700e822d)}
            u32_equalverify
            {u32_push(0x98bd6b10)}
            u32_equalverify
            {u32_push(0xfcc2af6c)}
            u32_equalverify
            {u32_push(0xd6e55b11)}
            u32_equalverify
            {u32_push(0xc1a5488b)}
            u32_equalverify
            {u32_push(0xc7bcf99a)}
            u32_equalverify
            {u32_push(0x963deefd)}
            u32_equalverify
            {u32_push(0xae95ca86)}
            u32_equal
        };
        let mut exec = Exec::new(
            ExecCtx::Tapscript,
            Options::default(),
            TxTemplate {
                tx: Transaction {
                    version: bitcoin::transaction::Version::TWO,
                    lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
                    input: vec![],
                    output: vec![],
                },
                prevouts: vec![],
                input_idx: 0,
                taproot_annex_scriptleaf: Some((TapLeafHash::all_zeros(), None)),
            },
            script,
            vec![],
        )
        .expect("error creating exec");

        loop {
            if exec.exec_next().is_err() {
                break;
            }
        }
        let res = exec.result().unwrap();
        if !res.success {
            println!(
                "Remaining script: {}",
                exec.remaining_script().to_asm_string()
            );
            println!("Remaining stack: {:?}", exec.stack());
            println!("Last Opcode: {:?}", res.opcode,);
            println!("StackSize: {:?}", exec.stack().len(),);
            println!("{:?}", res.clone().error.map(|e| format!("{:?}", e)));
        }

        assert!(res.success);
    }

    #[test]
    fn test_blake3_160() {
        let script = script! {
            {unroll(10, |_| u32_push(1))}
            blake3_160
            {u32_push(0xa759f48b)}
            u32_equalverify
            {u32_push(0x3efce995)}
            u32_equalverify
            {u32_push(0x63eae235)}
            u32_equalverify
            {u32_push(0x48e63346)}
            u32_equalverify
            {u32_push(0x2cef0e29)}
            u32_equal
        };
        let mut exec = Exec::new(
            ExecCtx::Tapscript,
            Options::default(),
            TxTemplate {
                tx: Transaction {
                    version: bitcoin::transaction::Version::TWO,
                    lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
                    input: vec![],
                    output: vec![],
                },
                prevouts: vec![],
                input_idx: 0,
                taproot_annex_scriptleaf: Some((TapLeafHash::all_zeros(), None)),
            },
            script,
            vec![],
        )
        .expect("error creating exec");

        loop {
            if exec.exec_next().is_err() {
                break;
            }
        }
        let res = exec.result().unwrap();
        if !res.success {
            println!(
                "Remaining script: {}",
                exec.remaining_script().to_asm_string()
            );
            println!("Remaining stack: {:?}", exec.stack());
            println!("Last Opcode: {:?}", res.opcode,);
            println!("StackSize: {:?}", exec.stack().len(),);
            println!("{:?}", res.clone().error.map(|e| format!("{:?}", e)));
        }

        assert!(res.success);
    }
}
