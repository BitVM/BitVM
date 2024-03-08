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

fn S(i: u32) -> String {
    format!("state_{i}")
}

fn M(i: u32) -> String {
    format!("msg_{i}")
}

fn ptr_init() -> HashMap<String, u32> {
    // Initial positions for state and message
    let mut env: HashMap<String, u32> = HashMap::new();
    for i in 0..16 {
        env.insert(S(i), i);
        // The message's offset is the size of the state
        // plus the u32 size of our XOR table
        env.insert(M(i), i + 16 + 256 / 4);
    }
    env
}

fn ptr_init_160() -> HashMap<String, u32> {
    // Initial positions for state and message
    let mut env: HashMap<String, u32> = HashMap::new();
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

trait BlakeEnv {
    /// Set the position of `identifier` to the top stack item
    fn ptr_insert(&mut self, identifier: &str);
    /// Get the position of `identifier`, then delete it
    fn ptr_extract(&mut self, identifier: &str) -> u32;
    fn G(&mut self, _ap: u32, a: &str, b: &str, c: &str, d: &str, m0: &str, m1: &str) -> Script;
    fn round(&mut self, _ap: u32) -> Script;
    fn permute(&mut self);
    fn compress(&mut self, _ap: u32) -> Script;
    fn compress_160(&mut self, _ap: u32) -> Script;
}

impl BlakeEnv for HashMap<String, u32> {
    fn ptr_insert(&mut self, identifier: &str) {
        for (_, value) in self.iter_mut() {
            *value += 1;
        }
        self.insert(String::from(identifier), 0);
    }

    fn ptr_extract(&mut self, identifier: &str) -> u32 {
        match self.remove(identifier) {
            Some(index) => {
                for (_, value) in self.iter_mut() {
                    if index < *value {
                        *value -= 1;
                    }
                }
                index
            }
            None => panic!("Undefined Variable {identifier}"),
        }
    }

    fn G(&mut self, _ap: u32, a: &str, b: &str, c: &str, d: &str, m0: &str, m1: &str) -> Script {
        let script = script! {
            // z = a+b+m0
            {u32_add(*self.get(b).unwrap(), self.ptr_extract(a))}
            {u32_add(*self.get(m0).unwrap() + 1, 0)}
            // Stack:  m1 m0 d c b  |  z

            // y = (d^z) >>> 16
            {u32_xor(0, self.ptr_extract(d) + 1, _ap + 1)}
            u32_rrot16
            // Stack:  m1 m0 c b  |  z y


            // x = y+c
            {u32_add(0, self.ptr_extract(c) + 2)}
            // Stack:  m1 m0 b  |  z y x

            // w = (b^x) >>> 12
            {u32_xor(0, self.ptr_extract(b) + 3, _ap + 1)}
            u32_rrot12
            // Stack:  m1 m0 |  z y x w


            // v = z+w+m1
            {u32_add(0, 3)}
            {u32_add(*self.get(m1).unwrap() + 4, 0)}
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

        self.ptr_insert(a);
        self.ptr_insert(d);
        self.ptr_insert(c);
        self.ptr_insert(b);
        script
    }

    fn round(&mut self, _ap: u32) -> Script {
        script! {
            {self.G(_ap, &S(0), &S(4), &S(8),  &S(12), &M(0),  &M(1))}
            {self.G(_ap, &S(1), &S(5), &S(9),  &S(13), &M(2),  &M(3))}
            {self.G(_ap, &S(2), &S(6), &S(10), &S(14), &M(4),  &M(5))}
            {self.G(_ap, &S(3), &S(7), &S(11), &S(15), &M(6),  &M(7))}

            {self.G(_ap, &S(0), &S(5), &S(10), &S(15), &M(8),  &M(9))}
            {self.G(_ap, &S(1), &S(6), &S(11), &S(12), &M(10), &M(11))}
            {self.G(_ap, &S(2), &S(7), &S(8),  &S(13), &M(12), &M(13))}
            {self.G(_ap, &S(3), &S(4), &S(9),  &S(14), &M(14), &M(15))}
        }
    }

    fn permute(&mut self) {
        let mut prev_env = Vec::new();
        for i in 0..16 {
            prev_env.push(*self.get(&M(i)).unwrap());
        }

        for i in 0..16 {
            self.insert(
                String::from(M(i as u32)),
                prev_env[MSG_PERMUTATION[i] as usize],
            );
        }
    }

    fn compress(&mut self, _ap: u32) -> Script {
        script! {
            // Perform 7 rounds and permute after each round,
            // except for the last round
            {(|| {
                let script = self.round(_ap);
                self.permute();
                script
            })()}
            {(|| {
                let script = self.round(_ap);
                self.permute();
                script
            })()}
            {(|| {
                let script = self.round(_ap);
                self.permute();
                script
            })()}
            {(|| {
                let script = self.round(_ap);
                self.permute();
                script
            })()}
            {(|| {
                let script = self.round(_ap);
                self.permute();
                script
            })()}
            {(|| {
                let script = self.round(_ap);
                self.permute();
                script
            })()}
            {self.round(_ap)}

            // XOR states [0..7] with states [8..15]
            {u32_xor(self.get(&S(0)).unwrap() + 0, self.ptr_extract(&S(8))  + 0, _ap + 1)}
            {u32_xor(self.get(&S(1)).unwrap() + 1, self.ptr_extract(&S(9))  + 1, _ap + 1)}
            {u32_xor(self.get(&S(2)).unwrap() + 2, self.ptr_extract(&S(10)) + 2, _ap + 1)}
            {u32_xor(self.get(&S(3)).unwrap() + 3, self.ptr_extract(&S(11)) + 3, _ap + 1)}
            {u32_xor(self.get(&S(4)).unwrap() + 4, self.ptr_extract(&S(12)) + 4, _ap + 1)}
            {u32_xor(self.get(&S(5)).unwrap() + 5, self.ptr_extract(&S(13)) + 5, _ap + 1)}
            {u32_xor(self.get(&S(6)).unwrap() + 6, self.ptr_extract(&S(14)) + 6, _ap + 1)}
            {u32_xor(self.get(&S(7)).unwrap() + 7, self.ptr_extract(&S(15)) + 7, _ap + 1)}
        }
    }

    fn compress_160(&mut self, _ap: u32) -> Script {
        script! {
            // Perform 7 rounds and permute after each round,
            // except for the last round

            {(|| {
                let script = self.round(_ap);
                self.permute();
                script
            })()}
            {(|| {
                let script = self.round(_ap);
                self.permute();
                script
            })()}
            {(|| {
                let script = self.round(_ap);
                self.permute();
                script
            })()}
            {(|| {
                let script = self.round(_ap);
                self.permute();
                script
            })()}
            {(|| {
                let script = self.round(_ap);
                self.permute();
                script
            })()}
            {(|| {
                let script = self.round(_ap);
                self.permute();
                script
            })()}
            {self.round(_ap)}

            // XOR states [0..4] with states [8..12]
            {u32_xor(self.get(&S(0)).unwrap() + 0, self.ptr_extract(&S(8)), _ap + 1)}
            {u32_xor(self.get(&S(1)).unwrap() + 1, self.ptr_extract(&S(9)) + 1, _ap + 1)}
            {u32_xor(self.get(&S(2)).unwrap() + 2, self.ptr_extract(&S(10)) + 2, _ap + 1)}
            {u32_xor(self.get(&S(3)).unwrap() + 3, self.ptr_extract(&S(11)) + 3, _ap + 1)}
            {u32_xor(self.get(&S(4)).unwrap() + 4, self.ptr_extract(&S(12)) + 4, _ap + 1)}
        }
    }
}

///
/// Blake3 taking a 64-byte message and returning a 32-byte digest
///
pub fn blake3() -> Script {
    let mut blake_env = ptr_init();
    script! {
        // Initialize our lookup table
        // We have to do that only once per program
        u32_push_xor_table

        // Push the initial Blake state onto the stack
        {initial_state(64)}

        // Perform a round caof Blake3
        {blake_env.compress(16)}

        // Clean up the stack
        {unroll(32, |_| u32_toaltstack())}
        u32_drop_xor_table
        {unroll(32, |_| u32_fromaltstack())}

        {unroll(24, |i| u32_roll(i + 8))}
        {unroll(24, |_| u32_drop())}
    }
}

pub fn blake3_160() -> Script {
    let mut blake_env = ptr_init_160();
    script! {
        // Message zero-padding to 64-byte block
        {unroll(6, |_| u32_push(0))}

        // Initialize our lookup table
        // We have to do that only once per program
        u32_push_xor_table

        // Push the initial Blake state onto the stack
        {initial_state(40)}

        // Perform a round of Blake3
        {blake_env.compress_160(16)}

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

    use crate::opcodes::blake3::blake3_160;
    use crate::opcodes::u32_std::u32_equal;
    use crate::opcodes::u32_std::u32_equalverify;
    use crate::opcodes::u32_std::u32_push;
    use crate::opcodes::unroll;

    use super::blake3;
    use super::initial_state;
    use super::ptr_init;
    use super::pushable;
    use super::BlakeEnv;
    use super::M;

    #[test]
    fn test_permute() {
        let mut env = ptr_init();
        println!("Start env: {}", env.round(16).to_hex_string());
        env.permute();
        println!("Permuted env: {:?}", env);
        assert!(*env.get(&M(0)).unwrap() == 82);
        assert!(*env.get(&M(1)).unwrap() == 86);
        assert!(*env.get(&M(2)).unwrap() == 83);
        assert!(*env.get(&M(3)).unwrap() == 90);
        assert!(*env.get(&M(4)).unwrap() == 87);
        assert!(*env.get(&M(5)).unwrap() == 80);
        assert!(*env.get(&M(6)).unwrap() == 84);
        assert!(*env.get(&M(7)).unwrap() == 93);
        assert!(*env.get(&M(8)).unwrap() == 81);
        assert!(*env.get(&M(9)).unwrap() == 91);
        assert!(*env.get(&M(10)).unwrap() == 92);
        assert!(*env.get(&M(11)).unwrap() == 85);
        assert!(*env.get(&M(12)).unwrap() == 89);
        assert!(*env.get(&M(13)).unwrap() == 94);
        assert!(*env.get(&M(14)).unwrap() == 95);
        assert!(*env.get(&M(15)).unwrap() == 88);
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
