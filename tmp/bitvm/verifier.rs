#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

use super::prover::{Prover, ProxyProverVM, P160, P32};
use super::vm::VM;
use super::constants::{LOG_PATH_LEN, LOG_TRACE_LEN};

type u1 = u8;

use crate::scripts::actor::ID;
use crate::scripts::{
    opcodes::{pushable, unroll},
    actor::{Actor, Opponent, Player},
};

use bitcoin::ScriptBuf as Script;
use bitcoin_script::bitcoin_script as script;

// TODO: Implement `export` with Serde

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// 
/// V32 V1

#[derive(Copy, Clone)]
pub enum V1 {
    // Get the next trace challenge
    TRACE_CHALLENGE(u8),
    // Get the next Merkle challenge for value_a, value_b or value_c
    MERKLE_CHALLENGE_A(u8), MERKLE_CHALLENGE_B(u8), MERKLE_CHALLENGE_C_PREV(u8),
    IS_FAULTY_READ_A(u8), IS_FAULTY_READ_B(u8), IS_FAULTY_WRITE_C(u8),
    IS_FAULTY_PC_CURR(u8), IS_FAULTY_PC_NEXT(u8),
}

#[derive(Copy, Clone)]
pub enum V32 {
    // Index of the last valid VM state
    TRACE_INDEX(u8),
    // Index of the current state
    NEXT_TRACE_INDEX(u8),
    // Index of the last valid node in the Merkle path
    MERKLE_INDEX_A, MERKLE_INDEX_B, MERKLE_INDEX_C_PREV,
    // Index of the current node in the Merkle path
    NEXT_MERKLE_INDEX_A(u8), NEXT_MERKLE_INDEX_B(u8), NEXT_MERKLE_INDEX_C_PREV(u8),
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// 
/// Actor
pub trait Verifier<T: Actor> {

    fn u1(&mut self, id: V1) -> u1;

    fn u32(&mut self, id: V32) -> u32;

    fn get_actor(&mut self) -> &mut T;

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// 
/// BitVM
pub struct VerifierVM { verifier: Player, vm: VM, prover: ProxyProverVM }

impl VerifierVM {

    /// commit
    pub fn u1_commit(&mut self, u1_id: V1) -> Script {
        self.get_actor().u1_commit(u1_id.ID())
    }

    /// unlock
    pub fn u1_unlock(&mut self, u1_id: V1) -> Script {
        let u1 = self.u1(u1_id);
        self.get_actor().u1_unlock(u1_id.ID(), u1)
    }

    /// unlock
    pub fn u32_unlock(&mut self, u32_id: V32) -> Script {
        match u32_id {
            V32::TRACE_INDEX(_) => script!{{ unroll(LOG_TRACE_LEN, |i| self.u1(V1::TRACE_CHALLENGE(LOG_TRACE_LEN as u8 - 1 - i as u8)) as u32) }},
            V32::NEXT_TRACE_INDEX(n) => script!{{ unroll(n as u16, |i| self.u1(V1::TRACE_CHALLENGE(n - 1 - i as u8)) as u32) }},
            V32::MERKLE_INDEX_A => script!{{ unroll(LOG_PATH_LEN, |i| self.u1_unlock(V1::MERKLE_CHALLENGE_A(LOG_PATH_LEN as u8 - 1 - i as u8))) }},
            V32::MERKLE_INDEX_B => script!{{ unroll(LOG_PATH_LEN, |i| self.u1_unlock(V1::MERKLE_CHALLENGE_B(LOG_PATH_LEN as u8 - 1 - i as u8))) }},
            V32::NEXT_MERKLE_INDEX_A(n) => script! {{ unroll(n as u16, |i| self.u1_unlock(V1::MERKLE_CHALLENGE_A(n - 1 - i as u8))) }},
            V32::NEXT_MERKLE_INDEX_B(n) => script! {{ unroll(n as u16, |i| self.u1_unlock(V1::MERKLE_CHALLENGE_B(n - 1 - i as u8))) }},
            // Undefined 32-bit variables
            V32::MERKLE_INDEX_C_PREV => unimplemented!(),
            V32::NEXT_MERKLE_INDEX_C_PREV(_) => unimplemented!()
        }
    }

    /// push
    pub fn u1_push(&mut self, u1_id: V1) -> Script {
        self.get_actor().u1_push(u1_id.ID())
    }

    /// push
    pub fn u32_push(&mut self, u32_id: V32) -> Script {
        match u32_id {
            V32::TRACE_INDEX(_) =>
                script! {
                    0
                    { unroll(LOG_TRACE_LEN, |i| script! {
                            OP_SWAP
                            { self.u1_push(V1::TRACE_CHALLENGE(i as u8)) }
                            OP_IF
                                { 1 << LOG_TRACE_LEN - 1 - i }
                                OP_ADD
                            OP_ENDIF
                    }) }
                },
            V32::MERKLE_INDEX_A =>
                script! {
                    0
                    { unroll(LOG_PATH_LEN, |i| script! {
                        OP_SWAP
                        { self.u1_push(V1::MERKLE_CHALLENGE_A(i as u8)) }
                        OP_IF
                            { 1 << LOG_PATH_LEN - 1 - i }
                            OP_ADD
                        OP_ENDIF
                    }) }
                },
            V32::MERKLE_INDEX_B =>
                script! {
                    0
                    { unroll(LOG_PATH_LEN, |i| script! {
                        OP_SWAP
                        { self.u1_push(V1::MERKLE_CHALLENGE_B(i as u8)) }
                        OP_IF
                            { 1 << LOG_PATH_LEN - 1 - i }
                            OP_ADD
                        OP_ENDIF
                    }) }
                },
            V32::NEXT_MERKLE_INDEX_A(n) =>
                script! {
                    0
                    { unroll(n as u16, |i| script! {
                        OP_SWAP
                        { self.u1_push(V1::MERKLE_CHALLENGE_A(i as u8)) }
                        OP_IF
                            { 1 << LOG_PATH_LEN - 1 - i }
                            OP_ADD
                        OP_ENDIF
                    }) }
                    { 1 << LOG_PATH_LEN as u8 - 1 - n }
                    OP_ADD
                },
            V32::NEXT_MERKLE_INDEX_B(n) =>
                script! {
                    0
                    { unroll(n as u16, |i| script! {
                        OP_SWAP
                        { self.u1_push(V1::MERKLE_CHALLENGE_B(i as u8)) }
                        OP_IF
                            { 1 << LOG_PATH_LEN - 1 - i }
                            OP_ADD
                        OP_ENDIF
                    }) }
                    { 1 << LOG_PATH_LEN as u8 - 1 - n }
                    OP_ADD
                },
            // Undefined 1-bit variables
            V32::NEXT_TRACE_INDEX(_) => unimplemented!(),
            V32::MERKLE_INDEX_C_PREV => unimplemented!(),
            V32::NEXT_MERKLE_INDEX_C_PREV(_) => unimplemented!(),

        }
    }
}

impl Verifier::<Player> for VerifierVM {
    
    fn u1(&mut self, u1_id: V1) -> u1 {
        match  u1_id {
            // Get the next trace challenge
            V1::TRACE_CHALLENGE(n) => {
                let trace_index = self.u32(V32::NEXT_TRACE_INDEX(n));
                let mem = self.vm.run(trace_index);
                (self.prover
                    .u160(P160::TRACE_RESPONSE(n)) == mem.root()
                  && self.prover
                    .u32(P32::TRACE_RESPONSE_PC(n)) == mem.pc
                ) as u1
            },
            // Get the next Merkle challenge
            V1::MERKLE_CHALLENGE_A(n) => {
                let trace_index = self.u32(V32::TRACE_INDEX(n));
                let node_index = self.u32(V32::NEXT_MERKLE_INDEX_A(n)) as u8; // NOTE: May flip `node_index = PATH_LEN - 1 - node_index`
                (self.vm
                    .run(trace_index)
                    .path(self.prover.u32(P32::ADDRESS_A))
                    .get_node(node_index)
                  == self.prover
                    .u160(P160::MERKLE_RESPONSE_A(n))
                ) as u1
            },
            // Get the next Merkle challenge
            V1::MERKLE_CHALLENGE_B(n) => {
                let trace_index = self.u32(V32::TRACE_INDEX(n));
                let node_index = self.u32(V32::NEXT_MERKLE_INDEX_B(n)) as u8; // NOTE: May flip `node_index = PATH_LEN - 1 - node_index`
                (self.vm
                    .run(trace_index)
                    .path(self.prover.u32(P32::ADDRESS_B))
                    .get_node(node_index)
                  == self.prover
                    .u160(P160::MERKLE_RESPONSE_B(n))
                ) as u1
            }
            // Get the next Merkle challenge
            V1::MERKLE_CHALLENGE_C_PREV(n) => {
                let trace_index = self.u32(V32::TRACE_INDEX(n));
                let node_index = self.u32(V32::NEXT_MERKLE_INDEX_C_PREV(n)) as u8; // NOTE: May flip `node_index = PATH_LEN - 1 - node_index`
                (self.vm
                    .run(trace_index)
                    .path(self.prover.u32(P32::ADDRESS_C))
                    .get_node(node_index)
                  == self.prover
                    .u160(P160::MERKLE_RESPONSE_C_NEXT(n))
                ) as u1
            },
            // TODO: Maybe Vicky should have "this.valueA" etc. too. In that case it should be moved to the Player class.
            V1::IS_FAULTY_READ_A(n) => {
                let trace_index = self.u32(V32::TRACE_INDEX(n));
                (self.vm
                    .run(trace_index)[self.prover.u32(P32::ADDRESS_A)]
                  != self.prover
                    .u32(P32::VALUE_A)
                ) as u1
            },
            V1::IS_FAULTY_READ_B(n) => {
                let trace_index = self.u32(V32::TRACE_INDEX(n));
                (self.vm
                    .run(trace_index)[self.prover.u32(P32::ADDRESS_B)]
                  != self.prover
                    .u32(P32::VALUE_B)
                ) as u1
            },
            V1::IS_FAULTY_WRITE_C(n) => {
                let trace_index = self.u32(V32::TRACE_INDEX(n));
                (self.vm
                    .run(trace_index + 1)[self.prover.u32(P32::ADDRESS_C)]
                  != self.prover
                    .u32(P32::VALUE_C)
                ) as u1
            },
            V1::IS_FAULTY_PC_CURR(n) => {
                let trace_index = self.u32(V32::TRACE_INDEX(n));
                (self.vm
                    .run(trace_index)[self.prover.u32(P32::PC_CURR)]
                  != self.prover
                    .u32(P32::PC_CURR)
                ) as u1
            },
            V1::IS_FAULTY_PC_NEXT(n) => {
                let trace_index = self.u32(V32::TRACE_INDEX(n));
                (self.vm
                    .run(trace_index + 1)[self.prover.u32(P32::PC_NEXT)]
                  != self.prover
                    .u32(P32::PC_NEXT)
                ) as u1
            },
        }
    }

    fn u32(&mut self, u32_id: V32) -> u32 {
        match u32_id {
            // Index of the last valid VM state
            V32::TRACE_INDEX(_) => {
                let mut trace_index = 0;
                for i in 0..LOG_TRACE_LEN {
                    trace_index += (self.u1(V1::TRACE_CHALLENGE(i as u8)) as u32) << LOG_TRACE_LEN - 1 - i;
                }
                trace_index
            },
            // Index of the current state
            V32::NEXT_TRACE_INDEX(n) => {
                let mut trace_index = 0;
                for i in 0..n {
                    trace_index += (self.u1(V1::TRACE_CHALLENGE(i)) as u32) << LOG_TRACE_LEN as u8 - 1 - i;
                }
                trace_index + 1 << LOG_TRACE_LEN as u32 - 1 - n as u32
            },
            // Index of the last valid node in the Merkle path
            V32::MERKLE_INDEX_A => {
                let mut merkle_index_a = 0;
                for i in 0..LOG_PATH_LEN {
                    merkle_index_a += (self.u1(V1::MERKLE_CHALLENGE_A(i as u8)) as u32) << LOG_PATH_LEN - 1 - i;
                }
                merkle_index_a
            },
            // Index of the last valid node in the Merkle path
            V32::MERKLE_INDEX_B => {
                let mut merkle_index_b = 0;
                for i in 0..LOG_PATH_LEN {
                    merkle_index_b += (self.u1(V1::MERKLE_CHALLENGE_B(i as u8)) as u32) << LOG_PATH_LEN - 1 - i;
                }
                merkle_index_b
            },
            // Index of the last valid node in the Merkle path
            V32::MERKLE_INDEX_C_PREV => {
                let mut merkle_index_c = 0;
                for i in 0..LOG_PATH_LEN {
                    merkle_index_c += (self.u1(V1::MERKLE_CHALLENGE_C_PREV(i as u8)) as u32) << LOG_PATH_LEN - 1 - i;
                }
                merkle_index_c
            },
            // Index of the current node in the Merkle path
            V32::NEXT_MERKLE_INDEX_A(n) => {
                let mut merkle_index_a = 0;
                for i in 0..n {
                    merkle_index_a += (self.u1(V1::MERKLE_CHALLENGE_A(i)) as u32) << LOG_PATH_LEN as u8 - 1 - i;
                }
                merkle_index_a + 1 << LOG_PATH_LEN as u8 - 1 - n
            },
            // Index of the current node in the Merkle path
            V32::NEXT_MERKLE_INDEX_B(n) => {
                let mut merkle_index_b = 0;
                for i in 0..n {
                    merkle_index_b += (self.u1(V1::MERKLE_CHALLENGE_A(i)) as u32) << LOG_PATH_LEN as u8 - 1 - i;
                }
                merkle_index_b + 1 << LOG_PATH_LEN as u8 - 1 - n
            },
            // Index of the current node in the Merkle path
            V32::NEXT_MERKLE_INDEX_C_PREV(n) => {
                let mut merkle_index_c = 0;
                for i in 0..n {
                    merkle_index_c += (self.u1(V1::MERKLE_CHALLENGE_C_PREV(i)) as u32) << LOG_PATH_LEN as u8 - 1 - i;
                }
                merkle_index_c + 1 << LOG_PATH_LEN as u8 - 1 - n
            },
        }
    }

    fn get_actor(&mut self) -> &mut Player {
        &mut self.verifier
    }

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// 
/// Proxy BitVM
pub struct ProxyVerifierVM(pub Opponent);

impl Verifier<Opponent> for ProxyVerifierVM {

    fn u32(&mut self, u32_id: V32) -> u32 {
        match u32_id {
            // Index of the last valid VM state
            V32::TRACE_INDEX(_) => {
                let mut trace_index = 0;
                for i in 0..LOG_TRACE_LEN {
                    trace_index += (self.u1(V1::TRACE_CHALLENGE(i as u8)) as u32) << LOG_TRACE_LEN - 1 - i;
                }
                trace_index
            },
            // Index of the current state
            V32::NEXT_TRACE_INDEX(n) => {
                let mut trace_index = 0;
                    for i in 0..n {
                        trace_index += (self.u1(V1::TRACE_CHALLENGE(i)) as u32) << LOG_TRACE_LEN as u8 - 1 - i;
                    }
                    trace_index + 1 << LOG_TRACE_LEN as u8 - 1 - n
            },
            // Index of the last valid node in the Merkle path
            V32::MERKLE_INDEX_A => {
                let mut merkle_index_a = 0;
                for i in 0..LOG_PATH_LEN {
                    merkle_index_a += (self.u1(V1::MERKLE_CHALLENGE_A(i as u8)) as u32) << LOG_PATH_LEN - 1 - i;
                }
                merkle_index_a
            },
            // Index of the last valid node in the Merkle path
            V32::MERKLE_INDEX_B => {
                let mut merkle_index_b = 0;
                for i in 0..LOG_PATH_LEN {
                    merkle_index_b += (self.u1(V1::MERKLE_CHALLENGE_B(i as u8)) as u32) << LOG_PATH_LEN - 1 - i;
                }
                merkle_index_b
            },
            // Index of the last valid node in the Merkle path
            V32::MERKLE_INDEX_C_PREV => {
                let mut merkle_index_c = 0;
                for i in 0..LOG_PATH_LEN {
                    merkle_index_c += (self.u1(V1::MERKLE_CHALLENGE_C_PREV(i as u8)) as u32) << LOG_PATH_LEN - 1 - i;
                }
                merkle_index_c
            },
            // Index of the current node in the Merkle path
            V32::NEXT_MERKLE_INDEX_A(n) => {
                let mut merkle_index_a = 0;
                for i in 0..n {
                    merkle_index_a += (self.u1(V1::MERKLE_CHALLENGE_A(i)) as u32) << LOG_PATH_LEN as u8 - 1 - i;
                }
                merkle_index_a + 1 << LOG_PATH_LEN as u8 - 1 - n
            },
            // Index of the current node in the Merkle path
            V32::NEXT_MERKLE_INDEX_B(n) => {
                let mut merkle_index_b = 0;
                for i in 0..n {
                    merkle_index_b += (self.u1(V1::MERKLE_CHALLENGE_B(i)) as u32) << LOG_PATH_LEN as u8 - 1 - i;
                }
                merkle_index_b + 1 << LOG_PATH_LEN as u8 - 1 - n
            },
            // Index of the current node in the Merkle path
            V32::NEXT_MERKLE_INDEX_C_PREV(n) => {
                let mut merkle_index_c = 0;
                for i in 0..n {
                    merkle_index_c += (self.u1(V1::MERKLE_CHALLENGE_C_PREV(i)) as u32) << LOG_PATH_LEN as u8 - 1 - i;
                }
                merkle_index_c + 1 << LOG_PATH_LEN as u8 - 1 - n
            },
        }
    }
    
    fn u1(&mut self, u1_id: V1) -> u1 {
        match u1_id {
            // Get the next trace challenge
            V1::TRACE_CHALLENGE(n) => (self.0.get_u1(V1::TRACE_CHALLENGE(n).ID()) != 0) as u1,
            // Get the next Merkle challenge
            V1::MERKLE_CHALLENGE_A(n) => (self.0.get_u1(V1::MERKLE_CHALLENGE_A(n).ID()) != 0) as u1,
            // Get the next Merkle challenge
            V1::MERKLE_CHALLENGE_B(n) => (self.0.get_u1(V1::MERKLE_CHALLENGE_B(n).ID()) != 0) as u1,
            // Get the next Merkle challenge
            V1::MERKLE_CHALLENGE_C_PREV(n) => (self.0.get_u1(V1::MERKLE_CHALLENGE_C_PREV(n).ID()) != 0) as u1,
            // Undefined 1-bit variables
            V1::IS_FAULTY_READ_A(_) => unimplemented!(),
            V1::IS_FAULTY_READ_B(_) => unimplemented!(),
            V1::IS_FAULTY_WRITE_C(_) => unimplemented!(),
            V1::IS_FAULTY_PC_CURR(_) => unimplemented!(),
            V1::IS_FAULTY_PC_NEXT(_) => unimplemented!(),
        }
    }

    fn get_actor(&mut self) -> & mut Opponent { &mut self.0 }

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// 
/// enum as u16

impl ID for V1 {
    fn ID(&self) -> u16 {
        match *self {
            // Vicky's trace challenges
            // TRACE_CHALLENGE_{n}
            V1::TRACE_CHALLENGE(n) => 1 << 8 | n as u16,
            // Vicky's Merkle challenges for the operand A
            // MERKLE_CHALLENGE_A_{n}
            V1::MERKLE_CHALLENGE_A(n) => 4 << 8 | n as u16,
            // Vicky's Merkle challenges for the operand B
            // MERKLE_CHALLENGE_B_{n}
            V1::MERKLE_CHALLENGE_B(n) => 6 << 8 | n as u16,
            // Vicky's Merkle challenges for the result C
            // MERKLE_CHALLENGE_C_PREV_{n}
            V1::MERKLE_CHALLENGE_C_PREV(n) => 8 << 8 | n as u16,
            // Undefined 1-bit variables
            V1::IS_FAULTY_READ_A(n) => 36 << 8 | n as u16,
            V1::IS_FAULTY_READ_B(n) => 37 << 8 | n as u16,
            V1::IS_FAULTY_WRITE_C(n) => 38 << 8 | n as u16,
            V1::IS_FAULTY_PC_CURR(n) => 39 << 8 | n as u16,
            V1::IS_FAULTY_PC_NEXT(n) => 40 << 8 | n as u16,
        }
    }
}

impl ID for V32 {
    fn ID(&self) -> u16 {
        match *self {
            // Index of the last valid VM state
            V32::TRACE_INDEX(n) => 21 << 8 | n as u16,
            // Index of the current state
            V32::NEXT_TRACE_INDEX(n) => 35 << 8 | n as u16,
            // Index of the last valid node in the Merkle path
            V32::MERKLE_INDEX_A => 23 << 8,
            V32::MERKLE_INDEX_B => 25 << 8,
            V32::MERKLE_INDEX_C_PREV => 27 << 8,
            // Index of the current node in the Merkle path
            V32::NEXT_MERKLE_INDEX_A(n) => 29 << 8 | n as u16,
            V32::NEXT_MERKLE_INDEX_B(n) => 31 << 8 | n as u16,
            V32::NEXT_MERKLE_INDEX_C_PREV(n) => 33 << 8 | n as u16,
        }
    }
}
