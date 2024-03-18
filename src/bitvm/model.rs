#![allow(non_snake_case)]
use crate::{bitvm::constants::LOG_PATH_LEN, scripts::{
    actor::{Actor, HashDigest, Opponent, Player},
    opcodes::{
        pushable, u160_std::{u160_state, u160_state_commit, u160_state_unlock, U160}, u32_state::{
            bit_state, bit_state_commit, bit_state_unlock, u32_state, u32_state_commit, u32_state_unlock, u8_state, u8_state_commit, u8_state_unlock
        }, unroll
    },
}};

use bitcoin::ScriptBuf as Script;
use bitcoin_script::bitcoin_script as script;
use super::{constants::LOG_TRACE_LEN, vm::{Instruction, VM}};

// Vicky's trace challenges
fn TRACE_CHALLENGE(index: u8) -> String {
    format!("TRACE_CHALLENGE_{index}")
}
// Paul's trace responses
fn TRACE_RESPONSE(index: u8) -> String {
    format!("TRACE_RESPONSE_{index}")
}
// Paul's trace response program counters
fn TRACE_RESPONSE_PC(index: u8) -> String {
    format!("TRACE_RESPONSE_PC_{index}")
}
// Vicky's Merkle challenges for the operand A
fn MERKLE_CHALLENGE_A(index: u8) -> String {
    format!("MERKLE_CHALLENGE_A_{index}")
}
// Paul's Merkle responses for the operand A
fn MERKLE_RESPONSE_A(index: u8) -> String {
    format!("MERKLE_RESPONSE_A_{index}")
}
// Vicky's Merkle challenges for the operand B
fn MERKLE_CHALLENGE_B(index: u8) -> String {
    format!("MERKLE_CHALLENGE_B_{index}")
}
// Paul's Merkle responses for the operand B
fn MERKLE_RESPONSE_B(index: u8) -> String {
    format!("MERKLE_RESPONSE_B_{index}")
}

// Vicky's Merkle challenges for the result C
fn MERKLE_CHALLENGE_C_PREV(index: u8) -> String {
    format!("MERKLE_CHALLENGE_C_PREV_{index}")
}
// Paul's Merkle responses for the result C
fn MERKLE_RESPONSE_C_NEXT(index: u8) -> String {
    format!("MERKLE_RESPONSE_C_NEXT_{index}")
}
// Paul's Merkle responses for the result C
fn MERKLE_RESPONSE_C_NEXT_SIBLING(index: u8) -> String {
    format!("MERKLE_RESPONSE_C_NEXT_SIBLING_{index}")
}
// Paul's Merkle responses for the result C
fn MERKLE_RESPONSE_C_PREV(index: u8) -> String {
    format!("MERKLE_RESPONSE_C_PREV_{index}")
}

// Paul's instruction commitment
const INSTRUCTION_TYPE: &str = "INSTRUCTION_TYPE";
const INSTRUCTION_VALUE_A: &str = "INSTRUCTION_VALUE_A";
const INSTRUCTION_ADDRESS_A: &str = "INSTRUCTION_ADDRESS_A";
const INSTRUCTION_VALUE_B: &str = "INSTRUCTION_VALUE_B";
const INSTRUCTION_ADDRESS_B: &str = "INSTRUCTION_ADDRESS_B";
const INSTRUCTION_VALUE_C: &str = "INSTRUCTION_VALUE_C";
const INSTRUCTION_ADDRESS_C: &str = "INSTRUCTION_ADDRESS_C";
const INSTRUCTION_PC_CURR: &str = "INSTRUCTION_PC_CURR";
const INSTRUCTION_PC_NEXT: &str = "INSTRUCTION_PC_NEXT";

pub trait Paul {
    fn instruction_type(&mut self) -> u8;

    fn address_a(&mut self) -> u32;

    fn address_b(&mut self) -> u32;

    fn address_c(&mut self) -> u32;

    fn value_a(&mut self) -> u32;

    fn value_b(&mut self) -> u32;

    fn value_c(&mut self) -> u32;

    fn pc_curr(&mut self) -> u32;

    fn pc_next(&mut self) -> u32;

    fn trace_response(&mut self, index: u8) -> HashDigest;

    fn trace_response_pc(&mut self, index: u8) -> u32;

    fn merkle_response_a(&mut self, index: u8) -> HashDigest;

    fn merkle_response_a_sibling(&mut self, index: u8) -> HashDigest;

    fn merkle_response_b(&mut self, index: u8) -> HashDigest;

    fn merkle_response_b_sibling(&mut self, index: u8) -> HashDigest;

    fn merkle_response_c_prev(&mut self, index: u8) -> HashDigest;

    fn merkle_response_c_next(&mut self, index: u8) -> HashDigest;

    fn merkle_response_c_next_sibling(&mut self, index: u8) -> HashDigest;

    fn commit(&mut self) -> PaulCommit;

    fn push(&mut self) -> PaulPush;

    fn unlock(&mut self) -> PaulUnlock;

    fn get_actor(&mut self) -> &mut dyn Actor;
}

pub struct PaulCommit<'a> {
    actor: &'a mut dyn Actor,
}

impl PaulCommit<'_> {
    pub fn instruction_type(&mut self) -> Script {
        u8_state_commit(self.actor, INSTRUCTION_TYPE)
    }

    pub fn address_a(&mut self) -> Script {
        u32_state_commit(self.actor, INSTRUCTION_ADDRESS_A)
    }

    pub fn address_b(&mut self) -> Script {
        u32_state_commit(self.actor, INSTRUCTION_ADDRESS_B)
    }

    pub fn address_c(&mut self) -> Script {
        u32_state_commit(self.actor, INSTRUCTION_ADDRESS_C)
    }

    pub fn value_a(&mut self) -> Script {
        u32_state_commit(self.actor, INSTRUCTION_VALUE_A)
    }

    pub fn value_b(&mut self) -> Script {
        u32_state_commit(self.actor, INSTRUCTION_VALUE_B)
    }

    pub fn value_c(&mut self) -> Script {
        u32_state_commit(self.actor, INSTRUCTION_VALUE_C)
    }

    pub fn pc_curr(&mut self) -> Script {
        u32_state_commit(self.actor, INSTRUCTION_PC_CURR)
    }

    pub fn pc_next(&mut self) -> Script {
        u32_state_commit(self.actor, INSTRUCTION_PC_NEXT)
    }

    pub fn trace_response(&mut self, index: u8) -> Script {
        u160_state_commit(self.actor, &TRACE_RESPONSE(index))
    }

    pub fn trace_response_pc(&mut self, index: u8) -> Script {
        u32_state_commit(self.actor, &TRACE_RESPONSE_PC(index))
    }

    pub fn merkle_response_a(&mut self, index: u8) -> Script {
        u160_state_commit(self.actor, &MERKLE_RESPONSE_A(index))
    }

    pub fn merkle_response_b(&mut self, index: u8) -> Script {
        u160_state_commit(self.actor, &MERKLE_RESPONSE_B(index))
    }

    pub fn merkle_response_c_prev(&mut self, index: u8) -> Script {
        u160_state_commit(self.actor, &MERKLE_RESPONSE_C_PREV(index))
    }

    pub fn merkle_response_c_next(&mut self, index: u8) -> Script {
        u160_state_commit(self.actor, &MERKLE_RESPONSE_C_NEXT(index))
    }

    pub fn merkle_response_c_next_sibling(&mut self, index: u8) -> Script {
        u160_state_commit(self.actor, &MERKLE_RESPONSE_C_NEXT_SIBLING(index))
    }
}

pub struct PaulPush<'a> {
    paul: &'a mut dyn Actor,
}

impl<'a> PaulPush<'a>
{
    pub fn instruction_type(&mut self) -> Script {
        u8_state(self.paul, INSTRUCTION_TYPE)
    }

    pub fn address_a(&mut self) -> Script {
        u32_state(self.paul, INSTRUCTION_ADDRESS_A)
    }

    pub fn address_b(&mut self) -> Script {
        u32_state(self.paul, INSTRUCTION_ADDRESS_B)
    }

    pub fn address_c(&mut self) -> Script {
        u32_state(self.paul, INSTRUCTION_ADDRESS_C)
    }

    pub fn value_a(&mut self) -> Script {
        u32_state(self.paul, INSTRUCTION_VALUE_A)
    }

    pub fn value_b(&mut self) -> Script {
        u32_state(self.paul, INSTRUCTION_VALUE_B)
    }

    pub fn value_c(&mut self) -> Script {
        u32_state(self.paul, INSTRUCTION_VALUE_C)
    }

    pub fn pc_curr(&mut self) -> Script {
        u32_state(self.paul, INSTRUCTION_PC_CURR)
    }

    pub fn pc_next(&mut self) -> Script {
        u32_state(self.paul, INSTRUCTION_PC_NEXT)
    }

    pub fn trace_response(&mut self, index: u8) -> Script {
        u160_state(self.paul, &TRACE_RESPONSE(index))
    }

    pub fn trace_response_pc(&mut self, index: u8) -> Script {
        u32_state(self.paul, &TRACE_RESPONSE_PC(index))
    }

    pub fn merkle_response_a(&mut self, index: u8) -> Script {
        u160_state(self.paul, &MERKLE_RESPONSE_A(index))
    }

    pub fn merkle_response_b(&mut self, index: u8) -> Script {
        u160_state(self.paul, &MERKLE_RESPONSE_B(index))
    }

    pub fn merkle_response_c_prev(&mut self, index: u8) -> Script {
        u160_state(self.paul, &MERKLE_CHALLENGE_C_PREV(index))
    }

    pub fn merkle_response_c_next(&mut self, index: u8) -> Script {
        u160_state(self.paul, &MERKLE_RESPONSE_C_NEXT(index))
    }

    pub fn merkle_response_c_next_sibling(&mut self, index: u8) -> Script {
        u160_state(self.paul, &MERKLE_RESPONSE_C_NEXT_SIBLING(index))
    }
}

pub struct PaulUnlock<'a> {
    paul: &'a mut dyn Paul,
}

impl PaulUnlock<'_>
{
    pub fn instruction_type(&mut self) -> Script {
        let value = self.paul.instruction_type();
        u8_state_unlock(self.paul.get_actor(), INSTRUCTION_TYPE, value)
    }

    pub fn address_a(&mut self) -> Script {
        let value = self.paul.address_a();
        u32_state_unlock(self.paul.get_actor(), INSTRUCTION_ADDRESS_A, value)
    }

    pub fn address_b(&mut self) -> Script {
        let value = self.paul.address_b();
        u32_state_unlock(self.paul.get_actor(), INSTRUCTION_ADDRESS_B, value)
    }

    pub fn address_c(&mut self) -> Script {
        let value = self.paul.address_c();
        u32_state_unlock(self.paul.get_actor(), INSTRUCTION_ADDRESS_C, value)
    }

    pub fn value_a(&mut self) -> Script {
        let value = self.paul.value_a();
        u32_state_unlock(self.paul.get_actor(), INSTRUCTION_VALUE_A, value)
    }

    pub fn value_b(&mut self) -> Script {
        let value = self.paul.value_b();
        u32_state_unlock(self.paul.get_actor(), INSTRUCTION_VALUE_B, value)
    }

    pub fn value_c(&mut self) -> Script {
        let value = self.paul.value_c();
        u32_state_unlock(self.paul.get_actor(), INSTRUCTION_VALUE_C, value)
    }

    pub fn pc_curr(&mut self) -> Script {
        let value = self.paul.address_a();
        u32_state_unlock(self.paul.get_actor(), INSTRUCTION_PC_CURR, value)
    }

    pub fn pc_next(&mut self) -> Script {
        let value = self.paul.address_a();
        u32_state_unlock(self.paul.get_actor(), INSTRUCTION_PC_NEXT, value)
    }

    pub fn trace_response(&mut self, index: u8) -> Script {
        let value: U160 = self.paul.trace_response(index).into();
        u160_state_unlock(self.paul.get_actor(), &TRACE_RESPONSE(index), value)
    }

    pub fn trace_response_pc(&mut self, index: u8) -> Script {
        let value = self.paul.trace_response_pc(index);
        u32_state_unlock(self.paul.get_actor(), &TRACE_RESPONSE_PC(index), value)
    }

    pub fn merkle_response_a(&mut self, index: u8) -> Script {
        let value: U160 = self.paul.merkle_response_a(index).into();
        u160_state_unlock(self.paul.get_actor(), &MERKLE_RESPONSE_A(index), value)
    }

    pub fn merkle_response_b(&mut self, index: u8) -> Script {
        let value: U160 = self.paul.merkle_response_b(index).into();
        u160_state_unlock(self.paul.get_actor(), &MERKLE_RESPONSE_B(index), value)
    }

    pub fn merkle_response_c_prev(&mut self, index: u8) -> Script {
        let value: U160 = self.paul.merkle_response_c_prev(index).into();
        u160_state_unlock(self.paul.get_actor(), &MERKLE_CHALLENGE_C_PREV(index), value)
    }

    pub fn merkle_response_c_next(&mut self, index: u8) -> Script {
        let value: U160 = self.paul.merkle_response_c_next(index).into();
        u160_state_unlock(self.paul.get_actor(), &MERKLE_RESPONSE_C_NEXT(index), value)
    }

    pub fn merkle_response_c_next_sibling(&mut self, index: u8) -> Script {
        let value: U160 = self.paul.merkle_response_c_next_sibling(index).into();
        u160_state_unlock(self.paul.get_actor(), &MERKLE_RESPONSE_C_NEXT_SIBLING(index), value)
    }
}

struct PaulPlayer {
    player: Player,
    vm: VM,
    opponent: VickyOpponent,
}

impl PaulPlayer {
    fn new(secret: &str, program_source: &[Instruction], memory_entries: &[u32]) -> Self {
        Self {
            player: Player::new(secret),
            vm: VM::new(program_source, memory_entries),
            opponent: VickyOpponent::new(),
        }
    }
}

impl Paul for PaulPlayer {
    fn instruction_type(&mut self) -> u8 {
        let trace_index = self.opponent.trace_index() + 1;
        let snapshot = self.vm.run(trace_index as usize);
        snapshot.instruction.asm_type
    }

    fn address_a(&mut self) -> u32 {
        let trace_index = self.opponent.trace_index();
        let snapshot = self.vm.run(trace_index as usize);
        snapshot.instruction.address_a
    }

    fn address_b(&mut self) -> u32 {
        let trace_index = self.opponent.trace_index();
        let snapshot = self.vm.run(trace_index as usize);
        snapshot.instruction.address_b
    }

    fn address_c(&mut self) -> u32 {
        let trace_index = self.opponent.trace_index();
        let snapshot = self.vm.run(trace_index as usize);
        snapshot.instruction.address_c
    }

    fn value_a(&mut self) -> u32 {
        // Read the value_a of the previous state
        // (The value at address_a in the snapshot at trace_index + 1 may already be overwritten)
        let trace_index = self.opponent.trace_index();
        let snapshot = self.vm.run(trace_index as usize);
        snapshot.read(self.address_a())
    }

    fn value_b(&mut self) -> u32 {
        // Read the value_b of the previous state
        // (The value at address_b in the snapshot at trace_index + 1 may already be overwritten)
        let trace_index = self.opponent.trace_index();
        let snapshot = self.vm.run(trace_index as usize);
        snapshot.read(self.address_b())
    }

    fn value_c(&mut self) -> u32 {
        let trace_index = self.opponent.trace_index();
        let snapshot = self.vm.run(trace_index as usize);
        snapshot.read(self.address_c())
    }

    fn pc_curr(&mut self) -> u32 {
        // Get the program counter of the previous instruction
        let trace_index = self.opponent.trace_index() - 1;
        let snapshot = self.vm.run(trace_index as usize);
        snapshot.pc
    }

    fn pc_next(&mut self) -> u32 {
        let trace_index = self.opponent.trace_index();
        let snapshot = self.vm.run(trace_index as usize);
        snapshot.pc
    }

    fn trace_response(&mut self, round_index: u8) -> HashDigest {
        let trace_index = self.opponent.next_trace_index(round_index);
        let snapshot = self.vm.run(trace_index as usize);
        snapshot.root()
    }

    fn trace_response_pc(&mut self, round_index: u8) -> u32 {
        let trace_index = self.opponent.next_trace_index(round_index);
        let snapshot = self.vm.run(trace_index as usize);
        snapshot.pc
    }

    fn merkle_response_a(&mut self, round_index: u8) -> HashDigest {
        let trace_index = self.opponent.trace_index();
        let snapshot = self.vm.run(trace_index as usize);
        let path = snapshot.path(self.address_a());
        let merkle_index_a = self.opponent.next_merkle_index_a(round_index);
        // TODO: we have to return a hash here, not a node of the path. MerklePathVerify up to round_index
        path.verify_up_to(merkle_index_a as usize)
    }

    fn merkle_response_a_sibling(&mut self, roundIndex: u8) -> HashDigest {
        let trace_index = self.opponent.trace_index();
        let snapshot = self.vm.run(trace_index as usize);
        let path = snapshot.path(self.address_a());
        let merkle_index_a = match roundIndex < LOG_PATH_LEN as u8 {
            true => self.opponent.next_merkle_index_a(roundIndex) - 1,
            false => self.opponent.merkle_index_a(),
        };
        path.get_node(merkle_index_a as usize)
    }

    fn merkle_response_b(&mut self, round_index: u8) -> HashDigest {
        let trace_index = self.opponent.trace_index();
        let snapshot = self.vm.run(trace_index as usize);
        let path = snapshot.path(self.address_b());
        let merkle_index_b = self.opponent.next_merkle_index_b(round_index);
        // TODO: we have to return a hash here, not a node of the path. MerklePathVerify up to round_index
        path.verify_up_to(merkle_index_b as usize)
    }

    fn merkle_response_b_sibling(&mut self, round_index: u8) -> HashDigest {
        let trace_index = self.opponent.trace_index();
        let snapshot = self.vm.run(trace_index as usize);
        let path = snapshot.path(self.address_b());
        let merkle_index_b = match round_index < LOG_PATH_LEN as u8 {
            true => self.opponent.next_merkle_index_b(round_index) - 1,
            false => self.opponent.merkle_index_b(),
        };
        path.get_node(merkle_index_b as usize)
    }

    fn merkle_response_c_prev(&mut self, round_index: u8) -> HashDigest {
        let trace_index = self.opponent.trace_index();
        let merkle_index_c = self.opponent.next_merkle_index_c_prev(round_index);
        let prev_snapshot = self.vm.run(trace_index as usize);
        let prev_path = prev_snapshot.path(self.address_c());
        prev_path.verify_up_to(merkle_index_c as usize)
    }

    fn merkle_response_c_next(&mut self, merkle_index_c: u8) -> HashDigest {
        let trace_index = self.opponent.trace_index() + 1;
        let snapshot = self.vm.run(trace_index as usize);
        let path = snapshot.path(self.address_c());
        path.verify_up_to(merkle_index_c as usize)
    }

    fn merkle_response_c_next_sibling(&mut self, merkle_index_c: u8) -> HashDigest {
        let trace_index = self.opponent.trace_index() + 1;
        let snapshot = self.vm.run(trace_index as usize);
        let path = snapshot.path(self.address_c());
        path.get_node(merkle_index_c as usize)
    }

    fn commit(&mut self) -> PaulCommit {
        PaulCommit {
            actor: &mut self.player,
        }
    }

    fn push(&mut self) -> PaulPush {
        PaulPush {
            paul: &mut self.player,
        }
    }

    fn unlock(&mut self) -> PaulUnlock {
        PaulUnlock { paul: self }
    }

    fn get_actor(&mut self) -> &mut dyn Actor {
        &mut self.player
    }
}

struct PaulOpponent {
    opponent: Opponent,
}

impl PaulOpponent {
    pub fn new() -> PaulOpponent {
        PaulOpponent {
            opponent: Opponent::new(),
        }
    }
}

impl Paul for PaulOpponent {
    fn instruction_type(&mut self) -> u8 {
        self.opponent.get_u32(String::from(INSTRUCTION_TYPE)) as u8
    }

    fn address_a(&mut self) -> u32 {
        self.opponent.get_u32(String::from(INSTRUCTION_ADDRESS_A))
    }

    fn address_b(&mut self) -> u32 {
        self.opponent.get_u32(String::from(INSTRUCTION_ADDRESS_B))
    }

    fn address_c(&mut self) -> u32 {
        self.opponent.get_u32(String::from(INSTRUCTION_ADDRESS_C))
    }

    fn value_a(&mut self) -> u32 {
        self.opponent.get_u32(String::from(INSTRUCTION_VALUE_A))
    }

    fn value_b(&mut self) -> u32 {
        self.opponent.get_u32(String::from(INSTRUCTION_VALUE_B))
    }

    fn value_c(&mut self) -> u32 {
        self.opponent.get_u32(String::from(INSTRUCTION_VALUE_C))
    }

    fn pc_curr(&mut self) -> u32 {
        self.opponent.get_u32(String::from(INSTRUCTION_PC_CURR))
    }

    fn pc_next(&mut self) -> u32 {
        self.opponent.get_u32(String::from(INSTRUCTION_PC_NEXT))
    }

    fn trace_response(&mut self, round_index: u8) -> HashDigest {
        // TODO: Bring [u8; 20] and [u32; 5] to common denominator
        let words = self.opponent.get_u160(TRACE_RESPONSE(round_index)).0;
        let mut bytes = [0u8; 20];
        bytes[0..4].copy_from_slice(&words[0].to_le_bytes());
        bytes[4..8].copy_from_slice(&words[1].to_le_bytes());
        bytes[8..16].copy_from_slice(&words[2].to_le_bytes());
        bytes[16..20].copy_from_slice(&words[3].to_le_bytes());
        bytes
    }

    fn trace_response_pc(&mut self, round_index: u8) -> u32 {
        self.opponent.get_u32(TRACE_RESPONSE_PC(round_index))
    }

    fn merkle_response_a(&mut self, round_index: u8) -> HashDigest {
        // TODO: Bring [u8; 20] and [u32; 5] to common denominator
        let words = self.opponent.get_u160(MERKLE_RESPONSE_A(round_index)).0;
        let mut bytes = [0u8; 20];
        bytes[0..4].copy_from_slice(&words[0].to_le_bytes());
        bytes[4..8].copy_from_slice(&words[1].to_le_bytes());
        bytes[8..16].copy_from_slice(&words[2].to_le_bytes());
        bytes[16..20].copy_from_slice(&words[3].to_le_bytes());
        bytes
    }
    
    fn merkle_response_a_sibling(&mut self, _index: u8) -> HashDigest {
        unimplemented!()
    }

    fn merkle_response_b(&mut self, round_index: u8) -> HashDigest {
        // TODO: Bring [u8; 20] and [u32; 5] to common denominator
        let words = self.opponent.get_u160(MERKLE_RESPONSE_B(round_index)).0;
        let mut bytes = [0u8; 20];
        bytes[0..4].copy_from_slice(&words[0].to_le_bytes());
        bytes[4..8].copy_from_slice(&words[1].to_le_bytes());
        bytes[8..16].copy_from_slice(&words[2].to_le_bytes());
        bytes[16..20].copy_from_slice(&words[3].to_le_bytes());
        bytes
    }
    
    fn merkle_response_b_sibling(&mut self, _index: u8) -> HashDigest {
        unimplemented!()
    }

    fn merkle_response_c_prev(&mut self, round_index: u8) -> HashDigest {
        // TODO: Bring [u8; 20] and [u32; 5] to common denominator
        let words = self.opponent.get_u160(MERKLE_RESPONSE_C_PREV(round_index)).0;
        let mut bytes = [0u8; 20];
        bytes[0..4].copy_from_slice(&words[0].to_le_bytes());
        bytes[4..8].copy_from_slice(&words[1].to_le_bytes());
        bytes[8..16].copy_from_slice(&words[2].to_le_bytes());
        bytes[16..20].copy_from_slice(&words[3].to_le_bytes());
        bytes
    }

    fn merkle_response_c_next(&mut self, round_index: u8) -> HashDigest {
        // TODO: Bring [u8; 20] and [u32; 5] to common denominator
        let words = self.opponent.get_u160(MERKLE_RESPONSE_C_NEXT(round_index)).0;
        let mut bytes = [0u8; 20];
        bytes[0..4].copy_from_slice(&words[0].to_le_bytes());
        bytes[4..8].copy_from_slice(&words[1].to_le_bytes());
        bytes[8..16].copy_from_slice(&words[2].to_le_bytes());
        bytes[16..20].copy_from_slice(&words[3].to_le_bytes());
        bytes
    }

    fn merkle_response_c_next_sibling(&mut self, _index: u8) -> HashDigest {
        unimplemented!()
    }

    fn commit(&mut self) -> PaulCommit {
        PaulCommit {
            actor: &mut self.opponent
        }
    }

    fn push(&mut self) -> PaulPush {
        PaulPush {
            paul: &mut self.opponent
        }
    }

    fn unlock(&mut self) -> PaulUnlock {
        PaulUnlock { paul: self }
    }

    fn get_actor(&mut self) -> &mut dyn Actor {
        &mut self.opponent
    }
}

pub trait Vicky {
    // Index of the last valid VM state
    fn trace_index(&mut self) -> u32;

    // Index of the current state
    fn next_trace_index(&mut self, index: u8) -> u32;

    // Get the next trace challenge
    fn trace_challenge(&mut self, index: u8) -> bool;

    // Index of the last valid node in the Merkle path
    fn merkle_index_a(&mut self) -> u32;

    // Index of the last valid node in the Merkle path
    fn merkle_index_b(&mut self) -> u32;

    // Index of the last valid node in the Merkle path
    fn merkle_index_c_prev(&mut self) -> u32;

    // Index of the current node in the Merkle path
    fn next_merkle_index_a(&mut self, index: u8) -> u32;

    // Index of the current node in the Merkle path
    fn next_merkle_index_b(&mut self, index: u8) -> u32;

    // Index of the current node in the Merkle path
    fn next_merkle_index_c_prev(&mut self, index: u8) -> u32;

    // Get the next Merkle challenge for value_a
    fn merkle_challenge_a(&mut self, index: u8) -> bool;

    // Get the next Merkle challenge for value_b
    fn merkle_challenge_b(&mut self, index: u8) -> bool;

    // Get the next Merkle challenge for value_c
    fn merkle_challenge_c_prev(&mut self, index: u8) -> bool;

    fn is_faulty_read_a(&mut self) -> bool;

    fn is_faulty_read_b(&mut self) -> bool;

    fn is_faulty_write_c(&mut self) -> bool;

    fn is_faulty_pc_curr(&mut self) -> bool;

    fn is_faulty_pc_next(&mut self) -> bool;

    fn commit (&mut self) -> VickyCommit;

    fn push (&mut self) -> VickyPush;

    fn unlock (&mut self) -> VickyUnlock;

    fn get_actor(&mut self) -> &mut dyn Actor;
}


pub struct VickyCommit<'a> {
    actor: &'a mut dyn Actor,
}

impl VickyCommit<'_> {

    fn trace_challenge(&mut self, round_index: u8) -> Script {
        bit_state_commit(self.actor, &TRACE_CHALLENGE(round_index), None)
    }

    fn merkle_challenge_a(&mut self, round_index: u8) -> Script {
        bit_state_commit(self.actor, &MERKLE_CHALLENGE_A(round_index), None)
    }

    fn merkle_challenge_b(&mut self, round_index: u8) -> Script {
        bit_state_commit(self.actor, &MERKLE_CHALLENGE_B(round_index), None)
    }

}
pub struct VickyPush<'a> {
    vicky: &'a mut dyn Actor,
}

impl<'a> VickyPush<'a>
{
    fn trace_challenge(&mut self, round_index: u8) -> Script {
        bit_state(self.vicky, &TRACE_CHALLENGE(round_index), None)
    }

    fn merkle_challenge_a(&mut self, round_index: u8) -> Script {
        bit_state(self.vicky, &MERKLE_CHALLENGE_A(round_index), None)
    }

    fn merkle_challenge_b(&mut self, round_index: u8) -> Script {
        bit_state(self.vicky, &MERKLE_CHALLENGE_B(round_index), None)
    }

    fn trace_index(&mut self) -> Script {
        script! {
            0
            { unroll(LOG_TRACE_LEN, |i| script! {
                    OP_SWAP
                    { self.trace_challenge(i as u8) }
                    OP_IF
                        { 1 << LOG_TRACE_LEN - 1 - i }
                        OP_ADD
                    OP_ENDIF
            }) }
        }
    }

    fn merkle_index_a(&mut self) -> Script {
        script! {
            0
            { unroll(LOG_PATH_LEN, |i| script! {
                OP_SWAP
                { self.merkle_challenge_a(i as u8) }
                OP_IF
                	{ 1 << LOG_PATH_LEN - 1 - i }
                	OP_ADD
                OP_ENDIF
            }) }
        }
    }    

    fn merkle_index_b(&mut self) -> Script {
        script! {
            0
            { unroll(LOG_PATH_LEN, |i| script! {
                OP_SWAP
                { self.merkle_challenge_b(i as u8) }
                OP_IF
                    { 1 << LOG_PATH_LEN - 1 - i }
                    OP_ADD
                OP_ENDIF
            }) }
        }
    }

    fn next_merkle_index_a(&mut self, round_index: u8) -> Script {
        script! {
            0
            { unroll(round_index as u32, |i| script! {
                OP_SWAP
                { self.merkle_challenge_a(i as u8) }
                OP_IF
	                { 1 << LOG_PATH_LEN - 1 - i }
	                OP_ADD
                OP_ENDIF
            }) }
            { 1 << LOG_PATH_LEN - 1 - round_index as u32 }
            OP_ADD
        }
    }    

    fn next_merkle_index_b(&mut self, round_index: u8) -> Script {
        script! {
            0
            { unroll(round_index as u32, |i| script! {
                OP_SWAP
                { self.merkle_challenge_b(i as u8) }
                OP_IF
                    { 1 << LOG_PATH_LEN - 1 - i }
                    OP_ADD
                OP_ENDIF
            }) }
            { 1 << LOG_PATH_LEN - 1 - round_index as u32 }
            OP_ADD
        }
    }
}

pub struct VickyUnlock<'a> {
    vicky: &'a mut dyn Vicky,
}

impl VickyUnlock<'_,>
{
    fn trace_challenge(&mut self, round_index: u8) -> Script {
        let value = self.vicky.trace_challenge(round_index) as u32;
        bit_state_unlock(self.vicky.get_actor(), &TRACE_CHALLENGE(round_index), None, value)
    }

    fn trace_index(&mut self) -> Script {
        script!{{ unroll(LOG_TRACE_LEN, |i| self.trace_challenge( (LOG_TRACE_LEN - 1 - i) as u8)) }}
    }

    fn next_trace_index(&mut self, round_index: u8) -> Script{
        script!{{ unroll(round_index.into(), |i| self.trace_challenge( round_index - 1 - i as u8)) }}
    }

    fn merkle_challenge_a(&mut self, round_index: u8) -> Script {
        let value = self.vicky.merkle_challenge_a(round_index) as u32;
        bit_state_unlock(self.vicky.get_actor(), &MERKLE_CHALLENGE_A(round_index), None, value)
    }

    fn merkle_challenge_b(&mut self, round_index: u8) -> Script {
        let value = self.vicky.merkle_challenge_b(round_index) as u32;
        bit_state_unlock(self.vicky.get_actor(), &MERKLE_CHALLENGE_B(round_index), None, value)
    }

    fn merkle_index_a(&mut self) -> Script {
        script! {
            { unroll(LOG_PATH_LEN, |i| self.merkle_challenge_a((LOG_PATH_LEN - 1 - i) as u8)) }
        }
    }

    fn merkle_index_b(&mut self) -> Script {
        script! {
            { unroll(LOG_PATH_LEN, |i| self.merkle_challenge_b((LOG_PATH_LEN - 1 - i) as u8)) }
        }
    }

    fn next_merkle_index_a(&mut self, round_index: u8) -> Script {
        script! {
            { unroll(round_index as u32, |i| self.merkle_challenge_a(round_index - 1 - i as u8)) }
        }
    }

    fn next_merkle_index_b(&mut self, round_index: u8) -> Script {
        script! {
            { unroll(round_index as u32, |i| self.merkle_challenge_b(round_index - 1 - i as u8)) }
        }
    }
}

struct VickyPlayer {
    player: Player,
    vm: VM,
    opponent: PaulOpponent,
}

impl VickyPlayer {
    fn new(secret: &str, program_source: &[Instruction], memory_entries: &[u32]) -> Self {
        Self {
            player: Player::new(secret),
            vm: VM::new(program_source, memory_entries),
            opponent: PaulOpponent::new(),
        }
    }
}

impl Vicky for VickyPlayer {

    // Index of the last valid VM state
    fn trace_index(&mut self) -> u32 {
        let mut trace_index = 0;
        for i in 0..LOG_TRACE_LEN {
            let bit = self.trace_challenge(i as u8) as u32;
            trace_index += bit << LOG_TRACE_LEN - 1 - i;
        }
        trace_index
    }

    // Index of the current state
    fn next_trace_index(&mut self, round_index: u8) -> u32 {
        let mut trace_index = 0;
        for i in 0..round_index {
            let bit = self.trace_challenge(i) as u32;
            trace_index += bit << LOG_TRACE_LEN - 1 - i as u32;
        }
        trace_index += 1 << LOG_TRACE_LEN - 1 - round_index as u32;
        trace_index
    }

    // Get the next trace challenge
    fn trace_challenge(&mut self, round_index: u8) -> bool {
        let trace_index = self.next_trace_index(round_index);
        let snapshot = self.vm.run(trace_index as usize);
        let our_root = snapshot.root();
        let our_pc = snapshot.pc;
        let their_root = self.opponent.trace_response(round_index);
        let their_pc = self.opponent.trace_response_pc(round_index);
        let is_correct = our_root == their_root && our_pc == their_pc;
        is_correct
    }

    // Index of the last valid node in the Merkle path
    fn merkle_index_a(&mut self) -> u32 {
        let mut merkle_index_a = 0;
        for i in 0..LOG_PATH_LEN {
            let bit = self.merkle_challenge_a(i as u8) as u32;
            merkle_index_a += bit << LOG_PATH_LEN - 1 - i;
        }
        merkle_index_a
    }

    // Index of the last valid node in the Merkle path
    fn merkle_index_b(&mut self) -> u32 {
        let mut merkle_index_b = 0;
        for i in 0..LOG_PATH_LEN {
            let bit = self.merkle_challenge_b(i as u8) as u32;
            merkle_index_b += bit << LOG_PATH_LEN - 1 - i;
        }
        merkle_index_b
    }

    // Index of the last valid node in the Merkle path
    fn merkle_index_c_prev(&mut self) -> u32 {
        let mut merkle_index_c = 0;
        for i in 0..LOG_PATH_LEN {
            let bit = self.merkle_challenge_c_prev(i as u8) as u32;
            merkle_index_c += bit << LOG_PATH_LEN - 1 - i;
        }
        merkle_index_c
    }

    // Index of the current node in the Merkle path
    fn next_merkle_index_a(&mut self, round_index: u8) -> u32 {
        let mut merkleIndexA = 0;
        for i in 0..round_index {
            let bit = self.merkle_challenge_a(i) as u32;
            merkleIndexA += bit << LOG_PATH_LEN - 1 - i as u32;
        }
        merkleIndexA += 1 << LOG_PATH_LEN - 1 - round_index as u32;
        merkleIndexA
    }

    // Index of the current node in the Merkle path
    fn next_merkle_index_b(&mut self, round_index: u8) -> u32 {
        let mut merkleIndexB = 0;
        for i in 0..round_index {
            let bit = self.merkle_challenge_b(i) as u32;
            merkleIndexB += bit << LOG_PATH_LEN - 1 - i as u32;
        }
        merkleIndexB += 1 << LOG_PATH_LEN - 1 - round_index as u32;
        merkleIndexB
    }

    // Index of the current node in the Merkle path
    fn next_merkle_index_c_prev(&mut self, round_index: u8) -> u32 {
        let mut merkleIndexC = 0;
        for i in 0..round_index {
            let bit = self.merkle_challenge_c_prev(i) as u32;
            merkleIndexC += bit << LOG_PATH_LEN - 1 - i as u32;
        }
        merkleIndexC += 1 << LOG_PATH_LEN - 1 - round_index as u32;
        merkleIndexC
    }

    // Get the next Merkle challenge
    fn merkle_challenge_a(&mut self, round_index: u8) -> bool {
        let node_index = self.next_merkle_index_a(round_index); // NOTE: May flip `node_index = PATH_LEN - 1 - node_index`
        let trace_index = self.trace_index() as usize;
        let snapshot = self.vm.run(trace_index);
        let our_node = snapshot.path(self.opponent.address_a()).get_node(node_index as usize);
        let their_node = self.opponent.merkle_response_a(round_index);
        let is_correct = our_node == their_node;
        is_correct
    }

    // Get the next Merkle challenge
    fn merkle_challenge_b(&mut self, round_index: u8) -> bool {
        let node_index = self.next_merkle_index_b(round_index); // NOTE: May flip `node_index = PATH_LEN - 1 - node_index`
        let trace_index = self.trace_index() as usize;
        let snapshot = self.vm.run(trace_index);
        let our_node = snapshot.path(self.opponent.address_b()).get_node(node_index as usize);
        let their_node = self.opponent.merkle_response_b(round_index);
        let is_correct = our_node == their_node;
        is_correct
    }

    // Get the next Merkle challenge
    fn merkle_challenge_c_prev(&mut self, round_index: u8) -> bool {
        let trace_index = self.trace_index() as usize;
        let node_index = self.next_merkle_index_c_prev(round_index); // NOTE: May flip `node_index = PATH_LEN - 1 - node_index`
        let snapshot = self.vm.run(trace_index);
        let our_prev_node = snapshot.path(self.opponent.address_c()).get_node(node_index as usize);

        let prev_node = self.opponent.merkle_response_c_prev(round_index);
        let is_correct = our_prev_node == prev_node;
        is_correct
    }

    // TODO: Maybe Vicky should have "this.valueA" etc. too. In that case it should be moved to the Player class.
    fn is_faulty_read_a(&mut self) -> bool {
        let trace_index = self.trace_index() as usize;
        let snapshot = self.vm.run(trace_index);
        let value_a = snapshot.read(self.opponent.address_a());
        value_a != self.opponent.value_a()
    }

    fn is_faulty_read_b(&mut self) -> bool {
        let trace_index = self.trace_index() as usize;
        let snapshot = self.vm.run(trace_index);
        let value_b = snapshot.read(self.opponent.address_b());
        value_b != self.opponent.value_b()
    }

    fn is_faulty_write_c(&mut self) -> bool {
        let trace_index = self.trace_index() as usize;
        let snapshot = self.vm.run(trace_index + 1);
        let value_c = snapshot.read(self.opponent.address_c());
        value_c != self.opponent.value_c()
    }

    fn is_faulty_pc_curr(&mut self) -> bool {
        let trace_index = self.trace_index() as usize;
        let snapshot = self.vm.run(trace_index);
        let pc_curr = snapshot.read(self.opponent.pc_curr());
        pc_curr != self.opponent.pc_curr()
    }

    fn is_faulty_pc_next(&mut self) -> bool {
        let trace_index = self.trace_index() as usize;
        let snapshot = self.vm.run(trace_index + 1);
        let pc_next = snapshot.read(self.opponent.pc_next());
        pc_next != self.opponent.pc_next()
    }

    fn commit (&mut self) -> VickyCommit {
        VickyCommit {
            actor: &mut self.player,
        }
    }

    fn push (&mut self) -> VickyPush {
        VickyPush {
            vicky: &mut self.player,
        }
    }

    fn unlock (&mut self) -> VickyUnlock {
        VickyUnlock { vicky: self }
    }

    fn get_actor(&mut self) -> &mut dyn Actor {
        &mut self.player
    }
}

struct VickyOpponent {
    opponent: Opponent,
}

impl VickyOpponent {
    pub fn new() -> VickyOpponent {
        VickyOpponent {
            opponent: Opponent::new(),
        }
    }
}

impl Vicky for VickyOpponent {

    // Index of the last valid VM state
    fn trace_index(&mut self) -> u32 {
        let mut trace_index = 0;
        for i in 0..LOG_TRACE_LEN {
            let bit = self.trace_challenge(i as u8) as u32;
            trace_index += bit << LOG_TRACE_LEN - 1 - i;
        }
        trace_index
    }
    
    // Index of the current state
    fn next_trace_index(&mut self, round_index: u8) -> u32 {
        let mut trace_index = 0;
        for i in 0..round_index {
            let bit = self.trace_challenge(i) as u32;
            trace_index += bit << LOG_TRACE_LEN - 1 - i as u32;
        }
        trace_index += 1 << LOG_TRACE_LEN - 1 - round_index as u32;
        trace_index
    }

    // Get the next trace challenge
    fn trace_challenge(&mut self, round_index: u8) -> bool {
        self.opponent.get_u1(TRACE_CHALLENGE(round_index)) != 0
    }

    // Index of the last valid node in the Merkle path
    fn merkle_index_a(&mut self) -> u32 {
        let mut merkle_index_a = 0;
        for i in 0..LOG_PATH_LEN {
            let bit = self.merkle_challenge_a(i as u8) as u32;
            merkle_index_a += bit << LOG_PATH_LEN - 1 - i;
        }
        merkle_index_a
    }

    // Index of the last valid node in the Merkle path
    fn merkle_index_b(&mut self) -> u32 {
        let mut merkle_index_b = 0;
        for i in 0..LOG_PATH_LEN {
            let bit = self.merkle_challenge_b(i as u8) as u32;
            merkle_index_b += bit << LOG_PATH_LEN - 1 - i;
        }
        merkle_index_b
    }

    // Index of the last valid node in the Merkle path
    fn merkle_index_c_prev(&mut self) -> u32 {
        let mut merkle_index_c = 0;
        for i in 0..LOG_PATH_LEN {
            let bit = self.merkle_challenge_c_prev(i as u8) as u32;
            merkle_index_c += bit << LOG_PATH_LEN - 1 - i;
        }
        merkle_index_c
    }

    // Index of the current node in the Merkle path
    fn next_merkle_index_a(&mut self, round_index: u8) -> u32 {
        let mut merkle_index_a = 0;
        for i in 0..round_index {
            let bit = self.merkle_challenge_a(i) as u32;
            merkle_index_a += bit << LOG_PATH_LEN - 1 - i as u32;
        }
        merkle_index_a += 1 << LOG_PATH_LEN - 1 - round_index as u32;
        merkle_index_a
    }

    // Index of the current node in the Merkle path
    fn next_merkle_index_b(&mut self, round_index: u8) -> u32 {
        let mut merkle_index_b = 0;
        for i in 0..round_index {
            let bit = self.merkle_challenge_b(i) as u32;
            merkle_index_b += bit << LOG_PATH_LEN - 1 - i as u32;
        }
        merkle_index_b += 1 << LOG_PATH_LEN - 1 - round_index as u32;
        merkle_index_b
    }

    // Index of the current node in the Merkle path
    fn next_merkle_index_c_prev(&mut self, round_index: u8) -> u32 {
        let mut merkle_index_c = 0;
        for i in 0..round_index {
            let bit = self.merkle_challenge_c_prev(i) as u32;
            merkle_index_c += bit << LOG_PATH_LEN - 1 - i as u32;
        }
        merkle_index_c += 1 << LOG_PATH_LEN - 1 - round_index as u32;
        merkle_index_c
    }

    // Get the next Merkle challenge
    fn merkle_challenge_a(&mut self, round_index: u8) -> bool {
        self.opponent.get_u1(MERKLE_CHALLENGE_A(round_index)) != 0
    }

    // Get the next Merkle challenge
    fn merkle_challenge_b(&mut self, round_index: u8) -> bool {
        self.opponent.get_u1(MERKLE_CHALLENGE_B(round_index)) != 0
    }

    // Get the next Merkle challenge
    fn merkle_challenge_c_prev(&mut self, round_index: u8) -> bool {
        self.opponent.get_u1(MERKLE_CHALLENGE_C_PREV(round_index)) != 0
    }

    fn is_faulty_read_a(&mut self) -> bool {
        unimplemented!()
    }

    fn is_faulty_read_b(&mut self) -> bool {
        unimplemented!()
    }

    fn is_faulty_write_c(&mut self) -> bool {
        unimplemented!()
    }

    fn is_faulty_pc_curr(&mut self) -> bool {
        unimplemented!()
    }

    fn is_faulty_pc_next(&mut self) -> bool {
        unimplemented!()
    }

    fn commit (&mut self) -> VickyCommit {
        VickyCommit {
            actor: &mut self.opponent,
        }
    }

    fn push (&mut self) -> VickyPush {
        VickyPush {
            vicky: &mut self.opponent,
        }
    }

    fn unlock (&mut self) -> VickyUnlock {
        VickyUnlock { vicky: self }
    }

    fn get_actor(&mut self) -> &mut dyn Actor {
        &mut self.opponent
    }
}




//
#[cfg(test)]
mod tests {

    use bitcoin_script::bitcoin_script as script;
    use crate::{scripts::opcodes::execute_script, bitvm::constants::ASM_ADD};
    use crate::bitvm::vm::Instruction;
    use super::PaulPlayer;
    use crate::bitvm::model::Paul;
    use super::pushable;


    #[test]
    fn test_push_and_unlock() {
        let address_a = 0;
        let value_a = 0xFFFFFFFB;
        let address_b = 1;
        let value_b = 7;
        let address_c = 2;
        let program = [Instruction {
            asm_type: ASM_ADD,
            address_a,
            address_b,
            address_c,
        }];
        let data: [u32; 2] = [value_a, value_b];

        let mut paul = PaulPlayer::new("d898098e09898a0980989b980809809809f09809884324874302975287524398", &program, &data);

        // let script = script! {
        //     { paul.unlock().value_a() }
        //     { paul.commit().value_a() }
        //     1
        // };

        // Works without opponent:
        //
        let script = script! {
            { paul.unlock().trace_response(0) }
            { paul.commit().trace_response(0) }
            1
        };

        let result = execute_script(script.into());
        // println!("{:?}", result.final_stack);
        assert!(result.success);
    }
}


// TODO: Test `push`, `commit`, `unlock` for Paul and Vicky using dummy Players with constant values

// TODO: Implement `export` for Vicky and Paul with Serde
