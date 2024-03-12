use crate::scripts::{
    actor::{Actor, HashDigest, Opponent, Player},
    opcodes::u32_state::{
        u32_state, u32_state_commit, u32_state_unlock, u8_state, u8_state_unlock, u8_state_commit,
    },
};
use bitcoin::ScriptBuf as Script;

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

trait Paul<T: Actor> {
    fn instruction_type(&self) -> u8;

    fn address_a(&self) -> u32;

    fn address_b(&self) -> u32;

    fn address_c(&self) -> u32;

    fn value_a(&self) -> u32;

    fn value_b(&self) -> u32;

    fn value_c(&self) -> u32;

    fn pc_curr(&self) -> u32;

    fn pc_next(&self) -> u32;

    fn trace_response(&self, round_index: u8) -> u32;

    fn trace_response_pc(&self, round_index: u8) -> u32;

    fn merkle_response_a(&self, round_index: u8) -> HashDigest;

    fn merkle_response_b(&self, round_index: u8) -> HashDigest;

    fn merkle_response_c_prev(&self, round_index: u8) -> HashDigest;

    fn merkle_response_c_next(&self, round_index: u8) -> HashDigest;

    fn merkle_response_c_next_sibling(&self, round_index: u8) -> HashDigest;

    fn commit(&mut self) -> PaulCommit<T>;

    fn push(&mut self) -> PaulPush<T>;

    fn unlock(&mut self) -> PaulUnlock<T>;

    fn get_actor(&mut self) -> &mut T;
}

struct PaulCommit<'a, T: Actor> {
    actor: &'a mut T,
}

impl<T: Actor> PaulCommit<'_, T> {
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

    pub fn trace_response(&mut self, round_index: u8) -> Script {
        todo!()
    }

    pub fn trace_response_pc(&mut self, round_index: u8) -> Script {
        todo!()
    }

    pub fn merkle_response_a(&mut self, round_index: u8) -> Script {
        todo!()
    }

    pub fn merkle_response_b(&mut self, round_index: u8) -> Script {
        todo!()
    }

    pub fn merkle_response_c_prev(&mut self, round_index: u8) -> Script {
        todo!()
    }

    pub fn merkle_response_c_next(&mut self, round_index: u8) -> Script {
        todo!()
    }

    pub fn merkle_response_c_next_sibling(&mut self, round_index: u8) -> Script {
        todo!()
    }
}

struct PaulPush<'a, T: Actor> {
    paul: &'a mut T,
}

impl<'a, T> PaulPush<'a, T>
where
    T: Actor,
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

    pub fn trace_response(&mut self, round_index: u8) -> Script {
        todo!()
    }

    pub fn trace_response_pc(&mut self, round_index: u8) -> Script {
        todo!()
    }

    pub fn merkle_response_a(&mut self, round_index: u8) -> Script {
        todo!()
    }

    pub fn merkle_response_b(&mut self, round_index: u8) -> Script {
        todo!()
    }

    pub fn merkle_response_c_prev(&mut self, round_index: u8) -> Script {
        todo!()
    }

    pub fn merkle_response_c_next(&mut self, round_index: u8) -> Script {
        todo!()
    }

    pub fn merkle_response_c_next_sibling(&mut self, round_index: u8) -> Script {
        todo!()
    }
}

struct PaulUnlock<'a, T: Actor> {
    paul: &'a mut dyn Paul<T>,
}

impl<T> PaulUnlock<'_, T>
where
    T: Actor,
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

    pub fn trace_response(&mut self, round_index: u8) -> Script {
        todo!()
    }

    pub fn trace_response_pc(&mut self, round_index: u8) -> Script {
        todo!()
    }

    pub fn merkle_response_a(&mut self, round_index: u8) -> Script {
        todo!()
    }

    pub fn merkle_response_b(&mut self, round_index: u8) -> Script {
        todo!()
    }

    pub fn merkle_response_c_prev(&mut self, round_index: u8) -> Script {
        todo!()
    }

    pub fn merkle_response_c_next(&mut self, round_index: u8) -> Script {
        todo!()
    }

    pub fn merkle_response_c_next_sibling(&mut self, round_index: u8) -> Script {
        todo!()
    }
}

struct PaulPlayer {
    player: Player,
    // vicky: &'a dyn Vicky,
}

impl Paul<Player> for PaulPlayer {
    fn instruction_type(&self) -> u8 {
        todo!()
    }

    fn address_a(&self) -> u32 {
        todo!()
    }

    fn address_b(&self) -> u32 {
        todo!()
    }

    fn address_c(&self) -> u32 {
        todo!()
    }

    fn value_a(&self) -> u32 {
        todo!()
    }

    fn value_b(&self) -> u32 {
        todo!()
    }

    fn value_c(&self) -> u32 {
        todo!()
    }

    fn pc_curr(&self) -> u32 {
        todo!()
    }

    fn pc_next(&self) -> u32 {
        todo!()
    }

    fn trace_response(&self, round_index: u8) -> u32 {
        todo!()
    }

    fn trace_response_pc(&self, round_index: u8) -> u32 {
        todo!()
    }

    fn merkle_response_a(&self, round_index: u8) -> HashDigest {
        todo!()
    }

    fn merkle_response_b(&self, round_index: u8) -> HashDigest {
        todo!()
    }

    fn merkle_response_c_prev(&self, round_index: u8) -> HashDigest {
        todo!()
    }

    fn merkle_response_c_next(&self, round_index: u8) -> HashDigest {
        todo!()
    }

    fn merkle_response_c_next_sibling(&self, round_index: u8) -> HashDigest {
        todo!()
    }

    fn commit(&mut self) -> PaulCommit<Player> {
        PaulCommit {
            actor: &mut self.player,
        }
    }

    fn push(&mut self) -> PaulPush<Player> {
        todo!()
    }

    fn unlock(&mut self) -> PaulUnlock<Player> {
        PaulUnlock { paul: self }
    }

    fn get_actor(&mut self) -> &mut Player {
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

impl Paul<Opponent> for PaulOpponent {
    fn instruction_type(&self) -> u8 {
        todo!()
    }

    fn address_a(&self) -> u32 {
        todo!()
    }

    fn address_b(&self) -> u32 {
        todo!()
    }

    fn address_c(&self) -> u32 {
        todo!()
    }

    fn value_a(&self) -> u32 {
        todo!()
    }

    fn value_b(&self) -> u32 {
        todo!()
    }

    fn value_c(&self) -> u32 {
        todo!()
    }

    fn pc_curr(&self) -> u32 {
        todo!()
    }

    fn pc_next(&self) -> u32 {
        todo!()
    }

    fn trace_response(&self, round_index: u8) -> u32 {
        todo!()
    }

    fn trace_response_pc(&self, round_index: u8) -> u32 {
        todo!()
    }

    fn merkle_response_a(&self, round_index: u8) -> HashDigest {
        todo!()
    }

    fn merkle_response_b(&self, round_index: u8) -> HashDigest {
        todo!()
    }

    fn merkle_response_c_prev(&self, round_index: u8) -> HashDigest {
        todo!()
    }

    fn merkle_response_c_next(&self, round_index: u8) -> HashDigest {
        todo!()
    }

    fn merkle_response_c_next_sibling(&self, round_index: u8) -> HashDigest {
        todo!()
    }

    fn commit(&mut self) -> PaulCommit<Opponent> {
        todo!()
    }

    fn push(&mut self) -> PaulPush<Opponent> {
        todo!()
    }

    fn unlock(&mut self) -> PaulUnlock<Opponent> {
        todo!()
    }

    fn get_actor(&mut self) -> &mut Opponent {
        &mut self.opponent
    }
}

trait Vicky {
    // Index of the last valid VM state
    fn trace_index(&self) -> u32;

    // Index of the current state
    fn next_trace_index(&self, round_index: u8) -> u32;

    // Get the next trace challenge
    fn trace_challenge(&self, round_index: u8) -> bool;

    // Index of the last valid node in the Merkle path
    fn merkle_index_a(&self) -> u32;

    // Index of the last valid node in the Merkle path
    fn merkle_index_b(&self) -> u32;

    // Index of the last valid node in the Merkle path
    fn merkle_index_c_prev(&self) -> u32;

    // Index of the current node in the Merkle path
    fn next_merkle_index_a(&self, round_index: u8) -> u32;

    // Index of the current node in the Merkle path
    fn next_merkle_index_b(&self, round_index: u8) -> u32;

    // Index of the current node in the Merkle path
    fn next_merkle_index_c_prev(&self, round_index: u8) -> u32;

    // Get the next Merkle challenge for value_a
    fn merkle_challenge_a(&self, round_index: u8) -> bool;

    // Get the next Merkle challenge for value_b
    fn merkle_challenge_b(&self, round_index: u8) -> bool;

    // Get the next Merkle challenge for value_c
    fn merkle_challenge_c_prev(&self, round_index: u8) -> bool;

    fn is_faulty_read_a(&self) -> bool;

    fn is_faulty_read_b(&self) -> bool;

    fn is_faulty_write_c(&self) -> bool;

    fn is_faulty_pc_curr(&self) -> bool;

    fn is_faulty_pc_next(&self) -> bool;

    // fn commit (&self) -> VickyCommit;

    // fn push (&self) -> VickyPush;

    // fn unlock (&self) -> VickyUnlock;
}
struct VickyPush<T: Actor> {
    vicky: T,
}

impl<T> VickyPush<T> where T: Actor {}
