use crate::scripts::{
    actor::{Actor, HashDigest, Opponent, Player},
    opcodes::{
        u160_std::{u160_state, u160_state_commit, u160_state_unlock, U160},
        u32_state::{
            bit_state, bit_state_commit, bit_state_unlock, u32_state, u32_state_commit, u32_state_unlock, u8_state, u8_state_commit, u8_state_unlock
        }, unroll, pushable,
    },
};

use bitcoin::ScriptBuf as Script;
use bitcoin_script::bitcoin_script as script;
use super::{constants::LOG_TRACE_LEN, vm::VM};

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

    fn trace_response(&self, index: u8) -> HashDigest;

    fn trace_response_pc(&self, index: u8) -> u32;

    fn merkle_response_a(&self, index: u8) -> HashDigest;

    fn merkle_response_b(&self, index: u8) -> HashDigest;

    fn merkle_response_c_prev(&self, index: u8) -> HashDigest;

    fn merkle_response_c_next(&self, index: u8) -> HashDigest;

    fn merkle_response_c_next_sibling(&self, index: u8) -> HashDigest;

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
    // opponent: &'a VickyOpponent,
}

impl Paul<Player> for PaulPlayer {
    fn instruction_type(&self) -> u8 {
        // let trace_index = self.opponent.trace_index + 1;
        // let snapshot = self.vm.run(trace_index);
        // snapshot.instruction.asm_type
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

    fn trace_response(&self, index: u8) -> HashDigest {
        todo!()
    }

    fn trace_response_pc(&self, index: u8) -> u32 {
        todo!()
    }

    fn merkle_response_a(&self, index: u8) -> HashDigest {
        todo!()
    }

    fn merkle_response_b(&self, index: u8) -> HashDigest {
        todo!()
    }

    fn merkle_response_c_prev(&self, index: u8) -> HashDigest {
        todo!()
    }

    fn merkle_response_c_next(&self, index: u8) -> HashDigest {
        todo!()
    }

    fn merkle_response_c_next_sibling(&self, index: u8) -> HashDigest {
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

    fn trace_response(&self, index: u8) -> HashDigest {
        todo!()
    }

    fn trace_response_pc(&self, index: u8) -> u32 {
        todo!()
    }

    fn merkle_response_a(&self, index: u8) -> HashDigest {
        todo!()
    }

    fn merkle_response_b(&self, index: u8) -> HashDigest {
        todo!()
    }

    fn merkle_response_c_prev(&self, index: u8) -> HashDigest {
        todo!()
    }

    fn merkle_response_c_next(&self, index: u8) -> HashDigest {
        todo!()
    }

    fn merkle_response_c_next_sibling(&self, index: u8) -> HashDigest {
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

trait Vicky<T: Actor> {
    // Index of the last valid VM state
    fn trace_index(&self) -> u32;

    // Index of the current state
    fn next_trace_index(&self, index: u8) -> u32;

    // Get the next trace challenge
    fn trace_challenge(&self, index: u8) -> bool;

    // Index of the last valid node in the Merkle path
    fn merkle_index_a(&self) -> u32;

    // Index of the last valid node in the Merkle path
    fn merkle_index_b(&self) -> u32;

    // Index of the last valid node in the Merkle path
    fn merkle_index_c_prev(&self) -> u32;

    // Index of the current node in the Merkle path
    fn next_merkle_index_a(&self, index: u8) -> u32;

    // Index of the current node in the Merkle path
    fn next_merkle_index_b(&self, index: u8) -> u32;

    // Index of the current node in the Merkle path
    fn next_merkle_index_c_prev(&self, index: u8) -> u32;

    // Get the next Merkle challenge for value_a
    fn merkle_challenge_a(&self, index: u8) -> bool;

    // Get the next Merkle challenge for value_b
    fn merkle_challenge_b(&self, index: u8) -> bool;

    // Get the next Merkle challenge for value_c
    fn merkle_challenge_c_prev(&self, index: u8) -> bool;

    fn is_faulty_read_a(&self) -> bool;

    fn is_faulty_read_b(&self) -> bool;

    fn is_faulty_write_c(&self) -> bool;

    fn is_faulty_pc_curr(&self) -> bool;

    fn is_faulty_pc_next(&self) -> bool;

    fn commit (&self) -> VickyCommit<T>;

    fn push (&self) -> VickyPush<T>;

    fn unlock (&self) -> VickyUnlock<T>;

    fn get_actor(&mut self) -> &mut T;
}


struct VickyCommit<'a, T: Actor> {
    actor: &'a mut T,
}

impl<T: Actor> VickyCommit<'_, T> {
    // pub fn instruction_type(&mut self) -> Script {
    //     todo!();
    // }

    fn trace_challenge(&mut self, round_index: u8) -> Script {
        return bit_state_commit(self.actor, &TRACE_CHALLENGE(round_index), None)
    }

    fn merkle_challenge_a(&mut self, round_index: u8) -> Script {
        return bit_state_commit(self.actor, &MERKLE_CHALLENGE_A(round_index), None)
    }

    fn merkle_challenge_b(&mut self, round_index: u8) -> Script {
        return bit_state_commit(self.actor, &MERKLE_CHALLENGE_B(round_index), None)
    }

}
struct VickyPush<'a, T: Actor> {
    vicky: &'a mut T,
}

impl<'a, T> VickyPush<'a, T>
where
    T: Actor,
{
    fn traceChallenge(&mut self, round_index: u8) -> Script {
        return bit_state(self.vicky, &TRACE_CHALLENGE(round_index), None)
    }

    fn merkleChallengeA(&mut self, round_index: u8) -> Script {
        return bit_state(self.vicky, &MERKLE_CHALLENGE_A(round_index), None)
    }

    fn merkleChallengeB(&mut self, round_index: u8) -> Script {
        return bit_state(self.vicky, &MERKLE_CHALLENGE_B(round_index), None)
    }

    // get traceIndex() {
    //     return [
    //         0,
    //         loop(LOG_TRACE_LEN, i => [
    //             OP_SWAP,
    //             this.traceChallenge(i),
    //             OP_IF,
    //                 2 ** (LOG_TRACE_LEN - 1 - i),
    //                 OP_ADD,
    //             OP_ENDIF
    //         ])
    //     ]
    // }

    // get merkleIndexA() {
    //     return [
    //         0,
    //         loop(LOG_PATH_LEN, i => [
    //             OP_SWAP,
    //             this.merkleChallengeA(i),
    //             OP_IF,
    //             	2 ** (LOG_PATH_LEN - 1 - i),
    //             	OP_ADD,
    //             OP_ENDIF
    //         ])
    //     ]
    // }    

    // get merkleIndexB() {
    //     return [
    //         0,
    //         loop(LOG_PATH_LEN, i => [
    //             OP_SWAP,
    //             this.merkleChallengeB(i),
    //             OP_IF,
    //                 2 ** (LOG_PATH_LEN - 1 - i),
    //                 OP_ADD,
    //             OP_ENDIF
    //         ])
    //     ]
    // }

    // nextMerkleIndexA(roundIndex) {
    //     return [
    //         0,
    //         loop(roundIndex, i => [
    //             OP_SWAP,
    //             this.merkleChallengeA(i),
    //             OP_IF,
	//                 2 ** (LOG_PATH_LEN - 1 - i),
	//                 OP_ADD,
    //             OP_ENDIF
    //         ]),
    //         2 ** (LOG_PATH_LEN - 1 - roundIndex),
    //         OP_ADD
    //     ]
    // }    

    // nextMerkleIndexB(roundIndex) {
    //     return [
    //         0,
    //         loop(roundIndex, i => [
    //             OP_SWAP,
    //             this.merkleChallengeB(i),
    //             OP_IF,
    //                 2 ** (LOG_PATH_LEN - 1 - i),
    //                 OP_ADD,
    //             OP_ENDIF
    //         ]),
    //         2 ** (LOG_PATH_LEN - 1 - roundIndex),
    //         OP_ADD
    //     ]
    // }
}

struct VickyUnlock<'a, T: Actor> {
    vicky: &'a mut dyn Vicky<T>,
}

impl<T> VickyUnlock<'_, T>
where
    T: Actor,
{
    fn trace_challenge(&mut self, round_index: u8) -> Script {
        let value = self.vicky.trace_challenge(round_index) as u32;
        bit_state_unlock(self.vicky.get_actor(), &TRACE_CHALLENGE(round_index), None, value)
    }

    fn trace_index(&mut self) -> Script {
        script!{{ unroll(LOG_TRACE_LEN, |i| self.trace_challenge( (LOG_TRACE_LEN - 1 - i) as u8)) }}
    }

    fn nextTraceIndex(&mut self, round_index: u8) -> Script{
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

    // get merkleIndexA() {
    //     return loop(LOG_PATH_LEN, i => self.merkleChallengeA(LOG_PATH_LEN - 1 - i))
    // }

    // get merkleIndexB() {
    //     return loop(LOG_PATH_LEN, i => self.merkleChallengeB(LOG_PATH_LEN - 1 - i))
    // }

    // nextMerkleIndexA(roundIndex) {
    //     return loop(roundIndex, i => self.merkleChallengeA(i)).reverse()
    // }

    // nextMerkleIndexB(roundIndex) {
    //     return loop(roundIndex, i => self.merkleChallengeB(i)).reverse()
    // }
}

struct VickyPlayer {
    player: Player,
    vm: VM,
    // opponent: &'a PaulOpponent,
}

impl Vicky<Player> for VickyPlayer {
    fn trace_index(&self) -> u32 {
        todo!()
    }

    fn next_trace_index(&self, index: u8) -> u32 {
        todo!()
    }

    fn trace_challenge(&self, index: u8) -> bool {
        todo!()
    }

    fn merkle_index_a(&self) -> u32 {
        todo!()
    }

    fn merkle_index_b(&self) -> u32 {
        todo!()
    }

    fn merkle_index_c_prev(&self) -> u32 {
        todo!()
    }

    fn next_merkle_index_a(&self, index: u8) -> u32 {
        todo!()
    }

    fn next_merkle_index_b(&self, index: u8) -> u32 {
        todo!()
    }

    fn next_merkle_index_c_prev(&self, index: u8) -> u32 {
        todo!()
    }

    fn merkle_challenge_a(&self, index: u8) -> bool {
        todo!()
    }

    fn merkle_challenge_b(&self, index: u8) -> bool {
        todo!()
    }

    fn merkle_challenge_c_prev(&self, index: u8) -> bool {
        todo!()
    }

    fn is_faulty_read_a(&self) -> bool {
        todo!()
    }

    fn is_faulty_read_b(&self) -> bool {
        todo!()
    }

    fn is_faulty_write_c(&self) -> bool {
        todo!()
    }

    fn is_faulty_pc_curr(&self) -> bool {
        todo!()
    }

    fn is_faulty_pc_next(&self) -> bool {
        todo!()
    }

    fn commit (&self) -> VickyCommit<Player> {
        todo!()
    }

    fn push (&self) -> VickyPush<Player> {
        todo!()
    }

    fn unlock (&self) -> VickyUnlock<Player> {
        todo!()
    }

    fn get_actor(&mut self) -> &mut Player {
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

impl Vicky<Opponent> for VickyOpponent {
    fn trace_index(&self) -> u32 {
        todo!()
    }

    fn next_trace_index(&self, index: u8) -> u32 {
        todo!()
    }

    fn trace_challenge(&self, index: u8) -> bool {
        todo!()
    }

    fn merkle_index_a(&self) -> u32 {
        todo!()
    }

    fn merkle_index_b(&self) -> u32 {
        todo!()
    }

    fn merkle_index_c_prev(&self) -> u32 {
        todo!()
    }

    fn next_merkle_index_a(&self, index: u8) -> u32 {
        todo!()
    }

    fn next_merkle_index_b(&self, index: u8) -> u32 {
        todo!()
    }

    fn next_merkle_index_c_prev(&self, index: u8) -> u32 {
        todo!()
    }

    fn merkle_challenge_a(&self, index: u8) -> bool {
        todo!()
    }

    fn merkle_challenge_b(&self, index: u8) -> bool {
        todo!()
    }

    fn merkle_challenge_c_prev(&self, index: u8) -> bool {
        todo!()
    }

    fn is_faulty_read_a(&self) -> bool {
        todo!()
    }

    fn is_faulty_read_b(&self) -> bool {
        todo!()
    }

    fn is_faulty_write_c(&self) -> bool {
        todo!()
    }

    fn is_faulty_pc_curr(&self) -> bool {
        todo!()
    }

    fn is_faulty_pc_next(&self) -> bool {
        todo!()
    }

    fn commit (&self) -> VickyCommit<Opponent> {
        todo!()
    }

    fn push (&self) -> VickyPush<Opponent> {
        todo!()
    }

    fn unlock (&self) -> VickyUnlock<Opponent> {
        todo!()
    }

    fn get_actor(&mut self) -> &mut Opponent {
        &mut self.opponent
    }
}
