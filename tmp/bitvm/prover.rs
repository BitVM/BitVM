#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

use super::verifier::{ProxyVerifierVM, Verifier, V32};
use super::vm::VM;
use super::constants::LOG_PATH_LEN;

use crate::scripts::actor::{as_ptr, ptr, ID};
use crate::utils::u160::u160;

use crate::scripts::actor::{Actor, Opponent, Player};

use bitcoin::ScriptBuf as Script;

// TODO: Implement `export` with Serde

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// 
/// Actor
/// 
pub trait Prover<T: Actor> {

    fn u8(&mut self, u8_id: P8) -> u8;

    fn u32(&mut self, u32_id: P32) -> u32;
    
    fn u160(&mut self, u160_id: P160) -> u160;

    fn get_actor(&mut self) -> &mut T;

}

#[derive(Copy, Clone)]
pub enum P8 {
    INSTRUCTION_TYPE
}

#[derive(Copy, Clone)]
pub enum P32 {
    ADDRESS_A, ADDRESS_B, ADDRESS_C,
    VALUE_A, VALUE_B, VALUE_C,
    PC_CURR, PC_NEXT, TRACE_RESPONSE_PC(u8)
}

#[derive(Copy, Clone)]
pub enum P160 {
    TRACE_RESPONSE(u8),
    MERKLE_RESPONSE_A(u8),
    MERKLE_RESPONSE_B(u8),
    MERKLE_RESPONSE_C_PREV(u8),
    MERKLE_RESPONSE_C_NEXT(u8),
    MERKLE_RESPONSE_A_SIBLING(u8),
    MERKLE_RESPONSE_B_SIBLING(u8),
    MERKLE_RESPONSE_C_NEXT_SIBLING(u8)
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// 
/// BitVM
/// 
pub struct ProverVM { prover: Player, verifier: ProxyVerifierVM, vm: VM }

impl Prover::<Player> for ProverVM {

    fn u8(&mut self, id: P8) -> u8 {
        match id {
            P8::INSTRUCTION_TYPE => self.vm.run(self.verifier.u32(V32::TRACE_INDEX(0)) + 1).instruction.0,
        }
    }

    fn u32(&mut self, id: P32) -> u32 {
        match id {
            P32::ADDRESS_A => self.vm.run(self.verifier.u32(V32::TRACE_INDEX(0))).instruction.1,
            P32::ADDRESS_B => self.vm.run(self.verifier.u32(V32::TRACE_INDEX(0))).instruction.2,
            P32::ADDRESS_C => self.vm.run(self.verifier.u32(V32::TRACE_INDEX(0))).instruction.3,
            // Read the value_a of the previous state
            // (The value at address_a in the snapshot at trace_index + 1 may already be overwritten)
            P32::VALUE_A => self.vm.run(self.verifier.u32(V32::TRACE_INDEX(0))) [self.u32(P32::ADDRESS_A)],
            // Read the value_b of the previous state
            // (The value at address_b in the snapshot at trace_index + 1 may already be overwritten)
            P32::VALUE_B => self.vm.run(self.verifier.u32(V32::TRACE_INDEX(0))) [self.u32(P32::ADDRESS_B)],
            P32::VALUE_C => self.vm.run(self.verifier.u32(V32::TRACE_INDEX(0))) [self.u32(P32::ADDRESS_C)],
            // Get the program counter of the previous instruction
            P32::PC_CURR => self.vm.run(self.verifier.u32(V32::TRACE_INDEX(0)) - 1).pc,
            P32::PC_NEXT => self.vm.run(self.verifier.u32(V32::TRACE_INDEX(0))).pc,
            P32::TRACE_RESPONSE_PC(n) => self.vm.run(self.verifier.u32(V32::NEXT_TRACE_INDEX(n))).pc,
        }
    }

    fn u160(&mut self, u160_id: P160) -> u160 {
        match u160_id {
            P160::TRACE_RESPONSE(n) => self.vm
                .run(self.verifier.u32(V32::NEXT_TRACE_INDEX(n)))
                .root(),

            // TODO: we have to return a hash here, not a node of the path. MerklePathVerify up to n
            P160::MERKLE_RESPONSE_A(n) => self.vm
                .run(self.verifier.u32(V32::TRACE_INDEX(0)))
                .path(self.u32(P32::ADDRESS_A))
                .verify_up_to(self.verifier.u32(V32::NEXT_MERKLE_INDEX_A(n)) as u8),
            
            P160::MERKLE_RESPONSE_A_SIBLING(n) => self.vm
                .run(self.verifier.u32(V32::TRACE_INDEX(0)))
                .path(self.u32(P32::ADDRESS_A))
                .get_node(match n < LOG_PATH_LEN as u8 {
                    true => self.verifier.u32(V32::NEXT_MERKLE_INDEX_A(n)) as u8 - 1,
                    false => self.verifier.u32(V32::MERKLE_INDEX_A) as u8
                }),
            // TODO: we have to return a hash here, not a node of the path. MerklePathVerify up to n
            P160::MERKLE_RESPONSE_B(n) => self.vm
                .run(self.verifier.u32(V32::TRACE_INDEX(0)))
                .path(self.u32(P32::ADDRESS_B))
                .verify_up_to(self.verifier.u32(V32::NEXT_MERKLE_INDEX_B(n)) as u8),

            P160::MERKLE_RESPONSE_B_SIBLING(n) => self.vm.run(self.verifier.u32(V32::TRACE_INDEX(0)))
                .path(self.u32(P32::ADDRESS_B))
                .get_node(match n < LOG_PATH_LEN as u8 {
                    true => self.verifier.u32(V32::NEXT_MERKLE_INDEX_B(n)) as u8 - 1,
                    false => self.verifier.u32(V32::MERKLE_INDEX_B) as u8
                }),
            P160::MERKLE_RESPONSE_C_PREV(n) => self.vm
                .run(self.verifier.u32(V32::TRACE_INDEX(0)))
                .path(self.u32(P32::ADDRESS_C))
                .verify_up_to(self.verifier.u32(V32::NEXT_MERKLE_INDEX_C_PREV(n)) as u8),

            P160::MERKLE_RESPONSE_C_NEXT(merkle_index_c) => self.vm
                .run(self.verifier.u32(V32::TRACE_INDEX(0)) + 1)
                .path(self.u32(P32::ADDRESS_C))
                .verify_up_to(merkle_index_c),

            P160::MERKLE_RESPONSE_C_NEXT_SIBLING(merkle_index_c) => self.vm.run(self.verifier.u32(V32::TRACE_INDEX(0)) + 1)
                .path(self.u32(P32::ADDRESS_C))
                .get_node(merkle_index_c),
        }
    }

    fn get_actor(&mut self) -> &mut Player {
        &mut self.prover
    }

}

impl ProverVM {

    /* commit wrapper */

    pub fn commit(&mut self, id: P8) -> Script { self.get_actor().commit(&ptr::from(id)) }

    pub fn u32_commit(&mut self, u32_id: P32) -> Script { self.get_actor().commit(&ptr::from(id)) }

    pub fn u160_commit(&mut self, u160_id: P160) -> Script { self.get_actor().commit(&ptr::from(id)) }

    /* push wrapper */

    pub fn u8_push(&mut self, id: P8) -> Script { self.get_actor().push(&ptr::from(id)) }

    pub fn u32_push(&mut self, id: P32) -> Script { self.get_actor().push(&ptr::from(id)) }

    pub fn u160_push(&mut self, id: P160) -> Script { self.get_actor().push(&ptr::from(id)) }

    /* unlock wrapper */

    pub fn u8_unlock(&mut self, u8_id: P8) -> Script { let u8 = self.u8(u8_id); self.get_actor().unlock(&ptr::from(id)) }

    pub fn u32_unlock(&mut self, u32_id: P32) -> Script { let u32 = self.u32(u32_id); self.get_actor().unlock(&ptr::from(id)) }

    pub fn u160_unlock(&mut self, u160_id: P160) -> Script { let u160 = self.u160(u160_id); self.get_actor().unlock(&ptr::from(id)) }

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// 
/// Proxy BitVM

pub struct ProxyProverVM(pub Opponent);

impl Prover<Opponent> for ProxyProverVM {

    fn u8(&mut self, u8_id: P8) -> u8 { self.0.get_u8(id.addr()) }

    fn u32(&mut self, u32_id: P32) -> u32 { self.0.get_u32(id.addr()) }

    fn u160(&mut self, u160_id: P160) -> u160 { self.0.get_u160(id.addr()) }

    fn get_actor(&mut self) -> &mut Opponent { &mut self.0 }

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// 
/// enum as ptr

impl as_ptr::<P8> for P8 {
    fn addr(id: P8) -> ptr {
        match id {
            // Paul's instruction commitment
            P8::INSTRUCTION_TYPE => ptr::u8(12)
        }
    }
}

impl as_ptr::<P32> for P32 {
    fn addr(id: P32) -> ptr {
        match id {
            P32::ADDRESS_A => ptr::u32(13),
            P32::ADDRESS_B => ptr::u32(14),
            P32::ADDRESS_C => ptr::u32(15),
            P32::VALUE_A => ptr::u32(16),
            P32::VALUE_B => ptr::u32(17),
            P32::VALUE_C => ptr::u32(18),
            P32::PC_CURR => ptr::u32(19),
            P32::PC_NEXT => ptr::u32(20),
            P32::TRACE_RESPONSE_PC(_) => ptr::u32(9),
        }
    }
}

impl as_ptr::<P160> for P160 {
    fn addr(id: P160) -> ptr {
        match id {
            // Paul's trace responses
            P160::TRACE_RESPONSE(_) => ptr::u160(22),
            // Paul's Merkle responses for the operand A
            P160::MERKLE_RESPONSE_A(_) => ptr::u160(24),
            // Paul's Merkle responses for the operand B
            P160::MERKLE_RESPONSE_B(_) => ptr::u160(26),
            // Paul's Merkle responses for the result C
            P160::MERKLE_RESPONSE_C_PREV(_) => ptr::u160(28),
            P160::MERKLE_RESPONSE_C_NEXT(_) => ptr::u160(30),
            P160::MERKLE_RESPONSE_A_SIBLING(_) => ptr::u160(32),
            // Undefined 160-bit variables
            P160::MERKLE_RESPONSE_C_NEXT_SIBLING(_) => unimplemented!(),
            P160::MERKLE_RESPONSE_B_SIBLING(_) => unimplemented!(),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////
//
#[cfg(test)]
mod tests {

    use crate::bitvm::{
        constants::ASM_ADD,
        vm::{Instruction, VM},
        verifier::ProxyVerifierVM,
        prover::{Prover, ProverVM, P160, P32, P8},
    };
    use crate::utils::u160::u160;
    use crate::scripts::{
        opcodes::{pushable, execute_script},
        actor::{Opponent, Player},
    };
    use bitcoin_script::bitcoin_script as script;

    #[test]
    fn test_push_and_unlock() {
        let address_a = 0;
        let value_a = 0xFFFFFFFB;
        let address_b = 1;
        let value_b = 7;
        let address_c = 2;
        let program: [Instruction; 1] = [(ASM_ADD, address_a, address_b, address_c)];
        let data: [u32; 2] = [value_a, value_b];

        let mut paul = ProverVM {
            prover: Player::new("d898098e09898a0980989b980809809809f09809884324874302975287524398"),
            vm: VM::new(program, data),
            verifier: ProxyVerifierVM {0: Opponent::new()},
        };

        // let script = script! {
        //     { paul.u32_state_unlock(P32::VALUE_A) }
        //     { paul.u32_state_commit(P32::VALUE_A) }
        //     1
        // };

        // Works without opponent:
        //
        let script = script! {
            { paul.u160_unlock(P160::TRACE_RESPONSE(0)) }
            { paul.u160_commit(P160::TRACE_RESPONSE(0)) }
            1
        };

        let result = execute_script(script.into());
        // println!("{:?}", result.final_stack);
        assert!(result.success)
    }

    // TODO: Test `push`, `commit`, `unlock` for Paul and Vicky using dummy Players with constant values

    type DummyPlayer = Player;
    type DummyOpponent = Opponent;
    struct DummyActor { prover: DummyPlayer, _verifier: DummyOpponent }

    impl Prover::<Player> for DummyActor {   
        fn u8(&mut self, id: P8) -> u8 { match id { _ => 0 } } 
        fn u32(&mut self, id: P32) -> u32 { match id { P32::VALUE_A => 42, _ => 0 } }
        fn u160(&mut self, id: P160) -> u160 { match id { _ => [0, 0, 0, 0, 0] } }
        fn get_actor(&mut self) -> &mut Player { &mut self.prover }
    }

    #[test]
    fn test_dummy_paul_and_vicky() {
        let mut _paul = DummyActor {
            prover: DummyPlayer::new("d898098e09898a0980989b980809809809f09809884324874302975287524398"),
            _verifier: DummyOpponent::new()
        };
    }
}