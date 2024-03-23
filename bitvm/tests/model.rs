mod common;

use crate::common::vicky_pubkey;
use bitcoin_script::bitcoin_script as script;
use bitvm::constants::ASM_ADD;
use bitvm::model::{Paul, PaulCommit, PaulPlayer, PaulPush, PaulUnlock};
use bitvm::vm::Instruction;
use tapscripts::actor::{Actor, HashDigest, Player};
use tapscripts::opcodes::execute_script;
use tapscripts::opcodes::pushable;

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

    let paul = PaulPlayer::new(
        "d898098e09898a0980989b980809809809f09809884324874302975287524398",
        &program,
        &data,
        "d898098e09898a0980989b980809809809f09809884324874302975287524398",
    );

    let script = script! {
        { paul.unlock().trace_response(0) }
        { paul.commit().trace_response(0) }
        1
    };

    let result = execute_script(script.into());
    // println!("{:?}", result.final_stack);
    assert!(result.success);
}

#[test]
fn test_pc_curr() {
    struct DummyPaul {
        paul: Player,
    }

    #[rustfmt::skip]
    impl Paul for DummyPaul {
        fn instruction_type(&self) -> u8 { ASM_ADD }
        fn address_a(&self) -> u32 { 2 }
        fn address_b(&self) -> u32 { 3 }
        fn address_c(&self) -> u32 { 4 }
        fn value_a(&self) -> u32 { 42 }
        fn value_b(&self) -> u32 { 43 }
        fn value_c(&self) -> u32 { 85 }
        fn pc_curr(&self) -> u32 { 1 }
        fn pc_next(&self) -> u32 { 2 }
        fn trace_response(&self, _: u8) -> HashDigest { [0u8; 20] }
        fn trace_response_pc(&self, _: u8) -> u32 { 0 }
        fn merkle_response_a(&self, _: u8) -> HashDigest { [0u8; 20] }
        fn merkle_response_a_sibling(&self, _: u8) -> HashDigest { [0u8; 20] }
        fn merkle_response_b(&self, _: u8) -> HashDigest { [0u8; 20] }
        fn merkle_response_b_sibling(&self, _: u8) -> HashDigest { [0u8; 20] }
        fn merkle_response_c_prev(&self, _: u8) -> HashDigest { [0u8; 20] }
        fn merkle_response_c_prev_sibling(&self, _: u8) -> HashDigest { [0u8; 20] }
        fn merkle_response_c_next(&self, _: u8) -> HashDigest { [0u8; 20] }
        fn merkle_response_c_next_sibling(&self, _: u8) -> HashDigest { [0u8; 20] }

        fn commit(&self) -> PaulCommit { PaulCommit { actor: &self.paul } }
        fn push(&self) -> PaulPush { PaulPush { paul: self } }
        fn unlock(&self) -> PaulUnlock { PaulUnlock { paul: self } }
        fn get_actor(&self) -> &dyn Actor { &self.paul }
        
    }

    let dummy_paul = DummyPaul {
        paul: Player::new("d898098e09898a0980989b980809809809f09809884324874302975287524398"),
    };

    let exec_result = execute_script(script! {
        { dummy_paul.unlock().pc_curr() }
        { dummy_paul.push().pc_curr() }
        1 OP_EQUALVERIFY
        0 OP_EQUALVERIFY
        0 OP_EQUALVERIFY
        0 OP_EQUAL
    });

    assert!(exec_result.success)
}
