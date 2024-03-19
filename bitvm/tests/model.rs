mod tests {

    use bitcoin_script::bitcoin_script as script;
    use scripts::actor::{Player, HashDigest, Actor};
    use scripts::opcodes::execute_script;
    use bitvm::constants::ASM_ADD;
    use bitvm::vm::Instruction;
    use bitvm::model::{Paul, PaulPlayer, PaulCommit, PaulPush, PaulUnlock};
    use scripts::opcodes::pushable;


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
    fn test_pc_curr(){

        struct DummyPaul { paul: Player }
        impl Paul for DummyPaul {
            fn instruction_type(&mut self) -> u8 { ASM_ADD }
            fn address_a(&mut self) -> u32 { 2 }
            fn address_b(&mut self) -> u32 { 3 }
            fn address_c(&mut self) -> u32 { 4 }
            fn value_a(&mut self) -> u32 { 42 }
            fn value_b(&mut self) -> u32 { 43 }
            fn value_c(&mut self) -> u32 { 85 }
            fn pc_curr(&mut self) -> u32 { 1 }
            fn pc_next(&mut self) -> u32 { 2 }
            fn trace_response(&mut self, _: u8) -> HashDigest { [0u8; 20] }
            fn trace_response_pc(&mut self, _: u8) -> u32 { 0 }
            fn merkle_response_a(&mut self, _: u8) -> HashDigest { [0u8; 20] }
            fn merkle_response_a_sibling(&mut self, _: u8) -> HashDigest { [0u8; 20] }
            fn merkle_response_b(&mut self, _: u8) -> HashDigest { [0u8; 20] }
            fn merkle_response_b_sibling(&mut self, _: u8) -> HashDigest { [0u8; 20] }
            fn merkle_response_c_prev(&mut self, _: u8) -> HashDigest { [0u8; 20] }
            fn merkle_response_c_prev_sibling(&mut self, _: u8) -> HashDigest { [0u8; 20] }
            fn merkle_response_c_next(&mut self, _: u8) -> HashDigest { [0u8; 20] }
            fn merkle_response_c_next_sibling(&mut self, _: u8) -> HashDigest { [0u8; 20] }
            fn commit(&mut self) -> PaulCommit { PaulCommit { actor: &mut self.paul } }
            fn push(&mut self) -> PaulPush { PaulPush { paul: self } }
            fn unlock(&mut self) -> PaulUnlock { PaulUnlock { paul: self } }
            fn get_actor(&mut self) -> &mut dyn Actor { &mut self.paul }
        }
        
        let mut dummy_paul = DummyPaul { paul: Player::new("d898098e09898a0980989b980809809809f09809884324874302975287524398") };

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
}

    

