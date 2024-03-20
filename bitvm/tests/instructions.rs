mod common;

#[cfg(test)]
mod instructions_tests {
    use bitvm::instructions::CommitInstructionAddLeaf;
    use std::str::FromStr;
    
    use bitcoin::key::{Keypair, Secp256k1};
    use bitcoin::secp256k1::PublicKey;
    use bitvm::constants::ASM_ADD;
    use bitvm::model::{Paul, PaulCommit, PaulPush, PaulUnlock, Vicky, VickyCommit, VickyPush, VickyUnlock};
    use scripts::actor::{Actor, HashDigest, Opponent, Player};
    use scripts::leaf::Leaf;
    use crate::common::vicky_pubkey;
    
    struct DummyVicky { vicky: Opponent }
    
    impl Vicky for DummyVicky {
        fn trace_index(&mut self) -> u32 { 0 }
        fn next_trace_index(&mut self, _: u8) -> u32 { 0 }
        fn trace_challenge(&mut self, _: u8) -> bool { false }
        fn merkle_index_a(&mut self) -> u32 { 0 }
        fn merkle_index_b(&mut self) -> u32 { 0 }
        fn merkle_index_c_prev(&mut self) -> u32 { 0 }
        fn next_merkle_index_a(&mut self, _: u8) -> u32 { 0 }
        fn next_merkle_index_b(&mut self, _: u8) -> u32 { 0 }
        fn next_merkle_index_c_prev(&mut self, _: u8) -> u32 { 0 }
        fn merkle_challenge_a(&mut self, _: u8) -> bool { false }
        fn merkle_challenge_b(&mut self, _: u8) -> bool { false }
        fn merkle_challenge_c_prev(&mut self, _: u8) -> bool { false }
        fn is_faulty_read_a(&mut self) -> bool { false }
        fn is_faulty_read_b(&mut self) -> bool { false }
        fn is_faulty_write_c(&mut self) -> bool { false }
        fn is_faulty_pc_curr(&mut self) -> bool { false }
        fn is_faulty_pc_next(&mut self) -> bool { false }
        fn commit (&mut self) -> VickyCommit { VickyCommit { actor: &mut self.vicky } }
        fn push (&mut self) -> VickyPush { VickyPush { vicky: &mut self.vicky } }
        fn unlock (&mut self) -> VickyUnlock { VickyUnlock { vicky: self } }
        fn get_actor(&mut self) -> &mut dyn Actor { &mut self.vicky }
    }
    
    // cargo test --package bitvm_rust --bin bitvm_rust -- scripts::transaction::tests::test_asm_add_script --exact --nocapture
    
    #[test]
    fn test_asm_add_script()
    {
        struct DummyPaulAdd { paul: Player }
    
        impl Paul for DummyPaulAdd {
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
            fn merkle_response_c_next(&mut self, _: u8) -> HashDigest { [0u8; 20] }
            fn merkle_response_c_next_sibling(&mut self, _: u8) -> HashDigest { [0u8; 20] }
            fn commit(&mut self) -> PaulCommit { PaulCommit { actor: &mut self.paul } }
            fn push(&mut self) -> PaulPush { PaulPush { paul: self } }
            fn unlock(&mut self) -> PaulUnlock { PaulUnlock { paul: self } }
            fn get_actor(&mut self) -> &mut dyn Actor { &mut self.paul }
    
            fn merkle_response_c_prev_sibling(&mut self, index: u8) -> HashDigest {
                [0u8; 20]
            }
        }
    
        let mut dummy_leaf = CommitInstructionAddLeaf {
            paul: &mut DummyPaulAdd { paul: Player::new("d898098e09898a0980989b980809809809f09809884324874302975287524398") },
            vicky: &mut DummyVicky { vicky: Opponent::new(vicky_pubkey()) }
        };
        
        assert!(dummy_leaf.executable());
    }
}
