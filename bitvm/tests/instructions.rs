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
        fn trace_index(&self) -> u32 { 0 }
        fn next_trace_index(&self, _: u8) -> u32 { 0 }
        fn trace_challenge(&self, _: u8) -> bool { false }
        fn merkle_index_a(&self) -> u32 { 0 }
        fn merkle_index_b(&self) -> u32 { 0 }
        fn merkle_index_c_prev(&self) -> u32 { 0 }
        fn next_merkle_index_a(&self, _: u8) -> u32 { 0 }
        fn next_merkle_index_b(&self, _: u8) -> u32 { 0 }
        fn next_merkle_index_c_prev(&self, _: u8) -> u32 { 0 }
        fn merkle_challenge_a(&self, _: u8) -> bool { false }
        fn merkle_challenge_b(&self, _: u8) -> bool { false }
        fn merkle_challenge_c_prev(&self, _: u8) -> bool { false }
        fn is_faulty_read_a(&self) -> bool { false }
        fn is_faulty_read_b(&self) -> bool { false }
        fn is_faulty_write_c(&self) -> bool { false }
        fn is_faulty_pc_curr(&self) -> bool { false }
        fn is_faulty_pc_next(&self) -> bool { false }
        fn commit (&self) -> VickyCommit { VickyCommit { actor: &self.vicky } }
        fn push (&self) -> VickyPush { VickyPush { vicky: &self.vicky } }
        fn unlock (&self) -> VickyUnlock { VickyUnlock { vicky: self } }
        fn get_actor(&self) -> &dyn Actor { &self.vicky }
    }
    
    // cargo test --package bitvm_rust --bin bitvm_rust -- scripts::transaction::tests::test_asm_add_script --exact --nocapture
    
    #[test]
    fn test_asm_add_script()
    {
        struct DummyPaulAdd { paul: Player }
    
        impl Paul for DummyPaulAdd {
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
            fn merkle_response_c_next(&self, _: u8) -> HashDigest { [0u8; 20] }
            fn merkle_response_c_next_sibling(&self, _: u8) -> HashDigest { [0u8; 20] }
            fn commit(&self) -> PaulCommit { PaulCommit { actor: &self.paul } }
            fn push(&self) -> PaulPush { PaulPush { paul: self } }
            fn unlock(&self) -> PaulUnlock { PaulUnlock { paul: self } }
            fn get_actor(&self) -> &dyn Actor { &self.paul }
    
            fn merkle_response_c_prev_sibling(&self, index: u8) -> HashDigest {
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
