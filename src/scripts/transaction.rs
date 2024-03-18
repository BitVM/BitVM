use bitcoin::{blockdata::transaction::Transaction, taproot::TaprootSpendInfo, ScriptBuf as Script, Witness};
use super::opcodes::{pushable, execute_script};
use bitcoin_script::bitcoin_script as script;

pub trait LeafGetters {
    fn get_taproot_spend_info(&self) -> TaprootSpendInfo {
        todo!("Implement me (potentially with a derive macro instead)")
    }

    fn get_transaction(&self) -> Transaction {
        todo!("Implement me (potentially with a derive macro instead)")
    }
}

// TODO: We can use a derive proc_macro to derive all the getters on our struct (e.g. self.timeout
// and self.transaction)
pub trait Leaf: LeafGetters {
    //
    //  Default Leaf behaviour
    //
    fn execute(&mut self) -> Transaction {
        let mut transaction = self.get_transaction();
        let target = self.lock();
        let unlock_script = self.unlock();

        // TODO: Get the TaprootSpendInfo to generate the control block
        transaction.input[0].witness =
            Witness::from_slice(&vec![unlock_script.as_bytes(), target.as_bytes()]);
        transaction
    }

    fn executable(&mut self) -> bool {
        let result = execute_script(script! {
            { self.unlock() }
            { self.lock() }
        });
        result.final_stack.len() == 1 && result.final_stack[0] == [1]
    }

    fn unlockable(&self) -> bool {
        todo!("Implement me");
    }

    // TODO: Might make sense to store the TaprootSpendInfo with the Transaction instead
    //fn get_taproot_spend_info(&self) -> TaprootSpendInfo;
    //fn get_transaction(&self) -> Transaction;

    //
    //  To be implemented by structs
    //
    fn lock(&mut self) -> Script;
    fn unlock(&mut self) -> Script;
}

pub trait TimeoutLeaf: Leaf {
    fn unlockable(&self, utxo_age: u32) -> bool {
        if utxo_age < self.get_timeout() {
            false
        } else {
            <Self as Leaf>::unlockable(&self)
        }
    }

    fn get_timeout(&self) -> u32;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
//
#[cfg(test)]
mod tests {
    use crate::bitvm::bitvm::CommitInstructionAddLeaf;
    use crate::bitvm::constants::ASM_ADD;
    use crate::bitvm::model::{Paul, PaulCommit, PaulPush, PaulUnlock, Vicky, VickyCommit, VickyPush, VickyUnlock};
    use crate::scripts::actor::{Actor, HashDigest, Opponent, Player};
    use crate::scripts::transaction::Leaf;

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
            fn pc_curr(&mut self) -> u32 { 0 }
            fn pc_next(&mut self) -> u32 { 0 }
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
            fn push(&mut self) -> PaulPush { PaulPush { paul: &mut self.paul } }
            fn unlock(&mut self) -> PaulUnlock { PaulUnlock { paul: self } }
            fn get_actor(&mut self) -> &mut dyn Actor { &mut self.paul }   
        }

        let mut dummy_leaf = CommitInstructionAddLeaf {
            paul: &mut DummyPaulAdd { paul: Player::new("d898098e09898a0980989b980809809809f09809884324874302975287524398") },
            vicky: &mut DummyVicky { vicky: Opponent::new() }
        };
        
        assert!(dummy_leaf.executable());
    }
    
}