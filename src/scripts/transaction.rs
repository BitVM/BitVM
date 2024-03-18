use bitcoin::{
    blockdata::transaction::Transaction, taproot::TaprootSpendInfo, ScriptBuf as Script, Witness,
};
use bitcoin_scriptexec::ExecutionResult;

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

    fn executable(&self) -> bool {
        let result = self.run_script();
        result.final_stack.len() == 1 && result.final_stack[0] == [1]
    }

    fn unlockable(&self) -> bool {
        todo!("Implement me");
    }

    fn run_script(&self) -> ExecutionResult {
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
