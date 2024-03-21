use bitcoin::Transaction;
use bitcoin::{taproot::TaprootSpendInfo, ScriptBuf as Script, Witness};

use super::opcodes::{execute_script, pushable};
use bitcoin_script::bitcoin_script as script;

pub type Leaves = Vec<Box<dyn Leaf>>;

pub trait Leaf {
    fn unlockable(&self) -> bool {
        todo!("Implement me");
    }

    fn executable(&mut self) -> bool {
        let result = execute_script(script! {
            { self.unlock() }
            { self.lock() }
        });
        result.final_stack.len() == 1 && result.final_stack[0] == [1]
    }

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
