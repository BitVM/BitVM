use crate::scripts::{opcodes::pushable, transaction::Leaf, transaction::LeafGetters};
use bitcoin_script::bitcoin_script as script;
use bitcoin::blockdata::script::ScriptBuf as Script;
use bitvm_macros::LeafGetters;

use super::model::{Paul, Vicky};

#[derive(LeafGetters)]
pub struct KickOffLeaf<'a> {
    paul: &'a mut dyn Paul,
    vicky: &'a mut dyn Vicky,
}

#[derive(LeafGetters)]
pub struct CommitInstructionAddLeaf<'a> {
    paul: &'a mut dyn Paul,
    vicky: &'a mut dyn Vicky,
}

impl Leaf for KickOffLeaf<'_> {
    fn unlock(&mut self) -> Script {
        todo!("Implement me")
    }

    fn lock(&mut self) -> Script {
        todo!("Implement me")
    }
}

impl Leaf for CommitInstructionAddLeaf<'_> {
    fn unlock(&mut self) -> Script {
        todo!("Implement me")
    }

    fn lock(&mut self) -> Script {
        script! {
            { self.paul.push().instruction_type() }
        }
    }
}

