use super::constants::{ASM_ADD, ASM_ADDI};
use crate::scripts::opcodes::u32_add::u32_add_drop;
use crate::scripts::opcodes::u32_std::{
    u32_equalverify, u32_fromaltstack, u32_push, u32_toaltstack,
};
use crate::scripts::{opcodes::pushable, transaction::Leaf, transaction::LeafGetters};
use bitcoin::blockdata::script::ScriptBuf as Script;
use bitcoin_script::bitcoin_script as script;
use bitvm_macros::LeafGetters;

use super::model::{Paul, Vicky};

#[derive(LeafGetters)]
pub struct KickOffLeaf<'a> {
    paul: &'a mut dyn Paul,
    vicky: &'a mut dyn Vicky,
}

impl Leaf for KickOffLeaf<'_> {
    fn lock(&mut self) -> Script {
        todo!("Implement me")
    }

    fn unlock(&mut self) -> Script {
        todo!("Implement me")
    }
}

#[derive(LeafGetters)]
pub struct CommitInstructionAddLeaf<'a> {
    paul: &'a mut dyn Paul,
    vicky: &'a mut dyn Vicky,
}

impl Leaf for CommitInstructionAddLeaf<'_> {
    fn lock(&mut self) -> Script {
        script! {
            {self.paul.push().instruction_type()}
            {ASM_ADD as u32}
            OP_EQUALVERIFY

            {self.paul.push().pc_curr()}
            u32_toaltstack
            {self.paul.push().pc_next()}
            u32_fromaltstack
            {u32_push(1)}
            {u32_add_drop(0, 1)}
            u32_equalverify

            {self.paul.push().value_c()}
            u32_toaltstack
            {self.paul.push().value_b()}
            u32_toaltstack
            {self.paul.push().value_a()}
            u32_fromaltstack
            {u32_add_drop(0, 1)}
            u32_fromaltstack
            u32_equalverify


            {self.paul.commit().address_a()}
            {self.paul.commit().address_b()}
            {self.paul.commit().address_c()}

            1 // OP_TRUE
        }
    }

    fn unlock(&mut self) -> Script {
        script! {
            { self.paul.unlock().address_c() }
            { self.paul.unlock().address_b() }
            { self.paul.unlock().address_a() }
            { self.paul.unlock().value_a() }
            { self.paul.unlock().value_b() }
            { self.paul.unlock().value_c() }
            { self.paul.unlock().pc_next() }
            { self.paul.unlock().pc_curr() }
            { self.paul.unlock().instruction_type() }
        }
    }
}

#[derive(LeafGetters)]
pub struct CommitInstructionAddImmediateLeaf<'a> {
    paul: &'a mut dyn Paul,
    vicky: &'a mut dyn Vicky,
}

// Different to the CommitInstructionAddLeaf
// The second summand is address_b instead of valueB
impl Leaf for CommitInstructionAddImmediateLeaf<'_> {
    fn lock(&mut self) -> Script {
        script! {
            {self.paul.push().instruction_type()}
            {ASM_ADDI as u32}
            OP_EQUALVERIFY

            {self.paul.push().pc_curr()}
            u32_toaltstack
            {self.paul.push().pc_next()}
            u32_fromaltstack
            {u32_push(1)}
            {u32_add_drop(0, 1)}
            u32_equalverify

            {self.paul.push().value_c()}
            u32_toaltstack

            {self.paul.push().address_b()}
            u32_toaltstack
            {self.paul.push().value_a()}
            u32_fromaltstack
            {u32_add_drop(0, 1)}
            u32_fromaltstack
            u32_equalverify


            {self.paul.commit().address_a()}
            {self.paul.commit().address_c()}

            1 // OP_TRUE // TODO: verify covenant here
        }
    }

    fn unlock(&mut self) -> Script {
        script! {
            { self.paul.unlock().address_c() }
            { self.paul.unlock().address_a() }
            { self.paul.unlock().value_a() }
            { self.paul.unlock().address_b() }
            { self.paul.unlock().value_c() }
            { self.paul.unlock().pc_next() }
            { self.paul.unlock().pc_curr() }
            { self.paul.unlock().instruction_type() }
        }
    }
}
