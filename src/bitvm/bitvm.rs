use crate::scripts::{opcodes::pushable, transaction::Leaf, transaction::LeafGetters};
use bitcoin_script::bitcoin_script as script;
use bitcoin::blockdata::script::ScriptBuf as Script;
use bitvm_macros::LeafGetters;
use bitcoin::opcodes::{OP_TRUE};
use crate::scripts::opcodes::u32_std::*;
use crate::scripts::opcodes::pseudo::*;
use crate::scripts::opcodes::u32_add::{u32_add_drop, u32_add};
use crate::scripts::opcodes::u32_sub::u32_sub_drop;
use crate::scripts::opcodes::u32_cmp::*;
use crate::scripts::opcodes::u32_xor::{u8_push_xor_table, u8_drop_xor_table, u32_xor};
use crate::scripts::opcodes::u32_and::u32_and;
use crate::scripts::opcodes::u32_or::u32_or;
use super::constants::*;

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
    pub paul: &'a mut dyn Paul,
    pub vicky: &'a mut dyn Vicky,
}

impl Leaf for CommitInstructionAddLeaf<'_> {
    fn lock(&mut self) -> Script {
        script!{
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

            1 // {OP_TRUE}
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
// The second summand is address_b instead of value_b
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
            
            1 // {OP_TRUE} // TODO: verify covenant here
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



#[derive(LeafGetters)]
pub struct CommitInstructionSubLeaf<'a> {
    paul: &'a mut dyn Paul,
    vicky: &'a mut dyn Vicky,
}


impl Leaf for CommitInstructionSubLeaf<'_> {

    fn lock(&mut self) -> Script{
        script! {
            {self.paul.push().instruction_type()}
            {ASM_SUB as u32}
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

            {self.paul.push().value_a()}
            u32_toaltstack
            {self.paul.push().value_b()}
            u32_fromaltstack
            {u32_sub_drop(0, 1)}
            u32_fromaltstack
            u32_equalverify


            {self.paul.commit().address_a()}
            {self.paul.commit().address_b()}
            {self.paul.commit().address_c()}

            {OP_TRUE} // TODO: verify covenant here
        }
    }

    fn unlock(&mut self) -> Script{
        script! {
            { self.paul.unlock().address_c() }
            { self.paul.unlock().address_b() }
            { self.paul.unlock().address_a() }
            { self.paul.unlock().value_b() }
            { self.paul.unlock().value_a() }
            { self.paul.unlock().value_c() }
            { self.paul.unlock().pc_next() }
            { self.paul.unlock().pc_curr() }
            { self.paul.unlock().instruction_type() }
        }
    }
}


#[derive(LeafGetters)]
pub struct CommitInstructionSubImmediateLeaf<'a> {
    paul: &'a mut dyn Paul,
    vicky: &'a mut dyn Vicky,
}

impl Leaf for CommitInstructionSubImmediateLeaf<'_> {

    fn lock(&mut self) -> Script {
        script!{
            {self.paul.push().instruction_type()}
            {ASM_SUBI as u32}
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

            {self.paul.push().value_a()}
            u32_toaltstack
            {self.paul.push().address_b()}
            u32_fromaltstack
            {u32_sub_drop(0, 1)}
            u32_fromaltstack
            u32_equalverify


            { self.paul.commit().address_a() } 
            { self.paul.commit().address_c() } 

            {OP_TRUE} // TODO: verify covenant here
        }
    }

    fn unlock(&mut self) -> Script {
        script!{
            { self.paul.unlock().address_c() }
            { self.paul.unlock().address_a() }
            { self.paul.unlock().address_b() }
            { self.paul.unlock().value_a() }
            { self.paul.unlock().value_c() }
            { self.paul.unlock().pc_next() }
            { self.paul.unlock().pc_curr() }
            { self.paul.unlock().instruction_type() }
        }
    }
}

#[derive(LeafGetters)]
pub struct CommitInstructionLoadLeaf<'a> {
    paul: &'a mut dyn Paul,
    vicky: &'a mut dyn Vicky,
}

impl Leaf for CommitInstructionLoadLeaf<'_>{

    fn lock(&mut self) -> Script {
        script!{
            {self.paul.push().instruction_type()}
            {ASM_LOAD as u32}
            OP_EQUALVERIFY

            {self.paul.push().pc_curr()}
            u32_toaltstack
            {self.paul.push().pc_next()}
            u32_fromaltstack
            {u32_push(1)}
            {u32_add_drop(0, 1)}
            u32_equalverify

            // Check if address_a == value_b
            {self.paul.push().address_a()}
            u32_toaltstack
            {self.paul.push().value_b()}
            u32_fromaltstack
            u32_equalverify

            // Check if value_a == value_c
            {self.paul.push().value_a()}
            u32_toaltstack
            {self.paul.push().value_c()}
            u32_fromaltstack
            u32_equalverify

            { self.paul.commit().address_b() } 
            { self.paul.commit().address_c() } 

            {OP_TRUE} // TODO: verify covenant here
        }
    }

    fn unlock(&mut self) -> Script {
        script!{
            { self.paul.unlock().address_c() }
            { self.paul.unlock().address_b() }
            { self.paul.unlock().value_c() }
            { self.paul.unlock().value_a() }
            { self.paul.unlock().value_b() }
            { self.paul.unlock().address_a() }
            { self.paul.unlock().pc_next() }
            { self.paul.unlock().pc_curr() }
            { self.paul.unlock().instruction_type() }
        }
    }
}

#[derive(LeafGetters)]
pub struct CommitInstructionStoreLeaf<'a> {
    paul: &'a mut dyn Paul,
    vicky: &'a mut dyn Vicky,
}

impl Leaf for CommitInstructionStoreLeaf<'_>{

    fn lock(&mut self) -> Script {
        script!{
            {self.paul.push().instruction_type()}
            {ASM_STORE as u32}
            OP_EQUALVERIFY

            {self.paul.push().pc_curr()}
            u32_toaltstack
            {self.paul.push().pc_next()}
            u32_fromaltstack
            {u32_push(1)}
            {u32_add_drop(0, 1)}
            u32_equalverify

            // Check if address_c == value_b
            {self.paul.push().address_c()}
            u32_toaltstack
            {self.paul.push().value_b()}
            u32_fromaltstack
            u32_equalverify

            // Check if value_a == value_c
            {self.paul.push().value_a()}
            u32_toaltstack
            {self.paul.push().value_c()}
            u32_fromaltstack
            u32_equalverify

            { self.paul.commit().address_a() } 
            { self.paul.commit().address_b() } 

            {OP_TRUE} // TODO: verify covenant here
        }
    }

    fn unlock(&mut self) -> Script {
        script!{
            { self.paul.unlock().address_b() }
            { self.paul.unlock().address_a() }
            { self.paul.unlock().value_c() }
            { self.paul.unlock().value_a() }
            { self.paul.unlock().value_b() }
            { self.paul.unlock().address_c() }
            { self.paul.unlock().pc_next() }
            { self.paul.unlock().pc_curr() }
            { self.paul.unlock().instruction_type() }
        }
    }
}

#[derive(LeafGetters)]
pub struct CommitInstructionAndLeaf<'a> {
    paul: &'a mut dyn Paul,
    vicky: &'a mut dyn Vicky,
}

impl Leaf for CommitInstructionAndLeaf<'_>{

    fn lock(&mut self) -> Script {
        script!{
            {self.paul.push().instruction_type()}
            {ASM_AND as u32}
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
            u32_toaltstack

            u8_push_xor_table
            u32_fromaltstack
            u32_fromaltstack
            {u32_and(0, 1, 3)}
            u32_fromaltstack
            u32_equalverify
            u32_drop
            u8_drop_xor_table

            { self.paul.commit().address_a() } 
            { self.paul.commit().address_b() } 
            { self.paul.commit().address_c() } 

            {OP_TRUE} // TODO: verify covenant here
        }
    }

    fn unlock(&mut self) -> Script {
        script!{
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
pub struct CommitInstructionAndImmediateLeaf<'a> {
    paul: &'a mut dyn Paul,
    vicky: &'a mut dyn Vicky,
}

impl Leaf for CommitInstructionAndImmediateLeaf<'_>{

    fn lock(&mut self) -> Script {
        script!{
            {self.paul.push().instruction_type()}
            {ASM_ANDI as u32}
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
            u32_toaltstack

            u8_push_xor_table
            u32_fromaltstack
            u32_fromaltstack
            {u32_and(0, 1, 3)}
            u32_fromaltstack
            u32_equalverify
            u32_drop
            u8_drop_xor_table

            { self.paul.commit().address_a() } 
            { self.paul.commit().address_c() } 

            {OP_TRUE} // TODO: verify covenant here
        }
    }

    fn unlock(&mut self) -> Script {
        script!{
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
#[derive(LeafGetters)]
pub struct CommitInstructionOrLeaf<'a> {
    paul: &'a mut dyn Paul,
    vicky: &'a mut dyn Vicky,
}

impl Leaf for CommitInstructionOrLeaf<'_> {

    fn lock(&mut self) -> Script {
        script!{
            {self.paul.push().instruction_type()}
            {ASM_OR as u32}
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
            u32_toaltstack

            u8_push_xor_table
            u32_fromaltstack
            u32_fromaltstack
            {u32_or(0, 1, 3)}
            u32_fromaltstack
            u32_equalverify
            u32_drop
            u8_drop_xor_table

            { self.paul.commit().address_a() } 
            { self.paul.commit().address_b() } 
            { self.paul.commit().address_c() } 

            {OP_TRUE} // TODO: verify covenant here
        }
    }

    fn unlock(&mut self) -> Script {
        script!{
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

pub struct CommitInstructionOrImmediateLeaf<'a> {
    paul: &'a mut dyn Paul,
    vicky: &'a mut dyn Vicky,
}

impl Leaf for CommitInstructionOrImmediateLeaf<'_>{

    fn lock(&mut self) -> Script {
        script!{
            {self.paul.push().instruction_type()}
            {ASM_ORI as u32}
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
            u32_toaltstack

            u8_push_xor_table
            u32_fromaltstack
            u32_fromaltstack
            {u32_or(0, 1, 3)}
            u32_fromaltstack
            u32_equalverify
            u32_drop
            u8_drop_xor_table

            { self.paul.commit().address_a() } 
            { self.paul.commit().address_c() } 

            {OP_TRUE} // TODO: verify covenant here
        }
    }

    fn unlock(&mut self) -> Script {
        script!{
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
#[derive(LeafGetters)]
pub struct CommitInstructionXorLeaf<'a> {
    paul: &'a mut dyn Paul,
    vicky: &'a mut dyn Vicky,
}

impl Leaf for CommitInstructionXorLeaf<'_>{

    fn lock(&mut self) -> Script {
        script!{
            {self.paul.push().instruction_type()}
            {ASM_XOR as u32}
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
            u32_toaltstack

            u8_push_xor_table
            u32_fromaltstack
            u32_fromaltstack
            {u32_xor(0, 1, 3)}
            u32_fromaltstack
            u32_equalverify
            u32_drop
            u8_drop_xor_table

            { self.paul.commit().address_a() } 
            { self.paul.commit().address_b() } 
            { self.paul.commit().address_c() } 

            {OP_TRUE} // TODO: verify covenant here
        }
    }

    fn unlock(&mut self) -> Script {
        script!{
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
pub struct CommitInstructionXorImmediateLeaf<'a> {
    paul: &'a mut dyn Paul,
    vicky: &'a mut dyn Vicky,
}

impl Leaf for CommitInstructionXorImmediateLeaf<'_>{

    fn lock(&mut self) -> Script {
        script!{
            {self.paul.push().instruction_type()}
            {ASM_XORI as u32}
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
            u32_toaltstack

            u8_push_xor_table
            u32_fromaltstack
            u32_fromaltstack
            {u32_xor(0, 1, 3)}
            u32_fromaltstack
            u32_equalverify
            u32_drop
            u8_drop_xor_table

            { self.paul.commit().address_a() } 
            { self.paul.commit().address_c() } 

            {OP_TRUE} // TODO: verify covenant here
        }
    }

    fn unlock(&mut self) -> Script {
        script!{
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

#[derive(LeafGetters)]

pub struct CommitInstructionJMPLeaf<'a> {
    paul: &'a mut dyn Paul,
    vicky: &'a mut dyn Vicky,
}

impl Leaf for CommitInstructionJMPLeaf<'_>{

    fn lock(&mut self) -> Script {
        script!{
            {self.paul.push().instruction_type()}
            {ASM_JMP as u32}
            OP_EQUALVERIFY

            {self.paul.push().pc_next()}
            u32_toaltstack
            {self.paul.push().value_a()}
            u32_fromaltstack
            u32_equalverify

            { self.paul.commit().address_a() } 

            {OP_TRUE} // TODO: verify covenant here
        }
    }

    fn unlock(&mut self) -> Script {
        script!{
            { self.paul.unlock().address_a() }
            { self.paul.unlock().value_a() }
            { self.paul.unlock().pc_next() }
            { self.paul.unlock().instruction_type() }
        }
    }
}


#[derive(LeafGetters)]
pub struct CommitInstructionBEQLeaf<'a> {
    paul: &'a mut dyn Paul,
    vicky: &'a mut dyn Vicky,
}
// Execute BEQ, "Branch if equal"
impl Leaf for CommitInstructionBEQLeaf<'_>{

    fn lock(&mut self) -> Script {
        script!{
            // Ensure the instruction_type is {ASM_BEQ as u32}
            {self.paul.push().instruction_type()}
            {ASM_BEQ as u32}
            OP_EQUALVERIFY

            // Read pc_next and put it on the altstack
            {self.paul.push().pc_next()}
            u32_toaltstack

            // Check if value_a == value_b
            {self.paul.push().value_a()}
            u32_toaltstack
            {self.paul.push().value_b()}
            u32_fromaltstack
            u32_equal

            OP_IF
                // If value_a == value_b then pc_next = address_c
                {self.paul.push().address_c()}
            OP_ELSE
                // Otherwise, pc_next = pc_curr + 1
                {self.paul.push().pc_curr()}
                {u32_push(1)}
                {u32_add_drop(0, 1)}
            OP_ENDIF

            // Take pc_next from the altstack
            u32_fromaltstack
            // Ensure its equal to the result from above
            u32_equalverify

            // Commit to address_a and address_b
            { self.paul.commit().address_a() } 
            { self.paul.commit().address_b() } 

            // TODO: Check the covenant here
            {OP_TRUE}
        }
    }

    fn unlock(&mut self) -> Script {
        script!{
            { self.paul.unlock().address_b() }
            { self.paul.unlock().address_a() }

            // IF value_a == value_b THEN address_c ELSE pc_curr
            // self.paul.value_a() == self.paul.value_b() ? self.paul.unlock().address_c() : self.paul.unlock().pc_curr() 

            { self.paul.unlock().value_b() }
            { self.paul.unlock().value_a() }
            { self.paul.unlock().pc_next() }
            { self.paul.unlock().instruction_type() }
        }
    }
}

#[derive(LeafGetters)]
pub struct CommitInstructionBNELeaf<'a> {
    paul: &'a mut dyn Paul,
    vicky: &'a mut dyn Vicky,
}
// Execute BEQ, "Branch if not equal"
impl Leaf for CommitInstructionBNELeaf<'_> {

    fn lock(&mut self) -> Script {
        script!{
            // Ensure the instruction_type is {ASM_BEQ as u32}
            {self.paul.push().instruction_type()}
            {ASM_BNE as u32}
            OP_EQUALVERIFY

            // Read pc_next and put it on the altstack
            {self.paul.push().pc_next()}
            u32_toaltstack

            // Check if value_a !== value_b
            {self.paul.push().value_a()}
            u32_toaltstack
            {self.paul.push().value_b()}
            u32_fromaltstack
            u32_notequal

            OP_IF
            // If value_a !== value_b then pc_next = address_c
            {self.paul.push().address_c()}
            OP_ELSE
            // Otherwise, pc_next = pc_curr + 1
            {self.paul.push().pc_curr()}
            {u32_push(1)}
            {u32_add_drop(0, 1)}
            OP_ENDIF

            // Take pc_next from the altstack
            u32_fromaltstack
            // Ensure its equal to the result from above
            u32_equalverify

            // Commit to address_a and address_b
            { self.paul.commit().address_a() } 
            { self.paul.commit().address_b() } 

            // TODO: Check the covenant here
            {OP_TRUE}
        }
    }

    fn unlock(&mut self) -> Script {
        script!{
            { self.paul.unlock().address_b() }
            { self.paul.unlock().address_a() }

            // IF value_a !== value_b THEN address_c ELSE pc_curr
            // self.paul.value_a() !== self.paul.value_b() ? self.paul.unlock().address_c() : { self.paul.unlock().pc_curr() }

            { self.paul.unlock().value_b() }
            { self.paul.unlock().value_a() }
            { self.paul.unlock().pc_next() }
            { self.paul.unlock().instruction_type() }
        }
    }
}
#[derive(LeafGetters)]
pub struct CommitInstructionRSHIFT1Leaf<'a> {
    paul: &'a mut dyn Paul,
    vicky: &'a mut dyn Vicky,
}

impl Leaf for CommitInstructionRSHIFT1Leaf<'_>{

    fn lock(&mut self) -> Script {
        script!{
            {self.paul.push().instruction_type()}
            {ASM_RSHIFT1 as u32}
            OP_EQUALVERIFY

            {self.paul.push().pc_curr()}
            u32_toaltstack
            {self.paul.push().pc_next()}
            u32_fromaltstack
            {u32_push(1)}
            {u32_add_drop(0, 1)}
            u32_equalverify

            {self.paul.push().value_a()}
            u32_toaltstack
            {u32_push(0x80000000)}
            u32_toaltstack
            {self.paul.push().value_c()}
            OP_4DUP
            u32_fromaltstack
            // value_c MSB is 0
            u32_lessthan
            OP_VERIFY
            // value_c << 1
            OP_4DUP
            {u32_add_drop(0, 1)}
            // Either value_c == value_a or value_c + 1 == value_a
            {u32_push(1)}
            {u32_add(1, 0)}
            u32_fromaltstack
            OP_4DUP
            {u32_roll(2)}
            u32_equal
            OP_TOALTSTACK
            u32_equal
            OP_FROMALTSTACK
            OP_BOOLOR
            OP_VERIFY

            { self.paul.commit().address_a() } 
            { self.paul.commit().address_c() } 

            {OP_TRUE} // TODO: verify covenant here
        }
    }

    fn unlock(&mut self) -> Script {
        script!{
            { self.paul.unlock().address_c() }
            { self.paul.unlock().address_a() }
            { self.paul.unlock().value_c() }
            { self.paul.unlock().value_a() }
            { self.paul.unlock().pc_next() }
            { self.paul.unlock().pc_curr() }
            { self.paul.unlock().instruction_type() }
        }
    }
}


#[derive(LeafGetters)]

pub struct CommitInstructionSLTULeaf<'a> {
    paul: &'a mut dyn Paul,
    vicky: &'a mut dyn Vicky,
}

impl Leaf for CommitInstructionSLTULeaf<'_>{

    fn lock(&mut self) -> Script {
        script!{
            {self.paul.push().instruction_type()}
            {ASM_SLTU as u32}
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
            u32_lessthan
            OP_IF
                {u32_push(1)}
            OP_ELSE
                {u32_push(0)}
            OP_ENDIF
            u32_fromaltstack
            u32_equalverify


            { self.paul.commit().address_a() } 
            { self.paul.commit().address_b() } 
            { self.paul.commit().address_c() } 

            {OP_TRUE} // TODO: verify covenant here
        }
    }

    fn unlock(&mut self) -> Script {
        script!{
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

pub struct CommitInstructionSLTLeaf<'a> {
    paul: &'a mut dyn Paul,
    vicky: &'a mut dyn Vicky,
}

impl Leaf for CommitInstructionSLTLeaf<'_>{

    fn lock(&mut self) -> Script {
        script!{
            {self.paul.push().instruction_type()}
            {ASM_SLT as u32 as u32}
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

            {self.paul.push().value_a()}
            OP_4DUP
            {u32_push(0x8000_0000)}
            u32_lessthan
            // Put negated value_a sign on altstack
            OP_TOALTSTACK
            u32_toaltstack
            {self.paul.push().value_b()}
            u32_fromaltstack
            {u32_roll(1)}
            OP_4DUP
            {u32_push(0x8000_0000)}
            u32_lessthan
            // Put negated value_b sign on altstack
            OP_TOALTSTACK
            u32_lessthan
            // If value_a and value_b have different signs the result has to be flipped
            OP_FROMALTSTACK
            OP_FROMALTSTACK
            OP_ADD
            1
            OP_EQUAL
            OP_IF
            OP_NOT
            OP_ENDIF

            // Check whether value_c is correctly set to the lessthan result
            OP_IF
            {u32_push(1)}
            OP_ELSE
            {u32_push(0)}
            OP_ENDIF
            u32_fromaltstack
            u32_equalverify

            { self.paul.commit().address_a() } 
            { self.paul.commit().address_b() } 
            { self.paul.commit().address_c() }

            {OP_TRUE} // TODO: verify covenant here
        }
    }

    fn unlock(&mut self) -> Script {
        script!{
            { self.paul.unlock().address_c() }
            { self.paul.unlock().address_b() }
            { self.paul.unlock().address_a() }
            { self.paul.unlock().value_b() }
            { self.paul.unlock().value_a() }
            { self.paul.unlock().value_c() }
            { self.paul.unlock().pc_next() }
            { self.paul.unlock().pc_curr() }
            { self.paul.unlock().instruction_type() }
        }
    }
}

///////////////////////////////////////////////////////////
// merkle/read.js

#[derive(LeafGetters)]
pub struct MerkleChallengeALeaf<'a> {
    pub paul: &'a mut dyn Paul,
    pub vicky: &'a mut dyn Vicky,
    pub round_index: u8
}

impl Leaf for MerkleChallengeALeaf<'_> {

    fn lock(&mut self) -> Script {
        script! {
            { self.vicky.commit().merkle_challenge_a(self.round_index) }
            // { self.vicky.pubkey() }
            // OP_CHECKSIGVERIFY
            // paul.pubkey
            OP_CHECKSIG
        }
    }

    fn unlock(&mut self) -> Script {
        assert!(self.vicky.is_faulty_read_a());
        script! {
            // paul.sign(this), // TODO
            // { self.vicky.sign(self) }
            { self.vicky.unlock().merkle_challenge_a(self.round_index) }
        }
    }
    
}
