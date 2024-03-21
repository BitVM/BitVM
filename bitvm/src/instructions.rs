use bitcoin::blockdata::script::ScriptBuf as Script;
use bitcoin::opcodes::OP_TRUE;
use bitcoin_script::bitcoin_script as script;
use scripts::opcodes::u32_add::{u32_add, u32_add_drop};
use scripts::opcodes::u32_and::u32_and;
use scripts::opcodes::u32_cmp::*;
use scripts::opcodes::u32_or::u32_or;
use scripts::opcodes::u32_std::*;
use scripts::opcodes::u32_sub::u32_sub_drop;
use scripts::opcodes::u32_xor::{u32_xor, u8_drop_xor_table, u8_push_xor_table};
use scripts::{
    leaf::{Leaves},
    opcodes::pushable,
};
use crate::graph::BitVmLeaf;
use crate::model::BitVmModel;
use super::constants::*;

pub const COMMIT_INSTRUCTION_ADD_LEAF: BitVmLeaf = BitVmLeaf {
    lock: |model| {
        script! {
            {model.paul.push().instruction_type()}
            {ASM_ADD}
            OP_EQUALVERIFY

            {model.paul.push().pc_curr()}
            u32_toaltstack
            {model.paul.push().pc_next()}
            u32_fromaltstack
            {u32_push(1)}
            {u32_add_drop(0, 1)}
            u32_equalverify

            {model.paul.push().value_c()}
            u32_toaltstack
            {model.paul.push().value_b()}
            u32_toaltstack
            {model.paul.push().value_a()}
            u32_fromaltstack
            {u32_add_drop(0, 1)}
            u32_fromaltstack
            u32_equalverify


            {model.paul.commit().address_a()}
            {model.paul.commit().address_b()}
            {model.paul.commit().address_c()}

            1 // {OP_TRUE}
        }
    },

    unlock:|model|{
        script! {
            { model.paul.unlock().address_c() }
            { model.paul.unlock().address_b() }
            { model.paul.unlock().address_a() }
            { model.paul.unlock().value_a() }
            { model.paul.unlock().value_b() }
            { model.paul.unlock().value_c() }
            { model.paul.unlock().pc_next() }
            { model.paul.unlock().pc_curr() }
            { model.paul.unlock().instruction_type() }
        }
    }
};


// Different to the CommitInstructionAddLeaf
// The second summand is address_b instead of value_b
const COMMIT_INSTRUCTION_ADD_IMMEDIATE_LEAF: BitVmLeaf = BitVmLeaf {
    lock: |model| {
        script! {
            {model.paul.push().instruction_type()}
            {ASM_ADD}
            OP_EQUALVERIFY

            {model.paul.push().pc_curr()}
            u32_toaltstack
            {model.paul.push().pc_next()}
            u32_fromaltstack
            {u32_push(1)}
            {u32_add_drop(0, 1)}
            u32_equalverify

            {model.paul.push().value_c()}
            u32_toaltstack

            {model.paul.push().address_b()}
            u32_toaltstack
            {model.paul.push().value_a()}
            u32_fromaltstack
            {u32_add_drop(0, 1)}
            u32_fromaltstack
            u32_equalverify


            {model.paul.commit().address_a()}
            {model.paul.commit().address_c()}

            1 // {OP_TRUE} // TODO: verify covenant here
        }
    },

    unlock:|model|{
        script! {
            { model.paul.unlock().address_c() }
            { model.paul.unlock().address_a() }
            { model.paul.unlock().value_a() }
            { model.paul.unlock().address_b() }
            { model.paul.unlock().value_c() }
            { model.paul.unlock().pc_next() }
            { model.paul.unlock().pc_curr() }
            { model.paul.unlock().instruction_type() }
        }
    }
};


const COMMIT_INSTRUCTION_SUB_LEAF: BitVmLeaf = BitVmLeaf {
    lock: |model| {
        script! {
            {model.paul.push().instruction_type()}
            {ASM_SUB}
            OP_EQUALVERIFY

            {model.paul.push().pc_curr()}
            u32_toaltstack
            {model.paul.push().pc_next()}
            u32_fromaltstack
            {u32_push(1)}
            {u32_add_drop(0, 1)}
            u32_equalverify

            {model.paul.push().value_c()}
            u32_toaltstack

            {model.paul.push().value_a()}
            u32_toaltstack
            {model.paul.push().value_b()}
            u32_fromaltstack
            {u32_sub_drop(0, 1)}
            u32_fromaltstack
            u32_equalverify


            {model.paul.commit().address_a()}
            {model.paul.commit().address_b()}
            {model.paul.commit().address_c()}

            {OP_TRUE} // TODO: verify covenant here
        }
    },

    unlock:|model|{
        script! {
            { model.paul.unlock().address_c() }
            { model.paul.unlock().address_b() }
            { model.paul.unlock().address_a() }
            { model.paul.unlock().value_b() }
            { model.paul.unlock().value_a() }
            { model.paul.unlock().value_c() }
            { model.paul.unlock().pc_next() }
            { model.paul.unlock().pc_curr() }
            { model.paul.unlock().instruction_type() }
        }
    }
};


const COMMIT_INSTRUCTION_SUB_IMMEDIATE_LEAF: BitVmLeaf = BitVmLeaf {
    lock: |model| {
        script! {
            {model.paul.push().instruction_type()}
            {ASM_SUBI}
            OP_EQUALVERIFY

            {model.paul.push().pc_curr()}
            u32_toaltstack
            {model.paul.push().pc_next()}
            u32_fromaltstack
            {u32_push(1)}
            {u32_add_drop(0, 1)}
            u32_equalverify

            {model.paul.push().value_c()}
            u32_toaltstack

            {model.paul.push().value_a()}
            u32_toaltstack
            {model.paul.push().address_b()}
            u32_fromaltstack
            {u32_sub_drop(0, 1)}
            u32_fromaltstack
            u32_equalverify


            { model.paul.commit().address_a() }
            { model.paul.commit().address_c() }

            {OP_TRUE} // TODO: verify covenant here
        }
    },

    unlock:|model|{
        script! {
            { model.paul.unlock().address_c() }
            { model.paul.unlock().address_a() }
            { model.paul.unlock().address_b() }
            { model.paul.unlock().value_a() }
            { model.paul.unlock().value_c() }
            { model.paul.unlock().pc_next() }
            { model.paul.unlock().pc_curr() }
            { model.paul.unlock().instruction_type() }
        }
    }
};


const COMMIT_INSTRUCTION_LOAD_LEAF: BitVmLeaf = BitVmLeaf {
    lock: |model| {
        script! {
            {model.paul.push().instruction_type()}
            {ASM_LOAD}
            OP_EQUALVERIFY

            {model.paul.push().pc_curr()}
            u32_toaltstack
            {model.paul.push().pc_next()}
            u32_fromaltstack
            {u32_push(1)}
            {u32_add_drop(0, 1)}
            u32_equalverify

            // Check if address_a == value_b
            {model.paul.push().address_a()}
            u32_toaltstack
            {model.paul.push().value_b()}
            u32_fromaltstack
            u32_equalverify

            // Check if value_a == value_c
            {model.paul.push().value_a()}
            u32_toaltstack
            {model.paul.push().value_c()}
            u32_fromaltstack
            u32_equalverify

            { model.paul.commit().address_b() }
            { model.paul.commit().address_c() }

            {OP_TRUE} // TODO: verify covenant here
        }
    },

    unlock:|model|{
        script! {
            { model.paul.unlock().address_c() }
            { model.paul.unlock().address_b() }
            { model.paul.unlock().value_c() }
            { model.paul.unlock().value_a() }
            { model.paul.unlock().value_b() }
            { model.paul.unlock().address_a() }
            { model.paul.unlock().pc_next() }
            { model.paul.unlock().pc_curr() }
            { model.paul.unlock().instruction_type() }
        }
    }
};


const COMMIT_INSTRUCTION_STORE_LEAF: BitVmLeaf = BitVmLeaf {
    lock: |model| {
        script! {
            {model.paul.push().instruction_type()}
            {ASM_STORE}
            OP_EQUALVERIFY

            {model.paul.push().pc_curr()}
            u32_toaltstack
            {model.paul.push().pc_next()}
            u32_fromaltstack
            {u32_push(1)}
            {u32_add_drop(0, 1)}
            u32_equalverify

            // Check if address_c == value_b
            {model.paul.push().address_c()}
            u32_toaltstack
            {model.paul.push().value_b()}
            u32_fromaltstack
            u32_equalverify

            // Check if value_a == value_c
            {model.paul.push().value_a()}
            u32_toaltstack
            {model.paul.push().value_c()}
            u32_fromaltstack
            u32_equalverify

            { model.paul.commit().address_a() }
            { model.paul.commit().address_b() }

            {OP_TRUE} // TODO: verify covenant here
        }
    },

    unlock:|model|{
        script! {
            { model.paul.unlock().address_b() }
            { model.paul.unlock().address_a() }
            { model.paul.unlock().value_c() }
            { model.paul.unlock().value_a() }
            { model.paul.unlock().value_b() }
            { model.paul.unlock().address_c() }
            { model.paul.unlock().pc_next() }
            { model.paul.unlock().pc_curr() }
            { model.paul.unlock().instruction_type() }
        }
    }
};


const COMMIT_INSTRUCTION_AND_LEAF: BitVmLeaf = BitVmLeaf {
    lock: |model| {
        script! {
            {model.paul.push().instruction_type()}
            {ASM_AND}
            OP_EQUALVERIFY

            {model.paul.push().pc_curr()}
            u32_toaltstack
            {model.paul.push().pc_next()}
            u32_fromaltstack
            {u32_push(1)}
            {u32_add_drop(0, 1)}
            u32_equalverify

            {model.paul.push().value_c()}
            u32_toaltstack
            {model.paul.push().value_b()}
            u32_toaltstack
            {model.paul.push().value_a()}
            u32_toaltstack

            u8_push_xor_table
            u32_fromaltstack
            u32_fromaltstack
            {u32_and(0, 1, 3)}
            u32_fromaltstack
            u32_equalverify
            u32_drop
            u8_drop_xor_table

            { model.paul.commit().address_a() }
            { model.paul.commit().address_b() }
            { model.paul.commit().address_c() }

            {OP_TRUE} // TODO: verify covenant here
        }
    },

    unlock:|model|{
        script! {
            { model.paul.unlock().address_c() }
            { model.paul.unlock().address_b() }
            { model.paul.unlock().address_a() }
            { model.paul.unlock().value_a() }
            { model.paul.unlock().value_b() }
            { model.paul.unlock().value_c() }
            { model.paul.unlock().pc_next() }
            { model.paul.unlock().pc_curr() }
            { model.paul.unlock().instruction_type() }
        }
    }
};


const COMMIT_INSTRUCTION_AND_IMMEDIATE_LEAF: BitVmLeaf = BitVmLeaf {
    lock: |model| {
        script! {
            {model.paul.push().instruction_type()}
            {ASM_ANDI}
            OP_EQUALVERIFY

            {model.paul.push().pc_curr()}
            u32_toaltstack
            {model.paul.push().pc_next()}
            u32_fromaltstack
            {u32_push(1)}
            {u32_add_drop(0, 1)}
            u32_equalverify

            {model.paul.push().value_c()}
            u32_toaltstack
            {model.paul.push().address_b()}
            u32_toaltstack
            {model.paul.push().value_a()}
            u32_toaltstack

            u8_push_xor_table
            u32_fromaltstack
            u32_fromaltstack
            {u32_and(0, 1, 3)}
            u32_fromaltstack
            u32_equalverify
            u32_drop
            u8_drop_xor_table

            { model.paul.commit().address_a() }
            { model.paul.commit().address_c() }

            {OP_TRUE} // TODO: verify covenant here
        }
    },

    unlock:|model|{
        script! {
            { model.paul.unlock().address_c() }
            { model.paul.unlock().address_a() }
            { model.paul.unlock().value_a() }
            { model.paul.unlock().address_b() }
            { model.paul.unlock().value_c() }
            { model.paul.unlock().pc_next() }
            { model.paul.unlock().pc_curr() }
            { model.paul.unlock().instruction_type() }
        }
    }
};

const COMMIT_INSTRUCTION_OR_LEAF: BitVmLeaf = BitVmLeaf {
    lock: |model| {
        script! {
            {model.paul.push().instruction_type()}
            {ASM_OR}
            OP_EQUALVERIFY

            {model.paul.push().pc_curr()}
            u32_toaltstack
            {model.paul.push().pc_next()}
            u32_fromaltstack
            {u32_push(1)}
            {u32_add_drop(0, 1)}
            u32_equalverify

            {model.paul.push().value_c()}
            u32_toaltstack
            {model.paul.push().value_b()}
            u32_toaltstack
            {model.paul.push().value_a()}
            u32_toaltstack

            u8_push_xor_table
            u32_fromaltstack
            u32_fromaltstack
            {u32_or(0, 1, 3)}
            u32_fromaltstack
            u32_equalverify
            u32_drop
            u8_drop_xor_table

            { model.paul.commit().address_a() }
            { model.paul.commit().address_b() }
            { model.paul.commit().address_c() }

            {OP_TRUE} // TODO: verify covenant here
        }
    },

    unlock:|model|{
        script! {
            { model.paul.unlock().address_c() }
            { model.paul.unlock().address_b() }
            { model.paul.unlock().address_a() }
            { model.paul.unlock().value_a() }
            { model.paul.unlock().value_b() }
            { model.paul.unlock().value_c() }
            { model.paul.unlock().pc_next() }
            { model.paul.unlock().pc_curr() }
            { model.paul.unlock().instruction_type() }
        }
    }
};


const COMMIT_INSTRUCTION_OR_IMMEDIATE_LEAF: BitVmLeaf = BitVmLeaf {
    lock: |model| {
        script! {
            {model.paul.push().instruction_type()}
            {ASM_ORI}
            OP_EQUALVERIFY

            {model.paul.push().pc_curr()}
            u32_toaltstack
            {model.paul.push().pc_next()}
            u32_fromaltstack
            {u32_push(1)}
            {u32_add_drop(0, 1)}
            u32_equalverify

            {model.paul.push().value_c()}
            u32_toaltstack
            {model.paul.push().address_b()}
            u32_toaltstack
            {model.paul.push().value_a()}
            u32_toaltstack

            u8_push_xor_table
            u32_fromaltstack
            u32_fromaltstack
            {u32_or(0, 1, 3)}
            u32_fromaltstack
            u32_equalverify
            u32_drop
            u8_drop_xor_table

            { model.paul.commit().address_a() }
            { model.paul.commit().address_c() }

            {OP_TRUE} // TODO: verify covenant here
        }
    },

    unlock:|model|{
        script! {
            { model.paul.unlock().address_c() }
            { model.paul.unlock().address_a() }
            { model.paul.unlock().value_a() }
            { model.paul.unlock().address_b() }
            { model.paul.unlock().value_c() }
            { model.paul.unlock().pc_next() }
            { model.paul.unlock().pc_curr() }
            { model.paul.unlock().instruction_type() }
        }
    }
};

const COMMIT_INSTRUCTION_XOR_LEAF: BitVmLeaf = BitVmLeaf {
    lock: |model| {
        script! {
            {model.paul.push().instruction_type()}
            {ASM_XOR}
            OP_EQUALVERIFY

            {model.paul.push().pc_curr()}
            u32_toaltstack
            {model.paul.push().pc_next()}
            u32_fromaltstack
            {u32_push(1)}
            {u32_add_drop(0, 1)}
            u32_equalverify

            {model.paul.push().value_c()}
            u32_toaltstack
            {model.paul.push().value_b()}
            u32_toaltstack
            {model.paul.push().value_a()}
            u32_toaltstack

            u8_push_xor_table
            u32_fromaltstack
            u32_fromaltstack
            {u32_xor(0, 1, 3)}
            u32_fromaltstack
            u32_equalverify
            u32_drop
            u8_drop_xor_table

            { model.paul.commit().address_a() }
            { model.paul.commit().address_b() }
            { model.paul.commit().address_c() }

            {OP_TRUE} // TODO: verify covenant here
        }
    },

    unlock:|model|{
        script! {
            { model.paul.unlock().address_c() }
            { model.paul.unlock().address_b() }
            { model.paul.unlock().address_a() }
            { model.paul.unlock().value_a() }
            { model.paul.unlock().value_b() }
            { model.paul.unlock().value_c() }
            { model.paul.unlock().pc_next() }
            { model.paul.unlock().pc_curr() }
            { model.paul.unlock().instruction_type() }
        }
    }
};


const COMMIT_INSTRUCTION_XOR_IMMEDIATE_LEAF: BitVmLeaf = BitVmLeaf {
    lock: |model| {
        script! {
            {model.paul.push().instruction_type()}
            {ASM_XORI}
            OP_EQUALVERIFY

            {model.paul.push().pc_curr()}
            u32_toaltstack
            {model.paul.push().pc_next()}
            u32_fromaltstack
            {u32_push(1)}
            {u32_add_drop(0, 1)}
            u32_equalverify

            {model.paul.push().value_c()}
            u32_toaltstack
            {model.paul.push().address_b()}
            u32_toaltstack
            {model.paul.push().value_a()}
            u32_toaltstack

            u8_push_xor_table
            u32_fromaltstack
            u32_fromaltstack
            {u32_xor(0, 1, 3)}
            u32_fromaltstack
            u32_equalverify
            u32_drop
            u8_drop_xor_table

            { model.paul.commit().address_a() }
            { model.paul.commit().address_c() }

            {OP_TRUE} // TODO: verify covenant here
        }
    },

    unlock:|model|{
        script! {
            { model.paul.unlock().address_c() }
            { model.paul.unlock().address_a() }
            { model.paul.unlock().value_a() }
            { model.paul.unlock().address_b() }
            { model.paul.unlock().value_c() }
            { model.paul.unlock().pc_next() }
            { model.paul.unlock().pc_curr() }
            { model.paul.unlock().instruction_type() }
        }
    }
};


const COMMIT_INSTRUCTION_JMPLEAF: BitVmLeaf = BitVmLeaf {
    lock: |model| {
        script! {
            {model.paul.push().instruction_type()}
            {ASM_JMP}
            OP_EQUALVERIFY

            {model.paul.push().pc_next()}
            u32_toaltstack
            {model.paul.push().value_a()}
            u32_fromaltstack
            u32_equalverify

            { model.paul.commit().address_a() }

            {OP_TRUE} // TODO: verify covenant here
        }
    },

    unlock:|model|{
        script! {
            { model.paul.unlock().address_a() }
            { model.paul.unlock().value_a() }
            { model.paul.unlock().pc_next() }
            { model.paul.unlock().instruction_type() }
        }
    }
};

// Execute BEQ, "Branch if equal"
const COMMIT_INSTRUCTION_BEQLEAF: BitVmLeaf = BitVmLeaf {
    lock: |model| {
        script! {
            // Ensure the instruction_type is {ASM_BEQ}
            {model.paul.push().instruction_type()}
            {ASM_BEQ}
            OP_EQUALVERIFY

            // Read pc_next and put it on the altstack
            {model.paul.push().pc_next()}
            u32_toaltstack

            // Check if value_a == value_b
            {model.paul.push().value_a()}
            u32_toaltstack
            {model.paul.push().value_b()}
            u32_fromaltstack
            u32_equal

            OP_IF
                // If value_a == value_b then pc_next = address_c
                {model.paul.push().address_c()}
            OP_ELSE
                // Otherwise, pc_next = pc_curr + 1
                {model.paul.push().pc_curr()}
                {u32_push(1)}
                {u32_add_drop(0, 1)}
            OP_ENDIF

            // Take pc_next from the altstack
            u32_fromaltstack
            // Ensure its equal to the result from above
            u32_equalverify

            // Commit to address_a and address_b
            { model.paul.commit().address_a() }
            { model.paul.commit().address_b() }

            // TODO: Check the covenant here
            {OP_TRUE}
        }
    },

    unlock:|model|{
        script! {
            { model.paul.unlock().address_b() }
            { model.paul.unlock().address_a() }

            // IF value_a == value_b THEN address_c ELSE pc_curr
            {
                if model.paul.value_a() == model.paul.value_b() {
                    model.paul.unlock().address_c()
                } else {
                    model.paul.unlock().pc_curr()
                }
            }
            { model.paul.unlock().value_b() }
            { model.paul.unlock().value_a() }
            { model.paul.unlock().pc_next() }
            { model.paul.unlock().instruction_type() }
        }
    }
};

// Execute BEQ, "Branch if not equal"
const COMMIT_INSTRUCTION_BNELEAF: BitVmLeaf = BitVmLeaf {
    lock: |model| {
        script! {
            // Ensure the instruction_type is {ASM_BEQ}
            {model.paul.push().instruction_type()}
            {ASM_BNE}
            OP_EQUALVERIFY

            // Read pc_next and put it on the altstack
            {model.paul.push().pc_next()}
            u32_toaltstack

            // Check if value_a !== value_b
            {model.paul.push().value_a()}
            u32_toaltstack
            {model.paul.push().value_b()}
            u32_fromaltstack
            u32_notequal

            OP_IF
                // If value_a !== value_b then pc_next = address_c
                // TODO: refactor this to not use the "address_c hack"
                // but instead a dedicated identifier for the jmp address
                {model.paul.push().address_c()}
            OP_ELSE
                // Otherwise, pc_next = pc_curr + 1
                {model.paul.push().pc_curr()}
                {u32_push(1)}
                {u32_add_drop(0, 1)}
            OP_ENDIF

            // Take pc_next from the altstack
            u32_fromaltstack
            // Ensure its equal to the result from above
            u32_equalverify

            // Commit to address_a and address_b
            { model.paul.commit().address_a() }
            { model.paul.commit().address_b() }

            // TODO: Check the covenant here
            {OP_TRUE}
        }
    },

    unlock:|model|{
        script! {
            { model.paul.unlock().address_b() }
            { model.paul.unlock().address_a() }

            // IF value_a !== value_b THEN address_c ELSE pc_curr
            {
                if model.paul.value_a() == model.paul.value_b() {
                    model.paul.unlock().address_c()
                } else {
                    model.paul.unlock().pc_curr()
                }
            }

            { model.paul.unlock().value_b() }
            { model.paul.unlock().value_a() }
            { model.paul.unlock().pc_next() }
            { model.paul.unlock().instruction_type() }
        }
    }
};

const COMMIT_INSTRUCTION_RSHIFT1_LEAF: BitVmLeaf = BitVmLeaf {
    lock: |model| {
        script! {
            {model.paul.push().instruction_type()}
            {ASM_RSHIFT1}
            OP_EQUALVERIFY

            {model.paul.push().pc_curr()}
            u32_toaltstack
            {model.paul.push().pc_next()}
            u32_fromaltstack
            {u32_push(1)}
            {u32_add_drop(0, 1)}
            u32_equalverify

            {model.paul.push().value_a()}
            u32_toaltstack
            {u32_push(0x80000000)}
            u32_toaltstack
            {model.paul.push().value_c()}
            u32_dup
            u32_fromaltstack
            // value_c MSB is 0
            u32_lessthan
            OP_VERIFY
            // value_c << 1
            u32_dup
            {u32_add_drop(0, 1)}
            // Either value_c == value_a or value_c + 1 == value_a
            {u32_push(1)}
            {u32_add(1, 0)}
            u32_fromaltstack
            u32_dup
            {u32_roll(2)}
            u32_equal
            OP_TOALTSTACK
            u32_equal
            OP_FROMALTSTACK
            OP_BOOLOR
            OP_VERIFY

            { model.paul.commit().address_a() }
            { model.paul.commit().address_c() }

            {OP_TRUE} // TODO: verify covenant here
        }
    },

    unlock:|model|{
        script! {
            { model.paul.unlock().address_c() }
            { model.paul.unlock().address_a() }
            { model.paul.unlock().value_c() }
            { model.paul.unlock().value_a() }
            { model.paul.unlock().pc_next() }
            { model.paul.unlock().pc_curr() }
            { model.paul.unlock().instruction_type() }
        }
    }
};


const COMMIT_INSTRUCTION_SLTULEAF: BitVmLeaf = BitVmLeaf {
    lock: |model| {
        script! {
            {model.paul.push().instruction_type()}
            {ASM_SLTU}
            OP_EQUALVERIFY

            {model.paul.push().pc_curr()}
            u32_toaltstack
            {model.paul.push().pc_next()}
            u32_fromaltstack
            {u32_push(1)}
            {u32_add_drop(0, 1)}
            u32_equalverify

            {model.paul.push().value_c()}
            u32_toaltstack

            {model.paul.push().value_b()}
            u32_toaltstack
            {model.paul.push().value_a()}
            u32_fromaltstack
            u32_lessthan
            OP_IF
                {u32_push(1)}
            OP_ELSE
                {u32_push(0)}
            OP_ENDIF
            u32_fromaltstack
            u32_equalverify


            { model.paul.commit().address_a() }
            { model.paul.commit().address_b() }
            { model.paul.commit().address_c() }

            {OP_TRUE} // TODO: verify covenant here
        }
    },

    unlock:|model|{
        script! {
            { model.paul.unlock().address_c() }
            { model.paul.unlock().address_b() }
            { model.paul.unlock().address_a() }
            { model.paul.unlock().value_a() }
            { model.paul.unlock().value_b() }
            { model.paul.unlock().value_c() }
            { model.paul.unlock().pc_next() }
            { model.paul.unlock().pc_curr() }
            { model.paul.unlock().instruction_type() }
        }
    }
};


const COMMIT_INSTRUCTION_SLTLEAF: BitVmLeaf = BitVmLeaf {
    lock: |model| {
        script! {
            {model.paul.push().instruction_type()}
            {ASM_SLT}
            OP_EQUALVERIFY

            {model.paul.push().pc_curr()}
            u32_toaltstack
            {model.paul.push().pc_next()}
            u32_fromaltstack
            {u32_push(1)}
            {u32_add_drop(0, 1)}
            u32_equalverify

            {model.paul.push().value_c()}
            u32_toaltstack

            {model.paul.push().value_a()}
            u32_dup
            {u32_push(0x8000_0000)}
            u32_lessthan
            // Put negated value_a sign on altstack
            OP_TOALTSTACK
            u32_toaltstack
            {model.paul.push().value_b()}
            u32_fromaltstack
            {u32_roll(1)}
            u32_dup
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

            { model.paul.commit().address_a() }
            { model.paul.commit().address_b() }
            { model.paul.commit().address_c() }

            {OP_TRUE} // TODO: verify covenant here
        }
    },

    unlock:|model|{
        script! {
            { model.paul.unlock().address_c() }
            { model.paul.unlock().address_b() }
            { model.paul.unlock().address_a() }
            { model.paul.unlock().value_b() }
            { model.paul.unlock().value_a() }
            { model.paul.unlock().value_c() }
            { model.paul.unlock().pc_next() }
            { model.paul.unlock().pc_curr() }
            { model.paul.unlock().instruction_type() }
        }
    }
};

pub fn commit_instruction() -> Leaves<BitVmModel> {
    vec![
        COMMIT_INSTRUCTION_ADD_LEAF,
        COMMIT_INSTRUCTION_ADD_IMMEDIATE_LEAF,
        COMMIT_INSTRUCTION_AND_IMMEDIATE_LEAF,
        COMMIT_INSTRUCTION_BEQLEAF,
        // TODO: 
    ]
}

