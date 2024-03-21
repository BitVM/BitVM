use std::vec;

use scripts::leaf::Leaves;
use scripts::opcodes::pseudo::OP_CHECKSEQUENCEVERIFY;
use scripts::{opcodes::pushable, leaf::Leaf};
use bitcoin_script::bitcoin_script as script;
use scripts::opcodes::blake3::blake3_160;
use scripts::opcodes::{
    unroll,
    u160_std::{
        u160_fromaltstack,
        u160_toaltstack,
        u160_equalverify,
        u160_swap_endian,
    },
    u32_std::{
        u32_fromaltstack,
        u32_toaltstack,
    },
};
use crate::graph::BitVmLeaf;
use crate::model::BitVmModel;
use crate::constants::{LOG_PATH_LEN, PATH_LEN, TIMEOUT};

fn merkle_challenge_c_leaf<const MERKLE_INDEX: u8>() -> BitVmLeaf {
    BitVmLeaf {
        lock: |model| script! {
            { MERKLE_INDEX }
            OP_DROP // This is just a marker to make the TXIDs unique
            // { model.vicky.pubkey, }
            OP_CHECKSIGVERIFY
            // paul.pubkey
            OP_CHECKSIG
        },
        unlock: |model| script! {
            // paul.sign(this), // TODO
            // { model.vicky.sign(this), }
        }
    }
}

pub fn merkle_challenge_c<const MERKLE_INDEX: u8>() -> Vec<BitVmLeaf> {
    vec![
        merkle_challenge_c_leaf::<MERKLE_INDEX>()
    ]
}


fn merkle_challenge_c_timeout_leaf() -> BitVmLeaf {
    BitVmLeaf {
        lock: |model| script! {
            { TIMEOUT }
            OP_CHECKSEQUENCEVERIFY
            OP_DROP
            // { model.paul.pubkey }
            OP_CHECKSIG
        },
        unlock: |model| script! {
            // { model.paul.sign(this) }
        }
    }
}



// // export class MerkleChallengeCTimeout extends EndTransaction {
// //     static ACTOR = PAUL
// //     static taproot(state) -> Script {
// //         return [
// //             [MerkleChallengeCTimeoutLeaf, state.vicky, state.paul]
// //         ]
// //     }
// // }


fn merkle_response_c_leaf<const MERKLE_INDEX: u8>() -> BitVmLeaf {
    BitVmLeaf {
        lock: |model| script! {
            { model.paul.commit().merkle_response_c_next_sibling(MERKLE_INDEX) }
            { model.paul.commit().merkle_response_c_next(MERKLE_INDEX) }
            // vicky.pubkey
            OP_CHECKSIGVERIFY
            // { model.paul.pubkey }
            OP_CHECKSIG
        },
        unlock: |model| script! {
            // paul.sign(this)
            // vicky.sign(this)
            { model.paul.unlock().merkle_response_c_next(MERKLE_INDEX) }
            { model.paul.unlock().merkle_response_c_next_sibling(MERKLE_INDEX) }
        }
    }
}

// // export class MerkleResponseC extends Transaction {
// //     static ACTOR = PAUL
// //     static taproot(model) -> Script {
// //         return [
// //             [MerkleResponseCLeaf, model.vicky, model.paul, this.INDEX]
// //         ]
// //     }
// // }


fn merkle_response_c_timeout_leaf() -> BitVmLeaf {
    BitVmLeaf {
        lock: |model| script! {
            { TIMEOUT }
            OP_CHECKSEQUENCEVERIFY
            OP_DROP
            // { self.vicky.pubkey }
            OP_CHECKSIG
        },
        unlock: |model| script! {
            // { self.vicky.sign(this) }
        }
    }
}

// // export class MerkleResponseCTimeout extends EndTransaction {
// //     static ACTOR = VICKY
// //     static taproot(state) -> Script {
// //         return [
// //             [MerkleResponseCTimeoutLeaf, state.vicky, state.paul]
// //         ]
// //     }
// // }


fn merkle_hash_c_left_leaf<const MERKLE_INDEX: u8>() -> BitVmLeaf {
    BitVmLeaf {
        lock: |model| script! {
            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            { model.paul.push().address_c_bit_at(PATH_LEN as u8 - 1 - MERKLE_INDEX) }
            OP_NOT
            OP_VERIFY

            // Read the child node
            { model.paul.push().merkle_response_c_next(MERKLE_INDEX) }
            // Read the child's sibling
            u160_toaltstack
            { model.paul.push().merkle_response_c_next_sibling(MERKLE_INDEX) }
            u160_fromaltstack

            // Hash the child nodes
            blake3_160
            u160_toaltstack
            // Read the parent hash
            { model.paul.push().merkle_response_c_next(MERKLE_INDEX + 1) }

            u160_fromaltstack
            u160_swap_endian
            u160_equalverify
            OP_TRUE // TODO: verify the covenant here
        },
        unlock: |model| script! {
            { model.paul.unlock().merkle_response_c_next(MERKLE_INDEX) }
            { model.paul.unlock().merkle_response_c_next_sibling(MERKLE_INDEX) }
            { model.paul.unlock().merkle_response_c_next(MERKLE_INDEX + 1) }
            { model.paul.unlock().address_c_bit_at(PATH_LEN as u8 - 1 - MERKLE_INDEX) }
        }
    }
}

fn merkle_hash_c_right_leaf<const MERKLE_INDEX_C: u8>() -> BitVmLeaf {
    BitVmLeaf {
        lock: |model| script! {
                // Read the bit from address to figure out if we have to swap the two nodes before hashing
            { model.paul.push().address_c_bit_at(PATH_LEN as u8 - 1 - MERKLE_INDEX_C) }
            OP_VERIFY

            // Read the child's sibling
            { model.paul.push().merkle_response_c_next_sibling(MERKLE_INDEX_C) }
            // Read the child node
            u160_toaltstack
            { model.paul.push().merkle_response_c_next(MERKLE_INDEX_C) }
            u160_fromaltstack

            // Hash the child nodes
            blake3_160
            u160_toaltstack
            // Read the parent hash
            { model.paul.push().merkle_response_c_next(MERKLE_INDEX_C + 1) }

            u160_fromaltstack
            u160_swap_endian
            u160_equalverify
            OP_TRUE // TODO: verify the covenant here
        },
        
        unlock: |model| script! {
            { model.paul.unlock().merkle_response_c_next_sibling(MERKLE_INDEX_C) }
            { model.paul.unlock().merkle_response_c_next(MERKLE_INDEX_C) }
            { model.paul.unlock().merkle_response_c_next(MERKLE_INDEX_C + 1) }
            { model.paul.unlock().address_c_bit_at(PATH_LEN as u8 - 1 - MERKLE_INDEX_C) }
        }
    }
}


fn merkle_hash_c_root_left_leaf<const TRACE_ROUND_INDEX: u8>() -> BitVmLeaf {
    BitVmLeaf {
        lock: |model| script! {
            // Verify we're executing the correct leaf

            { model.vicky.push().trace_index() }
            OP_TOALTSTACK
            { model.vicky.push().next_trace_index(TRACE_ROUND_INDEX) }
            OP_FROMALTSTACK
            OP_EQUALVERIFY

            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            { model.paul.push().address_c_bit_at(PATH_LEN as u8 - 1) }
            OP_NOT
            OP_VERIFY

            // Read the child nodes
            { model.paul.push().merkle_response_c_next(PATH_LEN as u8 - 1) }
            // Read the child's sibling
            u160_toaltstack
            { model.paul.push().merkle_response_c_next_sibling(PATH_LEN as u8 - 1) }
            u160_fromaltstack

            // Hash the child nodes
            blake3_160
            u160_toaltstack
            // Read the parent hash
            { model.paul.push().trace_response(TRACE_ROUND_INDEX) }

            u160_fromaltstack
            u160_swap_endian
            u160_equalverify

            OP_TRUE // TODO: verify the covenant here
        },

        unlock: |model| script! {
            { model.paul.unlock().trace_response(TRACE_ROUND_INDEX) }
            { model.paul.unlock().merkle_response_c_next_sibling(PATH_LEN as u8 - 1) }
            { model.paul.unlock().merkle_response_c_next(PATH_LEN as u8 - 1) }
            { model.paul.unlock().address_c_bit_at(PATH_LEN as u8 - 1) }
            { model.vicky.unlock().next_trace_index(TRACE_ROUND_INDEX) }
            { model.vicky.unlock().trace_index() }
        }
    }
}


fn merkle_hash_c_root_right_leaf<const TRACE_ROUND_INDEX: u8>() -> BitVmLeaf {
    BitVmLeaf {
        lock: |model| script! {
            // Verify we're executing the correct leaf

            { model.vicky.push().trace_index() }
            OP_TOALTSTACK
            { model.vicky.push().next_trace_index(TRACE_ROUND_INDEX) }
            OP_FROMALTSTACK
            OP_EQUALVERIFY

            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            { model.paul.push().address_c_bit_at(PATH_LEN as u8 - 1) }
            OP_VERIFY

            // Read the child's sibling
            { model.paul.push().merkle_response_c_next_sibling(PATH_LEN as u8 - 1) }
            // Read the child nodes
            { model.paul.push().merkle_response_c_next(PATH_LEN as u8 - 1) }
            u160_toaltstack
            u160_fromaltstack

            // Hash the child nodes
            blake3_160
            u160_toaltstack
            // Read the parent hash
            { model.paul.push().trace_response(TRACE_ROUND_INDEX) }

            u160_fromaltstack
            u160_swap_endian
            u160_equalverify

            OP_TRUE // TODO: verify the covenant here
        },

        unlock: |model| script! {
            { model.paul.unlock().trace_response(TRACE_ROUND_INDEX) }
            { model.paul.unlock().merkle_response_c_next(PATH_LEN as u8 - 1) }
            { model.paul.unlock().merkle_response_c_next_sibling(PATH_LEN as u8 - 1) }
            { model.paul.unlock().address_c_bit_at(PATH_LEN as u8 - 1) }
            { model.vicky.unlock().next_trace_index(TRACE_ROUND_INDEX) }
            { model.vicky.unlock().trace_index() } // TODO: Vicky can equivocate here
        }
    }
}

const MERKLE_CLEAF_HASH_LEFT_LEAF: BitVmLeaf = BitVmLeaf {
    lock: |model| script! {
    
        // Read the bit from address to figure out if we have to swap the two nodes before hashing
        { model.paul.push().address_c_bit_at(0) }
        OP_NOT
        OP_VERIFY
    
        // Read value_c
        { model.paul.push().value_c() }
        // Pad with 16 zero bytes
        u32_toaltstack
        { unroll(16, |_| 0) }
        u32_fromaltstack
        
        // Read sibling
        u160_toaltstack
        { model.paul.push().merkle_response_c_next_sibling(0) }
        u160_fromaltstack
    
        // Hash the child nodes
        blake3_160
        u160_toaltstack
        // Read the parent hash
        { model.paul.push().merkle_response_c_next(LOG_PATH_LEN as u8 - 1) }
    
        u160_fromaltstack
        u160_swap_endian
        u160_equalverify
        OP_TRUE // TODO: verify the covenant here
    },
    unlock: |model| script! {
        { model.paul.unlock().merkle_response_c_next(1) }
        { model.paul.unlock().merkle_response_c_next_sibling(0) }
        { model.paul.unlock().value_c() }
        { model.paul.unlock().address_c_bit_at(0) }
    }
};

const MERKLE_C_LEAF_HASH_RIGHT_LEAF: BitVmLeaf = BitVmLeaf {
    lock: |model| {
        script! {
            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            { model.paul.push().address_c_bit_at(0) }
            OP_VERIFY

            // Read sibling
            { model.paul.push().merkle_response_c_next_sibling(0) }
            
            // Read value_c
            u160_toaltstack
            { model.paul.push().value_c() }
            // Pad with 16 zero bytes
            u32_toaltstack
            { unroll(16, |_| 0) }
            u32_fromaltstack
            u160_fromaltstack
            
            // Hash the child nodes
            blake3_160
            u160_toaltstack
            // Read the parent hash
            { model.paul.push().merkle_response_c_next(LOG_PATH_LEN as u8 - 1) }

            u160_fromaltstack
            u160_swap_endian
            u160_equalverify
            OP_TRUE // TODO: verify the covenant here
        }
    },

    unlock: |model| script! {
        { model.paul.unlock().merkle_response_c_next(1) }
        { model.paul.unlock().value_c() }
        { model.paul.unlock().merkle_response_c_next_sibling(0) }
        { model.paul.unlock().address_c_bit_at(0) }
    }
};



// // export class MerkleHashC extends Transaction {
// //     static ACTOR = PAUL
// //     static taproot(model) -> Script {
// //         const { vicky, paul } = model;
// //         switch (this.INDEX) -> Script {
// //             case 0:
// //                 return [
// //                     [MerkleCLeafHashLeftLeaf, vicky, paul],
// //                     [MerkleCLeafHashRightLeaf, vicky, paul],
// //                 ];
// //             case (PATH_LEN as u8 - 1):
// //                 return [
// //                     ...loop(LOG_TRACE_LEN, traceRoundIndex => [MerkleHashCRootLeftLeaf, vicky, paul, traceRoundIndex]),
// //                     ...loop(LOG_TRACE_LEN, traceRoundIndex => [MerkleHashCRootRightLeaf, vicky, paul, traceRoundIndex]),
// //                 ];
// //             default:
// //                 return [
// //                     [MerkleHashCLeftLeaf, vicky, paul, this.INDEX],
// //                     [MerkleHashCRightLeaf, vicky, paul, this.INDEX],
// //                 ];
// //         }
// //     }
// // }



// // export class MerkleEquivocationC extends EndTransaction {
// //     static ACTOR = VICKY

// //     static taproot(model) -> Script {
// //         console.warn(`${this.name} not implemented`)
// //         return [
// //             [class extends Leaf<'a> {
// //                 lock() -> Script {
// //                     return ['OP_4']
// //                 }
// //                 unlock() -> Script {
// //                     return []
// //                 }
// //             }]
// //         ]
// //     }
// // }


