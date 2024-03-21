use tapscripts::opcodes::pushable;
use bitcoin_script::bitcoin_script as script;
use tapscripts::opcodes::blake3::blake3_160;
use tapscripts::opcodes::{
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
use crate::constants::{PATH_LEN, LOG_PATH_LEN};

fn trailing_zeros(uint: u8) -> u8 {
    uint.trailing_zeros() as u8
}

fn merkle_challenge_a_leaf<const ROUND_INDEX: u8>() -> BitVmLeaf {
    BitVmLeaf {
        lock: |model| script! {
            { model.vicky.commit().merkle_challenge_a(ROUND_INDEX) }
            // { model.vicky.pubkey() }
            // OP_CHECKSIGVERIFY
            // { paul.pubkey }
            OP_CHECKSIG
        },
        unlock: |model| {
            assert!(model.vicky.is_faulty_read_a());
            script! {
                // { paul.sign(this) }  // TODO
                // { model.vicky.sign(self) }
                { model.vicky.unlock().merkle_challenge_a(ROUND_INDEX) }
            }
        }
    }
}

fn merkle_challenge_b_leaf<const ROUND_INDEX: u8>() -> BitVmLeaf {
    BitVmLeaf {
        lock: |model| script! {
            { model.vicky.commit().merkle_challenge_b(ROUND_INDEX) }
            // vicky.pubkey,
            // OP_CHECKSIGVERIFY,
            // paul.pubkey,
            OP_CHECKSIG
        },
        unlock: |model| {
            assert!(model.vicky.is_faulty_read_b());
            script! {
                // paul.sign(this), // TODO
                // vicky.sign(this), 
                { model.vicky.unlock().merkle_challenge_b(ROUND_INDEX) }
            }
        }
    }
}

// // impl Transaction for MerkleChallengeA {
// //     static ACTOR = VICKY
// //     static taproot(model) {
// //         script! {
// //             [MerkleChallengeALeaf, model.vicky, model.paul, this.INDEX]
// //         ]
// //     }
// // }

// // impl Transaction for MerkleChallengeB {
// //     static ACTOR = VICKY
// //     static taproot(model) {
// //         script! {
// //             [MerkleChallengeBLeaf, model.vicky, model.paul, this.INDEX]
// //         ]
// //     }
// // }


fn merkle_challenge_a_timeout_leaf<const TIMEOUT: u32>() -> BitVmLeaf {
    BitVmLeaf {
        lock: |model| script! {
            { TIMEOUT }
            // OP_CHECKSEQUENCEVERIFY
            OP_DROP
            // paul.pubkey
            OP_CHECKSIG
        },
        unlock: |model| script! {
            // paul.sign(this), 
        }
    }
}

fn MerkleChallengeBTimeoutLeaf<const TIMEOUT: u32>() -> BitVmLeaf { 
    BitVmLeaf {
        lock: |model| script! {
            { TIMEOUT }
            // OP_CHECKSEQUENCEVERIFY
            OP_DROP
            // paul.pubkey
            OP_CHECKSIG
        },
        unlock: |model| script! {
            // paul.sign(this), 
        }
    }
}

// // export class MerkleChallengeATimeout extends EndTransaction {
// //     static ACTOR = PAUL
// //     static taproot(state){
// //         script! {[ MerkleChallengeATimeoutLeaf, state.vicky, state.paul]]
// //     }
// // }

// // export class MerkleChallengeBTimeout extends EndTransaction {
// //     static ACTOR = PAUL
// //     static taproot(state){
// //         script! {[ MerkleChallengeBTimeoutLeaf, state.vicky, state.paul]]
// //     }
// // } 

fn merkle_response_a_leaf<const ROUND_INDEX: u8>() -> BitVmLeaf {
    BitVmLeaf {
        lock: |model| script! {
            { model.paul.commit().merkle_response_a(ROUND_INDEX) }
            // vicky.pubkey
            // OP_CHECKSIGVERIFY
            // paul.pubkey
            OP_CHECKSIG
        },
        unlock: |model| script! {
            // { model.paul.sign(this) }
            // vicky.sign(this)
            { model.paul.unlock().merkle_response_a(ROUND_INDEX) }
        }
    }
}

fn merkle_response_b_leaf<const ROUND_INDEX: u8>() -> BitVmLeaf {
    BitVmLeaf {
        lock: |model|  script! {
            { model.paul.commit().merkle_response_b(ROUND_INDEX) }
            // vicky.pubkey
            // OP_CHECKSIGVERIFY
            // paul.pubkey
            OP_CHECKSIG
        },
        unlock: |model|  script! {
            // paul.sign(this), 
            // vicky.sign(this),
            { model.paul.unlock().merkle_response_b(ROUND_INDEX) }
        }
    }
}

// // export class Merkle_response_a extends Transaction {
// //     static ACTOR = PAUL
// //     static taproot(model) {
// //         script! {
// //             [MerkleResponseALeaf, model.vicky, model.paul, this.INDEX]
// //         ]
// //     }
// // }

// // export class Merkle_response_b extends Transaction {
// //     static ACTOR = PAUL
// //     static taproot(model) {
// //         script! {
// //             [MerkleResponseBLeaf, model.vicky, model.paul, this.INDEX]
// //         ]
// //     }
// // }

fn merkle_response_a_timeout_leaf<const TIMEOUT: u32>() -> BitVmLeaf {
    BitVmLeaf {
        lock: |model| script! {
            { TIMEOUT }
            // OP_CHECKSEQUENCEVERIFY
            OP_DROP
            // vicky.pubkey
            OP_CHECKSIG
        },
        unlock: |model| script! { 
            // vicky.sign(this), 
        }
    }
}

fn merkle_response_b_timeout_leaf<const TIMEOUT: u32>() -> BitVmLeaf {
    BitVmLeaf {
        lock: |model| script! {
            { TIMEOUT }
            // OP_CHECKSEQUENCEVERIFY
            OP_DROP
            // vicky.pubkey
            OP_CHECKSIG
        },
        unlock: |model| script! { 
            // vicky.sign(this), 
        }
    }
}

// // export class Merkle_response_aTimeout extends EndTransaction {
// //     static ACTOR = VICKY
// //     static taproot(state){
// //         script! {[ MerkleResponseATimeoutLeaf, state.vicky, state.paul]]
// //     }
// // } 

// // export class Merkle_response_bTimeout extends EndTransaction {
// //     static ACTOR = VICKY
// //     static taproot(state){
// //         script! {[ MerkleResponseBTimeoutLeaf, state.vicky, state.paul]]
// //     }
// // } 

fn merkle_hash_a_left_leaf<const MERKLE_INDEX_A: u8>() -> BitVmLeaf {
    BitVmLeaf {
        lock: |model| {
            let round_index_1 = LOG_PATH_LEN as u8 - 1 - trailing_zeros(MERKLE_INDEX_A);
            let round_index_2 = LOG_PATH_LEN as u8 - 1 - trailing_zeros(MERKLE_INDEX_A + 1);
            script! {
                // Verify we're executing the correct leaf
                { model.vicky.push().merkle_index_a() }
                { MERKLE_INDEX_A }
                OP_EQUALVERIFY

                { model.vicky.push().next_merkle_index_a(round_index_1) }
                { MERKLE_INDEX_A }
                OP_EQUALVERIFY


                { model.vicky.push().next_merkle_index_a(round_index_2) }
                { MERKLE_INDEX_A + 1 }
                OP_EQUALVERIFY

                // Read the bit from address to figure out if we have to swap the two nodes before hashing
                // { model.paul.push().address_a_bit_at(PATH_LEN - 1 - merkle_index_a) }
                OP_NOT
                OP_VERIFY

                // Read the child nodes
                { model.paul.push().merkle_response_a(round_index_2) }
                // Hash the child nodes
                blake3_160
                u160_toaltstack
                // Read the parent hash
                { model.paul.push().merkle_response_a(round_index_1) }
                
                u160_fromaltstack
                u160_swap_endian
                u160_equalverify
                OP_TRUE // TODO: verify the covenant here
            }
        },
        unlock: |model| {
            let round_index_1 = LOG_PATH_LEN as u8 - 1 - trailing_zeros(MERKLE_INDEX_A);
            let round_index_2 = LOG_PATH_LEN as u8 - 1 - trailing_zeros(MERKLE_INDEX_A + 1);
            script! {
                { model.paul.unlock().merkle_response_a(round_index_1) }
                { model.paul.unlock().merkle_response_a_sibling(round_index_2) }
                { model.paul.unlock().merkle_response_a(round_index_2) }
                // { model.paul.unlock().address_a_bit_at(PATH_LEN - 1 - merkle_index_a) }
                { model.vicky.unlock().next_merkle_index_a(round_index_2) }
                { model.vicky.unlock().next_merkle_index_a(round_index_1) }
                { model.vicky.unlock().merkle_index_a() }
            }
        }
    }
}

fn merkle_hash_b_left_leaf<const MERKLE_INDEX_B: u8>() -> BitVmLeaf {
    BitVmLeaf {
        lock: |model| {
            let round_index_1 = LOG_PATH_LEN as u8 - 1 - trailing_zeros(MERKLE_INDEX_B);
            let round_index_2 = LOG_PATH_LEN as u8 - 1 - trailing_zeros(MERKLE_INDEX_B + 1);
            script! {
                // Verify we're executing the correct leaf
                { model.vicky.push().merkle_index_b() }
                { MERKLE_INDEX_B }
                OP_EQUALVERIFY

                { model.vicky.push().next_merkle_index_b(round_index_1) }
                { MERKLE_INDEX_B }
                OP_EQUALVERIFY


                { model.vicky.push().next_merkle_index_b(round_index_2) }
                { MERKLE_INDEX_B + 1 }
                OP_EQUALVERIFY

                // Read the bit from address to figure out if we have to swap the two nodes before hashing
                // { paul.push().address_b_bit_at(PATH_LEN - 1 - MERKLE_INDEX_B) }
                OP_NOT
                OP_VERIFY

                // Read the child nodes
                { model.paul.push().merkle_response_b(round_index_2) }
                // Hash the child nodes
                blake3_160
                u160_toaltstack
                // Read the parent hash
                { model.paul.push().merkle_response_b(round_index_1) }
                
                u160_fromaltstack
                u160_swap_endian
                u160_equalverify
                OP_TRUE // TODO: verify the covenant here
            }
        },
        unlock: |model| {
            let round_index_1 = LOG_PATH_LEN as u8 - 1 - trailing_zeros(MERKLE_INDEX_B);
            let round_index_2 = LOG_PATH_LEN as u8 - 1 - trailing_zeros(MERKLE_INDEX_B + 1);
            script! {
                { model.paul.unlock().merkle_response_b(round_index_1) }
                { model.paul.unlock().merkle_response_b_sibling(round_index_2) }
                { model.paul.unlock().merkle_response_b(round_index_2) }
                // { model.paul.unlock().address_b_bit_at(PATH_LEN - 1 - model.merkle_index_b) }
                { model.vicky.unlock().next_merkle_index_b(round_index_2) }
                { model.vicky.unlock().next_merkle_index_b(round_index_1) }
                { model.vicky.unlock().merkle_index_b() }
            }
        }
    }
}

fn merkle_hash_a_right_leaf<const MERKLE_INDEX_A: u8>() -> BitVmLeaf {
    BitVmLeaf {
        lock: |model| {
            let round_index_1 = LOG_PATH_LEN as u8 - 1 - trailing_zeros(MERKLE_INDEX_A);
            let round_index_2 = LOG_PATH_LEN as u8 - 1 - trailing_zeros(MERKLE_INDEX_A + 1);
            script! {
                // Verify we're executing the correct leaf
                { model.vicky.push().merkle_index_a() }
                { MERKLE_INDEX_A }
                OP_EQUALVERIFY

                { model.vicky.push().next_merkle_index_a(round_index_1) }
                { MERKLE_INDEX_A }
                OP_EQUALVERIFY

                { model.vicky.push().next_merkle_index_a(round_index_2) }
                { MERKLE_INDEX_A + 1 }
                OP_EQUALVERIFY

                // Read the bit from address to figure out if we have to swap the two nodes before hashing
                // { paul.push().address_a_bit_at(PATH_LEN - 1 - merkle_index_a) }
                OP_VERIFY

                // Read the child nodes
                u160_toaltstack
                { model.paul.push().merkle_response_a(round_index_2) }
                u160_fromaltstack
                // Hash the child nodes
                blake3_160
                u160_toaltstack
                // Read the parent hash
                { model.paul.push().merkle_response_a(round_index_1) }
                
                u160_fromaltstack
                u160_swap_endian
                u160_equalverify
                OP_TRUE // TODO: verify the covenant here
            }
        },
        unlock: |model| {
            let round_index_1 = LOG_PATH_LEN as u8 - 1 - trailing_zeros(MERKLE_INDEX_A);
            let round_index_2 = LOG_PATH_LEN as u8 - 1 - trailing_zeros(MERKLE_INDEX_A + 1);
            script! {
                { model.paul.unlock().merkle_response_a(round_index_1) }
                { model.paul.unlock().merkle_response_a(round_index_2) }
                { model.paul.unlock().merkle_response_a_sibling(round_index_2) }
                // { model.paul.unlock().address_a_bit_at(PATH_LEN - 1 - merkle_index_a) }
                { model.vicky.unlock().next_merkle_index_a(round_index_2) }
                { model.vicky.unlock().next_merkle_index_a(round_index_1) }
                { model.vicky.unlock().merkle_index_a() }
            }
        }
    }
}

fn merkle_hash_b_right_leaf<const MERKLE_INDEX_B: u8>() -> BitVmLeaf {
    BitVmLeaf {
        lock: |model| {
            let round_index_1 = LOG_PATH_LEN as u8 - 1 - trailing_zeros(MERKLE_INDEX_B);
            let round_index_2 = LOG_PATH_LEN as u8 - 1 - trailing_zeros(MERKLE_INDEX_B + 1);
            script! {
                // Verify we're executing the correct leaf
                { model.vicky.push().merkle_index_b() }
                { MERKLE_INDEX_B }
                OP_EQUALVERIFY

                { model.vicky.push().next_merkle_index_b(round_index_1) }
                { MERKLE_INDEX_B }
                OP_EQUALVERIFY

                { model.vicky.push().next_merkle_index_b(round_index_2) }
                { MERKLE_INDEX_B + 1 }
                OP_EQUALVERIFY

                // Read the bit from address to figure out if we have to swap the two nodes before hashing
                // { model.paul.push().address_b_bit_at(PATH_LEN - 1 - MERKLE_INDEX_B) }
                OP_VERIFY

                // Read the child nodes
                u160_toaltstack
                { model.paul.push().merkle_response_b(round_index_2) }
                u160_fromaltstack
                // Hash the child nodes
                blake3_160
                u160_toaltstack
                // Read the parent hash
                { model.paul.push().merkle_response_b(round_index_1) }
                
                u160_fromaltstack
                u160_swap_endian
                u160_equalverify
                OP_TRUE // TODO: verify the covenant here
            }
        },
        unlock: |model| {
            let round_index_1 = LOG_PATH_LEN as u8 - 1 - trailing_zeros(MERKLE_INDEX_B);
            let round_index_2 = LOG_PATH_LEN as u8 - 1 - trailing_zeros(MERKLE_INDEX_B + 1);
            script! {
                { model.paul.unlock().merkle_response_b(round_index_1) }
                { model.paul.unlock().merkle_response_b(round_index_2) }
                { model.paul.unlock().merkle_response_b_sibling(round_index_2) }
                // { model.paul.unlock().address_b_bit_at(PATH_LEN - 1 - merkle_index_b) }
                { model.vicky.unlock().next_merkle_index_b(round_index_2) }
                { model.vicky.unlock().next_merkle_index_b(round_index_1) }
                { model.vicky.unlock().merkle_index_b() }
            }
        }
    }
}

fn merkle_hash_a_root_left_leaf<const TRACE_ROUND_INDEX: u8>() -> BitVmLeaf {
    BitVmLeaf {
        lock: |model| script! {
            // Verify we're executing the correct leaf
            { model.vicky.push().merkle_index_a() }
            0
            OP_EQUALVERIFY

            { model.vicky.push().trace_index() }
            OP_TOALTSTACK
            { model.vicky.push().next_trace_index(TRACE_ROUND_INDEX) }
            OP_FROMALTSTACK
            OP_EQUALVERIFY

            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            // { model.paul.push().address_a_bit_at(PATH_LEN - 1) }
            OP_NOT
            OP_VERIFY

            // Read the child nodes
            { model.paul.push().merkle_response_a(LOG_PATH_LEN as u8 - 1) }
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
            { model.paul.unlock().merkle_response_a_sibling(LOG_PATH_LEN as u8 - 1) }
            { model.paul.unlock().merkle_response_a(LOG_PATH_LEN as u8 - 1) }
            // { model.paul.unlock().address_a_bit_at(PATH_LEN - 1) }
            { model.vicky.unlock().next_trace_index(TRACE_ROUND_INDEX) }
            { model.vicky.unlock().trace_index() }
            { model.vicky.unlock().merkle_index_a() }
        }
    }
}

fn merkle_hash_b_root_left_leaf<const TRACE_ROUND_INDEX: u8>() -> BitVmLeaf {
    BitVmLeaf {
        lock: |model| script! {
            // Verify we're executing the correct leaf
            { model.vicky.push().merkle_index_b() }
            0
            OP_EQUALVERIFY

            { model.vicky.push().trace_index() }
            OP_TOALTSTACK
            { model.vicky.push().next_trace_index(TRACE_ROUND_INDEX) }
            OP_FROMALTSTACK
            OP_EQUALVERIFY


            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            // { model.paul.push().address_b_bit_at(PATH_LEN - 1) }
            OP_NOT
            OP_VERIFY

            // Read the child nodes
            { model.paul.push().merkle_response_b(LOG_PATH_LEN as u8 - 1) }
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
            { model.paul.unlock().merkle_response_b_sibling(LOG_PATH_LEN as u8 - 1) }
            { model.paul.unlock().merkle_response_b(LOG_PATH_LEN as u8 - 1) }
            // { model.paul.unlock().address_b_bit_at(PATH_LEN - 1) }
            { model.vicky.unlock().next_trace_index(TRACE_ROUND_INDEX) }
            { model.vicky.unlock().trace_index() }
            { model.vicky.unlock().merkle_index_b() }
        }
    }
}

fn merkle_hash_a_root_right_leaf<const TRACE_INDEX: u8>() -> BitVmLeaf {
    BitVmLeaf {
        lock: |model| script! {
            // Verify we're executing the correct leaf
            { model.vicky.push().merkle_index_a() }
            0
            OP_EQUALVERIFY

            { model.vicky.push().trace_index() }
            { TRACE_INDEX }
            OP_EQUALVERIFY

            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            // { model.paul.push().address_a_bit_at(PATH_LEN - 1) }
            OP_VERIFY

            // Read the child nodes
            u160_toaltstack
            { model.paul.push().merkle_response_a(LOG_PATH_LEN as u8 - 1) }
            u160_fromaltstack
            // Hash the child nodes
            blake3_160
            u160_toaltstack
            // Read the parent hash
            { model.paul.push().trace_response(TRACE_INDEX) }
            
            u160_fromaltstack
            u160_swap_endian
            u160_equalverify
            OP_TRUE // TODO: verify the covenant here
        },
        unlock: |model| script! {
            { model.paul.unlock().trace_response(TRACE_INDEX) }
            { model.paul.unlock().merkle_response_a(LOG_PATH_LEN as u8 - 1) }
            { model.paul.unlock().merkle_response_a_sibling(LOG_PATH_LEN as u8 - 1) }
            // { model.paul.unlock().address_a_bit_at(PATH_LEN - 1) }
            { model.vicky.unlock().trace_index() }
            { model.vicky.unlock().merkle_index_a() }
        }
    }
}

fn merkle_hash_b_root_right_leaf<const TRACE_INDEX: u8>() -> BitVmLeaf {
    BitVmLeaf {
        lock: |model| script! {
            // Verify we're executing the correct leaf
            { model.vicky.push().merkle_index_b() }
            0
            OP_EQUALVERIFY

            { model.vicky.push().trace_index() }
            { TRACE_INDEX }
            OP_EQUALVERIFY


            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            // { model.paul.push().address_b_bit_at(PATH_LEN - 1) }
            OP_VERIFY

            // Read the child nodes
            u160_toaltstack
            { model.paul.push().merkle_response_b(LOG_PATH_LEN as u8 - 1) }
            u160_fromaltstack
            // Hash the child nodes
            blake3_160
            u160_toaltstack
            // Read the parent hash
            { model.paul.push().trace_response(TRACE_INDEX) }
            
            u160_fromaltstack
            u160_swap_endian
            u160_equalverify
            OP_TRUE // TODO: verify the covenant here
        },
        unlock: |model| script! {
            { model.paul.unlock().trace_response(TRACE_INDEX) }
            { model.paul.unlock().merkle_response_b(LOG_PATH_LEN as u8 - 1) }
            { model.paul.unlock().merkle_response_b_sibling(LOG_PATH_LEN as u8 - 1) }
            // { model.paul.unlock().address_b_bit_at(PATH_LEN - 1) }
            { model.vicky.unlock().trace_index() }
            { model.vicky.unlock().merkle_index_b() }
        }
    }
}

fn merkle_a_leaf_hash_left_leaf() -> BitVmLeaf {
    BitVmLeaf {
        lock: |model| script! {
            // Verify we're executing the correct leaf
            { model.vicky.push().merkle_index_a() }
            { PATH_LEN - 1 }
            OP_EQUALVERIFY

            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            { model.paul.push().address_a_bit_at(0) }
            OP_NOT
            OP_VERIFY

            // Read valueA
            { model.paul.push().value_a() }
            // Pad with 16 zero bytes
            u32_toaltstack
            { unroll(16, |_| 0) }
            u32_fromaltstack
            // Hash the child nodes
            blake3_160
            u160_toaltstack
            // Read the parent hash
            { model.paul.push().merkle_response_a(LOG_PATH_LEN as u8 - 1) }
            
            u160_fromaltstack
            u160_swap_endian
            u160_equalverify
            OP_TRUE // TODO: verify the covenant here
        },
        unlock: |model| script! {
            { model.paul.unlock().merkle_response_a(LOG_PATH_LEN as u8 - 1) }
            { model.paul.unlock().merkle_response_a_sibling(LOG_PATH_LEN as u8) }
            { model.paul.unlock().value_a() }
            { model.paul.unlock().address_a_bit_at(0) }
            { model.vicky.unlock().merkle_index_a() }
        }
    }
}

fn merkle_b_leaf_hash_left_leaf() -> BitVmLeaf {
    BitVmLeaf {
        lock: |model| script! {
            // Verify we're executing the correct leaf
            { model.vicky.push().merkle_index_b() }
            { PATH_LEN - 1 }
            OP_EQUALVERIFY

            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            { model.paul.push().address_b_bit_at(0) }
            OP_NOT
            OP_VERIFY

            // Read value_b
            { model.paul.push().value_b() }
            // Pad with 16 zero bytes
            u32_toaltstack
            { unroll(16, |_| 0) }
            u32_fromaltstack
            // Hash the child nodes
            blake3_160
            u160_toaltstack
            // Read the parent hash
            { model.paul.push().merkle_response_b(LOG_PATH_LEN as u8 - 1) }
            
            u160_fromaltstack
            u160_swap_endian
            u160_equalverify
            OP_TRUE // TODO: verify the covenant here
        },
        unlock: |model| script! {
            { model.paul.unlock().merkle_response_b(LOG_PATH_LEN as u8 - 1) }
            { model.paul.unlock().merkle_response_b_sibling(LOG_PATH_LEN as u8) }
            { model.paul.unlock().value_b() }
            { model.paul.unlock().address_b_bit_at(0) }
            { model.vicky.unlock().merkle_index_b() }
        }
    }
}


fn merkle_a_leaf_hash_right_leaf() -> BitVmLeaf {
    BitVmLeaf {
        lock: |model| script! {
            // Verify we're executing the correct leaf
            { model.vicky.push().merkle_index_a() }
            { PATH_LEN - 1 }
            OP_EQUALVERIFY

            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            // { model.paul.push().address_a_bit_at(0) }
            OP_VERIFY


            u160_toaltstack
            // Read valueA
            { model.paul.push().value_a() }
            // Pad with 16 zero bytes
            u32_toaltstack
            { unroll(16, |_| 0) }
            u32_fromaltstack
            u160_fromaltstack
            // Hash the child nodes
            blake3_160
            u160_toaltstack
            // Read the parent hash
            { model.paul.push().merkle_response_a(LOG_PATH_LEN as u8 - 1) }
            
            u160_fromaltstack
            u160_swap_endian
            u160_equalverify
            OP_TRUE // TODO: verify the covenant here
        },
        unlock: |model| script! {
            { model.paul.unlock().merkle_response_a(LOG_PATH_LEN as u8 - 1) }
            { model.paul.unlock().value_a() }
            { model.paul.unlock().merkle_response_a_sibling(LOG_PATH_LEN as u8) }
            // { model.paul.unlock().address_a_bit_at(0) }
            { model.vicky.unlock().merkle_index_a() }
        }
    }
}

fn merkle_b_leaf_hash_right_leaf() -> BitVmLeaf {
    BitVmLeaf {
        lock: |model| script! {
            // Verify we're executing the correct leaf
            { model.vicky.push().merkle_index_b() }
            { PATH_LEN - 1 }
            OP_EQUALVERIFY

            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            // { model.paul.push().address_b_bit_at(0) }
            OP_VERIFY


            u160_toaltstack
            // Read value_b
            { model.paul.push().value_b() }
            // Pad with 16 zero bytes
            u32_toaltstack
            { unroll(16, |_| 0) }
            u32_fromaltstack
            u160_fromaltstack
            // Hash the child nodes
            blake3_160
            u160_toaltstack
            // Read the parent hash
            { model.paul.push().merkle_response_b(LOG_PATH_LEN as u8 - 1) }
            
            u160_fromaltstack
            u160_swap_endian
            u160_equalverify
            OP_TRUE // TODO: verify the covenant here
        },
        unlock: |model| script! {
            { model.paul.unlock().merkle_response_b(LOG_PATH_LEN as u8 - 1) }
            { model.paul.unlock().value_b() }
            { model.paul.unlock().merkle_response_b_sibling(LOG_PATH_LEN as u8) }
            // { model.paul.unlock().address_b_bit_at(0) }
            { model.vicky.unlock().merkle_index_b() }
        }
    }
}

// // export class MerkleHashA extends Transaction {
// //     static ACTOR = PAUL
// //     static taproot(model) {
// //         let {&mut self} = model;;
// //         script! {
// //             ...loop(PATH_LEN - 2, merkle_index_a => [MerkleHashALeftLeaf, &mut self + 1]),
// //             ...loop(PATH_LEN - 2, merkle_index_a => [MerkleHashARightLeaf, &mut self + 1]),
// //             ...loop(LOG_TRACE_LEN, traceRoundIndex => [MerkleHashARootLeftLeaf, &mut self, traceRoundIndex]),
// //             ...loop(LOG_TRACE_LEN, traceRoundIndex => [MerkleHashARootRightLeaf, &mut self, traceRoundIndex]),
// //             [MerkleALeafHashLeftLeaf, &mut self],
// //             [MerkleALeafHashRightLeaf, &mut self],
// //         ]
// //     }
// // }

// // export class MerkleHashB extends Transaction {
// //     static ACTOR = PAUL
// //     static taproot(model) {
// //         let {&mut self} = model;;
// //         script! {
// //             ...loop(PATH_LEN - 2, _merkle_index_b => [MerkleHashBLeftLeaf, &mut self, _merkle_index_b + 1]),
// //             ...loop(PATH_LEN - 2, _merkle_index_b => [MerkleHashBRightLeaf, &mut self, _merkle_index_b + 1]),
// //             ...loop(LOG_TRACE_LEN, traceRoundIndex => [MerkleHashBRootLeftLeaf, &mut self, traceRoundIndex]),
// //             ...loop(LOG_TRACE_LEN, traceRoundIndex => [MerkleHashBRootRightLeaf, &mut self, traceRoundIndex]),
// //             [MerkleBLeafHashLeftLeaf, &mut self],
// //             [MerkleBLeafHashRightLeaf, &mut self],
// //         ]
// //     }
// // }

fn merkle_hash_timeout_a_leaf<const TIMEOUT: u32>() -> BitVmLeaf {
    BitVmLeaf {
        lock: |model| script! {
            { TIMEOUT }
            // OP_CHECKSEQUENCEVERIFY
            OP_DROP
            // { self.vicky.pubkey }
            OP_CHECKSIG
        },
        unlock: |model| script! {
            // { self.vicky.sign(this) }
        }
    }
}

fn merkle_hash_timeout_b_leaf<const TIMEOUT: u32>() -> BitVmLeaf {
    BitVmLeaf {
        lock: |model| script! {
            { TIMEOUT }
            // OP_CHECKSEQUENCEVERIFY
            OP_DROP
            // { model.vicky.pubkey }
            OP_CHECKSIG
        },
        unlock: |model| script! { 
            // { model.vicky.sign(this) }
        }
    }
}

// // impl<'a> MerkleHashTimeoutA extends EndTransaction<'a> {
// //     static ACTOR = VICKY
// //     static taproot(state){
// //         script! {[ MerkleHashTimeoutALeaf, state.vicky, state.paul]]
// //     }
// // }

// // impl<'a> MerkleHashTimeoutB extends EndTransaction<'a> {
// //     static ACTOR = VICKY
// //     static taproot(state){
// //         script! {[ MerkleHashTimeoutBLeaf, state.vicky, state.paul]]
// //     }
// // }

// // impl<'a> MerkleEquivocationA extends EndTransaction<'a> {
// //     static ACTOR = VICKY

// //     static taproot(model) {
// //         console.warn(`${this.name} not implemented`)
// //         script! {[ class extends Leaf {
// //             fn lock(){
// //                 script! {'OP_4']
// //             }
// //             fn unlock(){
// //                 script! {]
// //             }
// //         }]]
// //     }
// // }

// // impl<'a> MerkleEquivocationB extends EndTransaction<'a> {
// //     static ACTOR = VICKY

// //     static taproot(model) {
// //         console.warn(`${this.name} not implemented`)
// //         script! {[ class extends Leaf {
// //             fn lock(){
// //                 script! {'OP_4']
// //             }
// //             fn unlock(){
// //                 script! {]
// //             }
// //         }]]
// //     }
// // }

// // impl<'a> MerkleEquivocationTimeoutA extends EndTransaction<'a> {
// //     static ACTOR = PAUL

// //     static taproot(model) {
// //         script! {[ 
// //             class extends TimeoutLeaf { 
// //                 fn lock(&mut self) -> Script {
// //                     script! {
// //                         TIMEOUT
// //                         OP_CHECKSEQUENCEVERIFY
// //                         OP_DROP
// //                         paul.pubkey
// //                         OP_CHECKSIG
// //                     ]
// //                 }

// //                 fn unlock(&mut self) -> Script {
// //                     script! { 
// //                         paul.sign(this) 
// //                     ]
// //                 }
// //             }, 
// //             model.vicky, 
// //             model.paul 
// //         ]]
// //     }
// // }

// // impl<'a> MerkleEquivocationTimeoutB extends EndTransaction<'a> {
// //     static ACTOR = PAUL

// //     static taproot(model) {
// //         script! {[ 
// //             class extends TimeoutLeaf { 
// //                 fn lock(&mut self) -> Script {
// //                     script! {
// //                         TIMEOUT
// //                         OP_CHECKSEQUENCEVERIFY
// //                         OP_DROP
// //                         paul.pubkey
// //                         OP_CHECKSIG
// //                     ]
// //                 }

// //                 fn unlock(&mut self) -> Script {
// //                     script! { 
// //                         paul.sign(this) 
// //                     ]
// //                 }
// //             }, 
// //             model.vicky, 
// //             model.paul 
// //         ]]
// //     }
// // }
