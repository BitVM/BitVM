use crate::constants::{LOG_PATH_LEN, PATH_LEN};
use crate::graph::BitVmLeaf;
use bitcoin_script::bitcoin_script as script;
use tapscripts::opcodes::blake3::blake3_160;
use tapscripts::opcodes::pushable;
use tapscripts::opcodes::{
    u160_std::{u160_equalverify, u160_fromaltstack, u160_swap_endian, u160_toaltstack},
    u32_std::{u32_fromaltstack, u32_toaltstack},
    unroll,
};

pub fn to_round_index(uint: u8) -> u8 {
    ( LOG_PATH_LEN - 1 - uint.trailing_zeros() ) as u8
}

pub fn merkle_challenge_cstart_prev() -> Vec<BitVmLeaf> {
    vec![BitVmLeaf {
        lock: |model| {
            script! {
                // {model.vicky.pubkey}
                // OP_CHECKSIGVERIFY
                // {model.paul.pubkey}
                OP_CHECKSIG
            }
        },

        unlock: |model| {
            script! {
                // {model.paul.sign(this), // TODO}
                // {model.vicky.sign(this)}
            }
        },
    }]
}

pub fn merkle_challenge_c_prev_leaf<const ROUND_INDEX: u8>() -> BitVmLeaf {
    BitVmLeaf {
        lock: |model| {
            script! {
                {model.vicky.commit().merkle_challenge_c_prev(ROUND_INDEX)} // faulty_index
                // {model.vicky.pubkey}
                // OP_CHECKSIGVERIFY
                // {model.paul.pubkey}
                // OP_CHECKSIG
                OP_TRUE
            }
        },

        unlock: |model| {
            script! {
                // {model.paul.sign(this)}
                // {model.vicky.sign(this)}
                {model.vicky.unlock().merkle_challenge_c_prev(ROUND_INDEX)} // faulty_index
            }
        },
    }
}

// export class MerkleChallengeCPrev extends Transaction {
//     static ACTOR = VICKY
//     static taproot(model) {
//         script! {
//             [MerkleChallengeCPrevLeaf, model.vicky, model.paul, this.ROUND, this.INDEX]
//         ]
//     }
// }

pub fn merkle_response_c_prev_leaf<const ROUND_INDEX: u8>() -> BitVmLeaf {
    BitVmLeaf {
        lock: |model| {
            script! {
                {model.paul.commit().merkle_response_c_prev(ROUND_INDEX)} // faulty_index
                // {model.vicky.pubkey}
                // OP_CHECKSIGVERIFY
                // {model.paul.pubkey}
                // OP_CHECKSIG
                OP_TRUE
            }
        },

        unlock: |model| {
            script! {
                // {model.paul.sign(this)}
                // {model.vicky.sign(this)}
                {model.paul.unlock().merkle_response_c_prev(ROUND_INDEX)} // faulty_index
            }
        },
    }
}

// export class Merkle_response_c_prev extends Transaction {
//     static ACTOR = PAUL
//     static taproot(model) {
//         script! {
//             [MerkleResponseCPrevLeaf, model.vicky, model.paul, this.ROUND, this.INDEX]
//         ]
//     }
// }

pub fn merkle_hash_cprev_node_left_leaf<const SIBLING_INDEX: u8, const MERKLE_INDEX_C: u8>() -> BitVmLeaf
{
    BitVmLeaf {
        lock: |model| {
            let round_index1 = to_round_index(MERKLE_INDEX_C);
            let round_index2 = to_round_index(MERKLE_INDEX_C + 1);
            script! {
                // Verify we're executing the correct leaf
                {model.vicky.push().merkle_index_c_prev()}
                {MERKLE_INDEX_C}
                OP_EQUALVERIFY

                {model.vicky.push().next_merkle_index_c_prev(round_index1)}
                {MERKLE_INDEX_C}
                OP_EQUALVERIFY


                {model.vicky.push().next_merkle_index_c_prev(round_index2)}
                {MERKLE_INDEX_C + 1}
                OP_EQUALVERIFY

                // Read the bit from address to figure out if we have to swap the two nodes before hashing
                {model.paul.push().address_c_bit_at(PATH_LEN as u8 - 1 - MERKLE_INDEX_C)}
                OP_NOT
                OP_VERIFY

                // Read the child nodes
                {model.paul.push().merkle_response_c_prev(round_index2)}
                // Hash the child nodes
                blake3_160
                u160_toaltstack
                // Read the parent hash
                {model.paul.push().merkle_response_c_prev(round_index1)}

                u160_fromaltstack
                u160_swap_endian
                u160_equalverify
                OP_TRUE // TODO: verify the covenant here
            }
        },

        unlock: |model| {
            let round_index1 = to_round_index(MERKLE_INDEX_C);
            let round_index2 = to_round_index(MERKLE_INDEX_C + 1);
            script! {
                {model.paul.unlock().merkle_response_c_prev(round_index1)}
                {model.paul.unlock().merkle_response_c_prev_sibling(round_index2)}
                {model.paul.unlock().merkle_response_c_prev(round_index2)}
                {model.paul.unlock().address_c_bit_at(PATH_LEN as u8 - 1 - MERKLE_INDEX_C)}
                {model.vicky.unlock().next_merkle_index_c_prev(round_index2)}
                {model.vicky.unlock().next_merkle_index_c_prev(round_index1)}
                {model.vicky.unlock().merkle_index_c_prev()}
            }
        },
    }
}

pub fn merkle_hash_cprev_node_right_leaf<const SIBLING_INDEX: u8, const MERKLE_INDEX_C: u8>(
) -> BitVmLeaf {
    BitVmLeaf {
        lock: |model| {
            let round_index1 = to_round_index(MERKLE_INDEX_C);
            let round_index2 = to_round_index(MERKLE_INDEX_C + 1);
            script! {
                // Verify we're executing the correct leaf
                {model.vicky.push().merkle_index_c_prev()}
                {MERKLE_INDEX_C}
                OP_EQUALVERIFY

                {model.vicky.push().next_merkle_index_c_prev(round_index1)}
                {MERKLE_INDEX_C}
                OP_EQUALVERIFY

                {model.vicky.push().next_merkle_index_c_prev(round_index2)}
                {MERKLE_INDEX_C + 1}
                OP_EQUALVERIFY

                // Read the bit from address to figure out if we have to swap the two nodes before hashing
                {model.paul.push().address_c_bit_at(PATH_LEN as u8 - 1 - MERKLE_INDEX_C)}
                OP_VERIFY

                // Read the child nodes
                u160_toaltstack
                {model.paul.push().merkle_response_c_prev(round_index2)}
                u160_fromaltstack
                // Hash the child nodes
                blake3_160
                u160_toaltstack
                // Read the parent hash
                {model.paul.push().merkle_response_c_prev(round_index1)}

                u160_fromaltstack
                u160_swap_endian
                u160_equalverify
                OP_TRUE // TODO: verify the covenant here
            }
        },

        unlock: |model| {
            let round_index1 = to_round_index(MERKLE_INDEX_C);
            let round_index2 = to_round_index(MERKLE_INDEX_C + 1);
            script! {
                {model.paul.unlock().merkle_response_c_prev(round_index1)}
                {model.paul.unlock().merkle_response_c_prev(round_index2)}
                {model.paul.unlock().merkle_response_c_prev_sibling(round_index2)}
                {model.paul.unlock().address_c_bit_at(PATH_LEN as u8 - 1 - MERKLE_INDEX_C)}
                {model.vicky.unlock().next_merkle_index_c_prev(round_index2)}
                {model.vicky.unlock().next_merkle_index_c_prev(round_index1)}
                {model.vicky.unlock().merkle_index_c_prev()}
            }
        },
    }
}

pub fn merkle_hash_cprev_root_left_leaf<const TRACE_ROUND_INDEX: u8>() -> BitVmLeaf {
    BitVmLeaf {
        lock: |model| {
            script! {
                // Verify we're executing the correct leaf
                {model.vicky.push().merkle_index_c_prev()}
                0
                OP_EQUALVERIFY

                {model.vicky.push().trace_index()}
                OP_TOALTSTACK
                {model.vicky.push().next_trace_index(TRACE_ROUND_INDEX)}
                OP_FROMALTSTACK
                OP_EQUALVERIFY

                // Read the bit from address to figure out if we have to swap the two nodes before hashing
                {model.paul.push().address_c_bit_at(PATH_LEN as u8 - 1)}
                OP_NOT
                OP_VERIFY

                // Read the child nodes
                {model.paul.push().merkle_response_c_prev(LOG_PATH_LEN  as u8 - 1)}
                // Hash the child nodes
                blake3_160
                u160_toaltstack
                // Read the parent hash
                {model.paul.push().trace_response(TRACE_ROUND_INDEX)}

                u160_fromaltstack
                u160_swap_endian
                u160_equalverify

                OP_TRUE // TODO: verify the covenant here
            }
        },

        unlock: |model| {
            script! {
                {model.paul.unlock().trace_response(TRACE_ROUND_INDEX)}
                {model.paul.unlock().merkle_response_c_prev_sibling((LOG_PATH_LEN - 1) as u8)}
                {model.paul.unlock().merkle_response_c_prev((LOG_PATH_LEN - 1) as u8)}
                {model.paul.unlock().address_c_bit_at(PATH_LEN as u8 - 1)}
                {model.vicky.unlock().next_trace_index(TRACE_ROUND_INDEX)}
                {model.vicky.unlock().trace_index()}
                {model.vicky.unlock().merkle_index_c_prev()}
            }
        },
    }
}

pub fn merkle_hash_cprev_root_right_leaf<const TRACE_INDEX: u8>() -> BitVmLeaf {
    BitVmLeaf {
        lock: |model| {
            script! {
                // Verify we're executing the correct leaf
                {model.vicky.push().merkle_index_c_prev()}
                0
                OP_EQUALVERIFY

                {model.vicky.push().trace_index()}
                {TRACE_INDEX}
                OP_EQUALVERIFY


                // Read the bit from address to figure out if we have to swap the two nodes before hashing
                {model.paul.push().address_c_bit_at(PATH_LEN as u8 - 1)}
                OP_VERIFY

                // Read the child nodes
                u160_toaltstack
                {model.paul.push().merkle_response_c_prev((LOG_PATH_LEN - 1) as u8)}
                u160_fromaltstack
                // Hash the child nodes
                blake3_160
                u160_toaltstack
                // Read the parent hash
                {model.paul.push().trace_response(TRACE_INDEX)}

                u160_fromaltstack
                u160_swap_endian
                u160_equalverify
                OP_TRUE // TODO: verify the covenant here
            }
        },

        unlock: |model| {
            script! {
                {model.paul.unlock().trace_response(TRACE_INDEX)}
                {model.paul.unlock().merkle_response_c_prev((LOG_PATH_LEN - 1) as u8)}
                {model.paul.unlock().merkle_response_c_prev_sibling((LOG_PATH_LEN - 1) as u8)}
                {model.paul.unlock().address_c_bit_at(PATH_LEN as u8 - 1)}
                {model.vicky.unlock().trace_index()}
                {model.vicky.unlock().merkle_index_c_prev()}
            }
        },
    }
}

pub fn merkle_hash_cprev_sibling_left_leaf<const SIBLING_INDEX: u8>() -> BitVmLeaf {
    BitVmLeaf {
        lock: |model| {
            script! {
                // Verify we're executing the correct leaf
                {model.vicky.push().merkle_index_c_prev()}
                {PATH_LEN - 1}
                OP_EQUALVERIFY

                // Read the bit from address to figure out if we have to swap the two nodes before hashing
                {model.paul.push().address_c_bit_at(SIBLING_INDEX)}
                OP_VERIFY

                // Read valueC
                {model.paul.push().value_c()}
                // Pad with 16 zero bytes
                u32_toaltstack
                {unroll(16, |_| script!{0})}
                u32_fromaltstack
                // Hash the child nodes
                blake3_160
                u160_toaltstack
                // Read the parent hash
                {model.paul.push().merkle_response_c_prev((LOG_PATH_LEN - 1) as u8)}

                u160_fromaltstack
                u160_swap_endian
                u160_equalverify
                OP_TRUE // TODO: verify the covenant here
            }
        },

        unlock: |model| {
            script! {
                {model.paul.unlock().merkle_response_c_prev((LOG_PATH_LEN - 1) as u8)}
                {model.paul.unlock().merkle_response_c_prev_sibling(LOG_PATH_LEN as u8)}
                {model.paul.unlock().value_c()}
                {model.paul.unlock().address_c_bit_at(SIBLING_INDEX)}
                {model.vicky.unlock().merkle_index_c_prev()}
            }
        },
    }
}

pub fn merkle_hash_cprev_sibling_right_leaf<const SIBLING_INDEX: u8>() -> BitVmLeaf {
    BitVmLeaf {
        lock: |model| {
            script! {
                // Verify we're executing the correct leaf
                {model.vicky.push().merkle_index_c_prev()}
                {PATH_LEN - 1}
                OP_EQUALVERIFY

                // Read the bit from address to figure out if we have to swap the two nodes before hashing
                {model.paul.push().address_c_bit_at(SIBLING_INDEX)}
                OP_NOT
                OP_VERIFY


                u160_toaltstack
                // Read valueC
                {model.paul.push().value_c()}
                // Pad with 16 zero bytes
                u32_toaltstack
                {unroll(16, |_| script!{0})}
                u32_fromaltstack
                u160_fromaltstack
                // Hash the child nodes
                blake3_160
                u160_toaltstack
                // Read the parent hash
                {model.paul.push().merkle_response_c_prev((LOG_PATH_LEN - 1) as u8)}

                u160_fromaltstack
                u160_swap_endian
                u160_equalverify
                OP_TRUE // TODO: verify the covenant here
            }
        },

        unlock: |model| {
            script! {
                {model.paul.unlock().merkle_response_c_prev((LOG_PATH_LEN - 1) as u8)}
                {model.paul.unlock().value_c()}
                {model.paul.unlock().merkle_response_c_prev_sibling(LOG_PATH_LEN as u8)}
                {model.paul.unlock().address_c_bit_at(SIBLING_INDEX)}
                {model.vicky.unlock().merkle_index_c_prev()}
            }
        },
    }
}

// export class MerkleHashCPrev extends Transaction {
//     static ACTOR = PAUL
//     static taproot(model) {
//         const {vicky, paul} = model;
//         script! {
//             ...loop(PATH_LEN - 2, merkle_index_c => [MerkleHashCPrevNodeLeftLeaf, vicky, paul, merkle_index_c + 1])
//             ...loop(PATH_LEN - 2, merkle_index_c => [MerkleHashCPrevNodeRightLeaf, vicky, paul, merkle_index_c + 1])
//             ...loop(LOG_TRACE_LEN, trace_indexRound => [MerkleHashCPrevRootLeftLeaf, vicky, paul, trace_indexRound])
//             ...loop(LOG_TRACE_LEN, trace_indexRound => [MerkleHashCPrevRootRightLeaf, vicky, paul, trace_indexRound])
//             [MerkleHashCPrevSiblingLeftLeaf, vicky, paul, this.INDEX]
//             [MerkleHashCPrevSiblingRightLeaf, vicky, paul, this.INDEX]
//         ]
//     }
// }

// export class MerkleEquivocationCPrev extends EndTransaction {
//     static ACTOR = VICKY

//     static taproot(model) {
//         console.warn(`${this.name} not implemented`)
//         return [[ class extends Leaf {
//             lock(){
//                 return ['OP_4']
//             }
//             unlock(){
//                 return []
//             }
//         }]]
//     }
// }
