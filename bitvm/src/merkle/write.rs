use crate::scripts::{opcodes::pushable, transaction::Leaf, transaction::LeafGetters};
use bitcoin_script::bitcoin_script as script;
use bitcoin::blockdata::script::ScriptBuf as Script;
use bitvm_macros::LeafGetters;
use bitcoin::opcodes::OP_TRUE;
use crate::scripts::opcodes::blake3::blake3_160;
use crate::scripts::opcodes::{
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
use crate::bitvm::model::{Paul, Vicky};
use crate::bitvm::constants::{PATH_LEN, LOG_PATH_LEN};



#[derive(LeafGetters)]
pub struct MerkleChallengeCStartPrevLeaf<'a> {
    pub paul: &'a mut dyn Paul,
    pub vicky: &'a mut dyn Vicky,
    pub round_index: u8
}

impl Leaf for MerkleChallengeCStartPrevLeaf<'_> {

    fn lock(&mut self) -> Script {
        script! {
            // {self.vicky.pubkey}
            // OP_CHECKSIGVERIFY
            // {self.paul.pubkey}
            OP_CHECKSIG
        }
    }

    fn unlock(&mut self) -> Script {
        script! {
            // {self.paul.sign(this), // TODO}
            // {self.vicky.sign(this)}
        }
    }
}


// export class MerkleChallengeCStartPrev extends Transaction {
//     static ACTOR = VICKY
//     static taproot(params) {
//         script! {
//             [MerkleChallengeCStartPrevLeaf, params.vicky, params.paul]
//         ]
//     }
// }


#[derive(LeafGetters)]
pub struct MerkleChallengeCPrevLeaf<'a> {
    pub paul: &'a mut dyn Paul,
    pub vicky: &'a mut dyn Vicky,
    pub round_index: u8
}

impl Leaf for MerkleChallengeCPrevLeaf<'_> {

    fn lock(&mut self) -> Script {
        script! {
            {self.vicky.commit().merkle_challenge_c_prev(self.round_index, self.faulty_index)}
            // {self.vicky.pubkey}
            // OP_CHECKSIGVERIFY
            // {self.paul.pubkey}
            // OP_CHECKSIG
            {OP_TRUE}
        }
    }

    fn unlock(&mut self) -> Script {
        script! {
            // {self.paul.sign(this), // TODO}
            // {self.vicky.sign(this)}
            {self.vicky.unlock().merkle_challenge_c_prev(self.round_index, self.faulty_index)}
        }
    }
}

// export class MerkleChallengeCPrev extends Transaction {
//     static ACTOR = VICKY
//     static taproot(params) {
//         script! {
//             [MerkleChallengeCPrevLeaf, params.vicky, params.paul, this.ROUND, this.INDEX]
//         ]
//     }
// }

#[derive(LeafGetters)]
pub struct Merkle_response_c_prevLeaf<'a> {
    pub paul: &'a mut dyn Paul,
    pub vicky: &'a mut dyn Vicky,
    pub round_index: u8,
    pub faulty_index: u8
}

impl Leaf for Merkle_response_c_prevLeaf<'_> {

    fn lock(&mut self) -> Script {
        script! {
            {self.paul.commit().merkle_response_c_prev(self.round_index, self.faulty_index)}
            // {self.vicky.pubkey}
            // OP_CHECKSIGVERIFY
            // {self.paul.pubkey}
            // OP_CHECKSIG
            {OP_TRUE}
        }
    }

    fn unlock(&mut self) -> Script {
        script! {
            // {self.paul.sign(this)}
            // {self.vicky.sign(this)}
            {self.paul.unlock().merkle_response_c_prev(self.round_index, self.faulty_index)}
        }
    }
}


// export class Merkle_response_c_prev extends Transaction {
//     static ACTOR = PAUL
//     static taproot(params) {
//         script! {
//             [Merkle_response_c_prevLeaf, params.vicky, params.paul, this.ROUND, this.INDEX]
//         ]
//     }
// }



#[derive(LeafGetters)]
pub struct MerkleHashCPrevNodeLeftLeaf<'a> {
    pub paul: &'a mut dyn Paul,
    pub vicky: &'a mut dyn Vicky,
    pub merkle_index_c: u8
}

impl Leaf for MerkleHashCPrevNodeLeftLeaf<'_> {

    fn lock(&mut self) -> Script {
        let round_index1 = LOG_PATH_LEN - 1 - trailingZeros(self.merkle_index_c);
        let round_index2 = LOG_PATH_LEN - 1 - trailingZeros(self.merkle_index_c + 1);
        script! {
            // Verify we're executing the correct leaf
            {self.vicky.push().merkle_index_c()}
            {self.merkle_index_c()}
            OP_EQUALVERIFY

            {self.vicky.push().next_merkle_index_c_prev(self.round_index1)}
            {self.merkle_index_c()}
            OP_EQUALVERIFY


            {self.vicky.push().next_merkle_index_c_prev(self.round_index2)}
            {self.merkle_index_c + 1}
            OP_EQUALVERIFY

            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            {self.paul.push().address_c_bit_at(PATH_LEN - 1 - self.merkle_index_c)}
            OP_NOT
            OP_VERIFY

            // Read the child nodes
            {self.paul.push().merkle_response_c_prev(self.round_index2)}
            // Hash the child nodes
            blake3_160
            u160_toaltstack
            // Read the parent hash
            {self.paul.push().merkle_response_c_prev(self.round_index1)}
            
            u160_fromaltstack
            u160_swap_endian
            u160_equalverify
            {OP_TRUE} // TODO: verify the covenant here
        }
    }

    fn unlock(&mut self) -> Script {
        let round_index1 = LOG_PATH_LEN - 1 - trailingZeros(self.merkle_index_c);
        let round_index2 = LOG_PATH_LEN - 1 - trailingZeros(self.merkle_index_c + 1);
        script! {
            {self.paul.unlock().merkle_response_c_prev(self.round_index1)}
            {self.paul.unlock().merkle_response_c_prev_sibling(self.round_index2)}
            {self.paul.unlock().merkle_response_c_prev(self.round_index2)}
            {self.paul.unlock().address_c_bit_at(PATH_LEN - 1 - self.merkle_index_c)}
            {self.vicky.unlock().next_merkle_index_c_prev(self.round_index2)}
            {self.vicky.unlock().next_merkle_index_c_prev(self.round_index1)}
            {self.vicky.unlock().merkle_index_c()}
        }
    }
}



#[derive(LeafGetters)]
pub struct MerkleHashCPrevNodeRightLeaf<'a> {
    pub paul: &'a mut dyn Paul,
    pub vicky: &'a mut dyn Vicky,
    pub round_index: u8,
    pub merkle_index_c: u8
}

impl Leaf for MerkleHashCPrevNodeRightLeaf<'_> {

    fn lock(&mut self) -> Script {
        let round_index1 = LOG_PATH_LEN - 1 - trailingZeros(self.merkle_index_c);
        let round_index2 = LOG_PATH_LEN - 1 - trailingZeros(self.merkle_index_c + 1);
        script! {
            // Verify we're executing the correct leaf
            {self.vicky.push().merkle_index_c()}
            {self.merkle_index_c}
            OP_EQUALVERIFY

            {self.vicky.push().next_merkle_index_c_prev(self.round_index1)}
            {self.merkle_index_c}
            OP_EQUALVERIFY

            {self.vicky.push().next_merkle_index_c_prev(self.round_index2)}
            {self.merkle_index_c + 1}
            OP_EQUALVERIFY

            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            {self.paul.push().address_c_bit_at(PATH_LEN - 1 - self.merkle_index_c)}
            OP_VERIFY

            // Read the child nodes
            u160_toaltstack
            {self.paul.push().merkle_response_c_prev(self.round_index2)}
            u160_fromaltstack
            // Hash the child nodes
            blake3_160
            u160_toaltstack
            // Read the parent hash
            {self.paul.push().merkle_response_c_prev(self.round_index1)}
            
            u160_fromaltstack
            u160_swap_endian
            u160_equalverify
            {OP_TRUE} // TODO: verify the covenant here
        }
    }

    fn unlock(&mut self) -> Script {
        let round_index1 = LOG_PATH_LEN - 1 - trailingZeros(self.merkle_index_c);
        let round_index2 = LOG_PATH_LEN - 1 - trailingZeros(self.merkle_index_c + 1);
        script! {
            {self.paul.unlock().merkle_response_c_prev(self.round_index1)}
            {self.paul.unlock().merkle_response_c_prev(self.round_index2)}
            {self.paul.unlock().merkle_response_c_prev_sibling(self.round_index2)}
            {self.paul.unlock().address_c_bit_at(PATH_LEN - 1 - self.merkle_index_c)}
            {self.vicky.unlock().next_merkle_index_c_prev(self.round_index2)}
            {self.vicky.unlock().next_merkle_index_c_prev(self.round_index1)}
            {self.vicky.unlock().merkle_index_c()}
        }
    }
}

#[derive(LeafGetters)]
pub struct MerkleHashCPrevRootLeftLeaf<'a> {
    pub paul: &'a mut dyn Paul,
    pub vicky: &'a mut dyn Vicky,
    pub round_index: u8,
    trace_round_index: u8
}

impl Leaf for MerkleHashCPrevRootLeftLeaf<'_> {

    fn lock(&mut self) -> Script {
        script! {
            // Verify we're executing the correct leaf
            {self.vicky.push().merkle_index_c()}
            0
            OP_EQUALVERIFY

            {self.vicky.push().trace_index()}
            OP_TOALTSTACK
            {self.vicky.push().next_trace_index(self.trace_round_index)}
            OP_FROMALTSTACK
            OP_EQUALVERIFY

            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            {self.paul.push().address_c_bit_at(((PATH_LEN -) as u8 1) as u8)}
            OP_NOT
            OP_VERIFY

            // Read the child nodes
            {self.paul.push().merkle_response_c_prev(((LOG_PATH_LEN - 1) as u8) as u8)}
            // Hash the child nodes
            blake3_160
            u160_toaltstack
            // Read the parent hash
            {self.paul.push().trace_response(self.trace_round_index)}
            
            u160_fromaltstack
            u160_swap_endian
            u160_equalverify
            
            {OP_TRUE} // TODO: verify the covenant here
        }
    }

    fn unlock(&mut self) -> Script {
        script! {
            {self.paul.unlock().trace_response(self.trace_round_index)}
            {self.paul.unlock().merkle_response_c_prev_sibling((LOG_PATH_LEN - 1) as u8)}
            {self.paul.unlock().merkle_response_c_prev((LOG_PATH_LEN - 1) as u8)}
            {self.paul.unlock().address_c_bit_at((PATH_LEN - 1) as u8)}
            {self.vicky.unlock().next_trace_index(self.trace_round_index)}
            {self.vicky.unlock().trace_index()}
            {self.vicky.unlock().merkle_index_c()}
        }
    }
}



#[derive(LeafGetters)]
pub struct MerkleHashCPrevRootRightLeaf<'a> {
    pub paul: &'a mut dyn Paul,
    pub vicky: &'a mut dyn Vicky,
    pub round_index: u8,
    pub trace_index: u8
}

impl Leaf for MerkleHashCPrevRootRightLeaf<'_> {

    fn lock(&mut self) -> Script {
        script! {
            // Verify we're executing the correct leaf
            {self.vicky.push().merkle_index_c()}
            0
            OP_EQUALVERIFY

            {self.vicky.push().trace_index()}
            {self.trace_index}
            OP_EQUALVERIFY


            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            {self.paul.push().address_c_bit_at((PATH_LEN - 1) as u8)}
            OP_VERIFY

            // Read the child nodes
            u160_toaltstack
            {self.paul.push().merkle_response_c_prev((LOG_PATH_LEN - 1) as u8)}
            u160_fromaltstack
            // Hash the child nodes
            blake3_160
            u160_toaltstack
            // Read the parent hash
            {self.paul.push().trace_response(self.trace_index)}
            
            u160_fromaltstack
            u160_swap_endian
            u160_equalverify
            {OP_TRUE} // TODO: verify the covenant here
        }
    }

    fn unlock(&mut self) -> Script {
        script! {
            {self.paul.unlock().trace_response(self.trace_index)}
            {self.paul.unlock().merkle_response_c_prev((LOG_PATH_LEN - 1) as u8)}
            {self.paul.unlock().merkle_response_c_prev_sibling((LOG_PATH_LEN - 1) as u8)}
            {self.paul.unlock().address_c_bit_at((PATH_LEN - 1) as u8)}
            {self.vicky.unlock().trace_index()}
            {self.vicky.unlock().merkle_index_c()}
        }
    }
}




#[derive(LeafGetters)]
pub struct MerkleHashCPrevSiblingLeftLeaf<'a> {
    pub paul: &'a mut dyn Paul,
    pub vicky: &'a mut dyn Vicky,
    pub round_index: u8,
    pub sibling_index: u8
}

impl Leaf for MerkleHashCPrevSiblingLeftLeaf<'_> {

    fn lock(&mut self) -> Script {
        script! {
            // Verify we're executing the correct leaf
            {self.vicky.push().merkle_index_c()}
            {PATH_LEN - 1}
            OP_EQUALVERIFY

            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            {self.paul.push().address_c_bit_at(self.sibling_index)}
            OP_VERIFY

            // Read valueC
            {self.paul.push().value_c()}
            // Pad with 16 zero bytes
            u32_toaltstack
            {unroll(16, |_| script!{0})}
            u32_fromaltstack
            // Hash the child nodes
            blake3_160
            u160_toaltstack
            // Read the parent hash
            {self.paul.push().merkle_response_c_prev((LOG_PATH_LEN - 1) as u8)}
            
            u160_fromaltstack
            u160_swap_endian
            u160_equalverify
            {OP_TRUE} // TODO: verify the covenant here
        }
    }

    fn unlock(&mut self) -> Script {
        script! {
            {self.paul.unlock().merkle_response_c_prev((LOG_PATH_LEN - 1) as u8)}
            {self.paul.unlock().merkle_response_c_prev_sibling(LOG_PATH_LEN as u8)}
            {self.paul.unlock().value_c()}
            {self.paul.unlock().address_c_bit_at(self.sibling_index)}
            {self.vicky.unlock().merkle_index_c()}
        }
    }
}

#[derive(LeafGetters)]
pub struct MerkleHashCPrevSiblingRightLeaf<'a> {
    pub paul: &'a mut dyn Paul,
    pub vicky: &'a mut dyn Vicky,
    pub round_index: u8,
    pub sibling_index: u8
}

impl Leaf for MerkleHashCPrevSiblingRightLeaf<'_> {

    fn lock(&mut self) -> Script {
        script! {
            // Verify we're executing the correct leaf
            {self.vicky.push().merkle_index_c()}
            {PATH_LEN - 1}
            OP_EQUALVERIFY

            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            {self.paul.push().address_c_bit_at(self.sibling_index)}
            OP_NOT
            OP_VERIFY


            u160_toaltstack
            // Read valueC
            {self.paul.push().value_c()}
            // Pad with 16 zero bytes
            u32_toaltstack
            {unroll(16, |_| script!{0})}
            u32_fromaltstack
            u160_fromaltstack
            // Hash the child nodes
            blake3_160
            u160_toaltstack
            // Read the parent hash
            {self.paul.push().merkle_response_c_prev((LOG_PATH_LEN - 1) as u8)}
            
            u160_fromaltstack
            u160_swap_endian
            u160_equalverify
            {OP_TRUE} // TODO: verify the covenant here
        }
    }

    fn unlock(&mut self) -> Script {
        script! {
            {self.paul.unlock().merkle_response_c_prev((LOG_PATH_LEN - 1) as u8)}
            {self.paul.unlock().value_c()}
            {self.paul.unlock().merkle_response_c_prev_sibling(LOG_PATH_LEN as u8)}
            {self.paul.unlock().address_c_bit_at(self.sibling_index)}
            {self.vicky.unlock().merkle_index_c()}
        }
    }
}



// export class MerkleHashCPrev extends Transaction {
//     static ACTOR = PAUL
//     static taproot(params) {
//         const {vicky, paul} = params;
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

//     static taproot(params) {
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
 


