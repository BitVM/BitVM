use scripts::{opcodes::pushable, leaf::Leaf, leaf::LeafGetters};
use bitcoin_script::bitcoin_script as script;
use bitcoin::blockdata::script::ScriptBuf as Script;
use bitvm_macros::LeafGetters;
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
use crate::model::{Paul, Vicky};
use crate::constants::{PATH_LEN, LOG_PATH_LEN};

fn trailing_zeros(uint: u32) -> u8 {
    uint.trailing_zeros() as u8
}

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

#[derive(LeafGetters)]
pub struct MerkleChallengeBLeaf<'a> {
    pub paul: &'a mut dyn Paul,
    pub vicky: &'a mut dyn Vicky,
    pub round_index: u8
}

impl Leaf for MerkleChallengeBLeaf<'_> {

    fn lock(&mut self) -> Script {
        script! {
            { self.vicky.commit().merkle_challenge_b(self.round_index) }
            // vicky.pubkey,
            // OP_CHECKSIGVERIFY,
            // paul.pubkey,
            OP_CHECKSIG
        }
    }

    fn unlock(&mut self) -> Script {
        assert!(self.vicky.is_faulty_read_b());
        script! {
            // paul.sign(this), // TODO
            // vicky.sign(this), 
            { self.vicky.unlock().merkle_challenge_b(self.round_index) }
        }
    }
}

// impl Transaction for MerkleChallengeA {
//     static ACTOR = VICKY
//     static taproot(params) {
//         script! {
//             [MerkleChallengeALeaf, params.vicky, params.paul, this.INDEX]
//         ]
//     }
// }

// impl Transaction for MerkleChallengeB {
//     static ACTOR = VICKY
//     static taproot(params) {
//         script! {
//             [MerkleChallengeBLeaf, params.vicky, params.paul, this.INDEX]
//         ]
//     }
// }

#[derive(LeafGetters)]
pub struct MerkleChallengeATimeoutLeaf<'a> {
    pub paul: &'a mut dyn Paul,
    pub vicky: &'a mut dyn Vicky,
    pub timeout: u32
}

impl<'a> Leaf for MerkleChallengeATimeoutLeaf<'a> { 

    fn lock(&mut self) -> Script {
        script! {
            { self.timeout }
            // OP_CHECKSEQUENCEVERIFY
            OP_DROP
            // paul.pubkey
            OP_CHECKSIG
        }
    }

    fn unlock(&mut self) -> Script {
        script! {
            // paul.sign(this), 
        }
    }
}

#[derive(LeafGetters)]
pub struct MerkleChallengeBTimeoutLeaf<'a> {
    pub paul: &'a mut dyn Paul,
    pub vicky: &'a mut dyn Vicky,
    timeout: u32
}

impl<'a> Leaf for MerkleChallengeBTimeoutLeaf<'a> { 

    fn lock(&mut self) -> Script {
        script! {
            { self.timeout }
            // OP_CHECKSEQUENCEVERIFY
            OP_DROP
            // paul.pubkey
            OP_CHECKSIG
        }
    }

    fn unlock(&mut self) -> Script {
        script! {
            // paul.sign(this), 
        }
    }
}

// export class MerkleChallengeATimeout extends EndTransaction {
//     static ACTOR = PAUL
//     static taproot(state){
//         script! {[ MerkleChallengeATimeoutLeaf, state.vicky, state.paul]]
//     }
// }

// export class MerkleChallengeBTimeout extends EndTransaction {
//     static ACTOR = PAUL
//     static taproot(state){
//         script! {[ MerkleChallengeBTimeoutLeaf, state.vicky, state.paul]]
//     }
// } 

#[derive(LeafGetters)]
pub struct MerkleResponseALeaf<'a> {
    pub paul: &'a mut dyn Paul,
    pub vicky: &'a mut dyn Vicky,
    pub round_index: u8
}

impl<'a> Leaf for MerkleResponseALeaf<'a> { 

    fn lock(&mut self) -> Script {
        script! {
            { self.paul.commit().merkle_response_a(self.round_index) }
            // vicky.pubkey
            // OP_CHECKSIGVERIFY
            // paul.pubkey
            OP_CHECKSIG
        }
    }

    fn unlock(&mut self) -> Script{
        script! {
            // { self.paul.sign(this) }
            // vicky.sign(this)
            { self.paul.unlock().merkle_response_a(self.round_index) }
        }
    }
}

#[derive(LeafGetters)]
pub struct MerkleResponseBLeaf<'a> {
    pub paul: &'a mut dyn Paul,
    pub vicky: &'a mut dyn Vicky,
    pub round_index: u8
}

impl<'a> Leaf for MerkleResponseBLeaf<'a> { 

    fn lock(&mut self) -> Script {
        script! {
            { self.paul.commit().merkle_response_b(self.round_index) }
            // vicky.pubkey
            // OP_CHECKSIGVERIFY
            // paul.pubkey
            OP_CHECKSIG
        }
    }

    fn unlock(&mut self) -> Script{
        script! {
            // paul.sign(this), 
            // vicky.sign(this),
            { self.paul.unlock().merkle_response_b(self.round_index) }
        }
    }
}

// export class Merkle_response_a extends Transaction {
//     static ACTOR = PAUL
//     static taproot(params) {
//         script! {
//             [MerkleResponseALeaf, params.vicky, params.paul, this.INDEX]
//         ]
//     }
// }

// export class Merkle_response_b extends Transaction {
//     static ACTOR = PAUL
//     static taproot(params) {
//         script! {
//             [MerkleResponseBLeaf, params.vicky, params.paul, this.INDEX]
//         ]
//     }
// }



#[derive(LeafGetters)]
pub struct MerkleResponseATimeoutLeaf<'a> {
    pub paul: &'a mut dyn Paul,
    pub vicky: &'a mut dyn Vicky,
    pub timeout: u32
}
impl<'a> Leaf for MerkleResponseATimeoutLeaf<'a> { 

    fn lock(&mut self) -> Script {
        script! {
            { self.timeout }
            // OP_CHECKSEQUENCEVERIFY
            OP_DROP
            // vicky.pubkey
            OP_CHECKSIG
        }
    }

    fn unlock(&mut self) -> Script {
        script! { 
            // vicky.sign(this), 
        }
    }
}

#[derive(LeafGetters)]
pub struct MerkleResponseBTimeoutLeaf<'a> {
    pub paul: &'a mut dyn Paul,
    pub vicky: &'a mut dyn Vicky,
    pub timeout: u32
}
impl<'a> Leaf for MerkleResponseBTimeoutLeaf<'a> { 

    fn lock(&mut self) -> Script {
        script! {
            { self.timeout }
            // OP_CHECKSEQUENCEVERIFY
            OP_DROP
            // vicky.pubkey
            OP_CHECKSIG
        }
    }

    fn unlock(&mut self) -> Script {
        script! { 
            // vicky.sign(this), 
        }
    }
}

// export class Merkle_response_aTimeout extends EndTransaction {
//     static ACTOR = VICKY
//     static taproot(state){
//         script! {[ MerkleResponseATimeoutLeaf, state.vicky, state.paul]]
//     }
// } 

// export class Merkle_response_bTimeout extends EndTransaction {
//     static ACTOR = VICKY
//     static taproot(state){
//         script! {[ MerkleResponseBTimeoutLeaf, state.vicky, state.paul]]
//     }
// } 

#[derive(LeafGetters)]
pub struct MerkleHashALeftLeaf<'a> {
    pub paul: &'a mut dyn Paul,
    pub vicky: &'a mut dyn Vicky,
    pub merkle_index_a: u32
}

impl<'a> Leaf for MerkleHashALeftLeaf<'a> {

    fn lock(&mut self) -> Script {
        let round_index_1 = LOG_PATH_LEN as u8 - 1 - trailing_zeros(self.merkle_index_a);
        let round_index_2 = LOG_PATH_LEN as u8 - 1 - trailing_zeros(self.merkle_index_a + 1);
        script! {
            // Verify we're executing the correct leaf
            { self.vicky.push().merkle_index_a() }
            { self.merkle_index_a }
            OP_EQUALVERIFY

            { self.vicky.push().next_merkle_index_a(round_index_1) }
            { self.merkle_index_a }
            OP_EQUALVERIFY


            { self.vicky.push().next_merkle_index_a(round_index_2) }
            { self.merkle_index_a + 1 }
            OP_EQUALVERIFY

            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            // { self.paul.push().address_a_bit_at(PATH_LEN - 1 - merkle_index_a) }
            OP_NOT
            OP_VERIFY

            // Read the child nodes
            { self.paul.push().merkle_response_a(round_index_2) }
            // Hash the child nodes
            blake3_160
            u160_toaltstack
            // Read the parent hash
            { self.paul.push().merkle_response_a(round_index_1) }
            
            u160_fromaltstack
            u160_swap_endian
            u160_equalverify
            /* OP_TRUE */ 1 // TODO: verify the covenant here
        }
    }

    fn unlock(&mut self) -> Script {
        let round_index_1 = LOG_PATH_LEN as u8 - 1 - trailing_zeros(self.merkle_index_a);
        let round_index_2 = LOG_PATH_LEN as u8 - 1 - trailing_zeros(self.merkle_index_a + 1);
        script! {
            { self.paul.unlock().merkle_response_a(round_index_1) }
            { self.paul.unlock().merkle_response_a_sibling(round_index_2) }
            { self.paul.unlock().merkle_response_a(round_index_2) }
            // { self.paul.unlock().address_a_bit_at(PATH_LEN - 1 - merkle_index_a) }
            { self.vicky.unlock().next_merkle_index_a(round_index_2) }
            { self.vicky.unlock().next_merkle_index_a(round_index_1) }
            { self.vicky.unlock().merkle_index_a() }
        }
    }
}

#[derive(LeafGetters)]
pub struct MerkleHashBLeftLeaf<'a> {
    pub paul: &'a mut dyn Paul,
    pub vicky: &'a mut dyn Vicky,
    pub merkle_index_b: u32
}
impl<'a> Leaf for MerkleHashBLeftLeaf<'a> {

    fn lock(&mut self) -> Script {
        let round_index_1 = LOG_PATH_LEN as u8 - 1 - trailing_zeros(self.merkle_index_b);
        let round_index_2 = LOG_PATH_LEN as u8 - 1 - trailing_zeros(self.merkle_index_b + 1);
        script! {
            // Verify we're executing the correct leaf
            { self.vicky.push().merkle_index_b() }
            { self.merkle_index_b }
            OP_EQUALVERIFY

            { self.vicky.push().next_merkle_index_b(round_index_1) }
            { self.merkle_index_b }
            OP_EQUALVERIFY


            { self.vicky.push().next_merkle_index_b(round_index_2) }
            { self.merkle_index_b + 1 }
            OP_EQUALVERIFY

            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            // { paul.push().address_b_bit_at(PATH_LEN - 1 - self.merkle_index_b) }
            OP_NOT
            OP_VERIFY

            // Read the child nodes
            { self.paul.push().merkle_response_b(round_index_2) }
            // Hash the child nodes
            blake3_160
            u160_toaltstack
            // Read the parent hash
            { self.paul.push().merkle_response_b(round_index_1) }
            
            u160_fromaltstack
            u160_swap_endian
            u160_equalverify
            /* OP_TRUE */ 1 // TODO: verify the covenant here
        }
    }

    fn unlock(&mut self) -> Script {
        let round_index_1 = LOG_PATH_LEN as u8 - 1 - trailing_zeros(self.merkle_index_b);
        let round_index_2 = LOG_PATH_LEN as u8 - 1 - trailing_zeros(self.merkle_index_b + 1);
        script! {
            { self.paul.unlock().merkle_response_b(round_index_1) }
            { self.paul.unlock().merkle_response_b_sibling(round_index_2) }
            { self.paul.unlock().merkle_response_b(round_index_2) }
            // { self.paul.unlock().address_b_bit_at(PATH_LEN - 1 - self.merkle_index_b) }
            { self.vicky.unlock().next_merkle_index_b(round_index_2) }
            { self.vicky.unlock().next_merkle_index_b(round_index_1) }
            { self.vicky.unlock().merkle_index_b() }
        }
    }
}

#[derive(LeafGetters)]
pub struct MerkleHashARightLeaf<'a> {
    pub paul: &'a mut dyn Paul,
    pub vicky: &'a mut dyn Vicky,
    pub merkle_index_a: u32
}
impl<'a> Leaf for MerkleHashARightLeaf<'a> {

    fn lock(&mut self) -> Script {
        let round_index_1 = LOG_PATH_LEN as u8 - 1 - trailing_zeros(self.merkle_index_a);
        let round_index_2 = LOG_PATH_LEN as u8 - 1 - trailing_zeros(self.merkle_index_a + 1);
        script! {
            // Verify we're executing the correct leaf
            { self.vicky.push().merkle_index_a() }
            { self.merkle_index_a }
            OP_EQUALVERIFY

            { self.vicky.push().next_merkle_index_a(round_index_1) }
            { self.merkle_index_a }
            OP_EQUALVERIFY

            { self.vicky.push().next_merkle_index_a(round_index_2) }
            { self.merkle_index_a + 1 }
            OP_EQUALVERIFY

            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            // { paul.push().address_a_bit_at(PATH_LEN - 1 - merkle_index_a) }
            OP_VERIFY

            // Read the child nodes
            u160_toaltstack
            { self.paul.push().merkle_response_a(round_index_2) }
            u160_fromaltstack
            // Hash the child nodes
            blake3_160
            u160_toaltstack
            // Read the parent hash
            { self.paul.push().merkle_response_a(round_index_1) }
            
            u160_fromaltstack
            u160_swap_endian
            u160_equalverify
            /* OP_TRUE */ 1 // TODO: verify the covenant here
        }
    }

    fn unlock(&mut self) -> Script {
        let round_index_1 = LOG_PATH_LEN as u8 - 1 - trailing_zeros(self.merkle_index_a);
        let round_index_2 = LOG_PATH_LEN as u8 - 1 - trailing_zeros(self.merkle_index_a + 1);
        script! {
            { self.paul.unlock().merkle_response_a(round_index_1) }
            { self.paul.unlock().merkle_response_a(round_index_2) }
            { self.paul.unlock().merkle_response_a_sibling(round_index_2) }
            // { self.paul.unlock().address_a_bit_at(PATH_LEN - 1 - merkle_index_a) }
            { self.vicky.unlock().next_merkle_index_a(round_index_2) }
            { self.vicky.unlock().next_merkle_index_a(round_index_1) }
            { self.vicky.unlock().merkle_index_a() }
        }
    }
}

#[derive(LeafGetters)]
pub struct MerkleHashBRightLeaf<'a> {
    pub paul: &'a mut dyn Paul,
    pub vicky: &'a mut dyn Vicky,
    pub merkle_index_b: u32
}
impl<'a> Leaf for MerkleHashBRightLeaf<'a> {

    fn lock(&mut self) -> Script {
        let round_index_1 = LOG_PATH_LEN as u8 - 1 - trailing_zeros(self.merkle_index_b);
        let round_index_2 = LOG_PATH_LEN as u8 - 1 - trailing_zeros(self.merkle_index_b + 1);
        script! {
            // Verify we're executing the correct leaf
            { self.vicky.push().merkle_index_b() }
            { self.merkle_index_b }
            OP_EQUALVERIFY

            { self.vicky.push().next_merkle_index_b(round_index_1) }
            { self.merkle_index_b }
            OP_EQUALVERIFY

            { self.vicky.push().next_merkle_index_b(round_index_2) }
            { self.merkle_index_b + 1 }
            OP_EQUALVERIFY

            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            // { self.paul.push().address_b_bit_at(PATH_LEN - 1 - self.merkle_index_b) }
            OP_VERIFY

            // Read the child nodes
            u160_toaltstack
            { self.paul.push().merkle_response_b(round_index_2) }
            u160_fromaltstack
            // Hash the child nodes
            blake3_160
            u160_toaltstack
            // Read the parent hash
            { self.paul.push().merkle_response_b(round_index_1) }
            
            u160_fromaltstack
            u160_swap_endian
            u160_equalverify
            /* OP_TRUE */ 1 // TODO: verify the covenant here
        }
    }

    fn unlock(&mut self) -> Script {
        let round_index_1 = LOG_PATH_LEN as u8 - 1 - trailing_zeros(self.merkle_index_b);
        let round_index_2 = LOG_PATH_LEN as u8 - 1 - trailing_zeros(self.merkle_index_b + 1);
        script! {
            { self.paul.unlock().merkle_response_b(round_index_1) }
            { self.paul.unlock().merkle_response_b(round_index_2) }
            { self.paul.unlock().merkle_response_b_sibling(round_index_2) }
            // { self.paul.unlock().address_b_bit_at(PATH_LEN - 1 - merkle_index_b) }
            { self.vicky.unlock().next_merkle_index_b(round_index_2) }
            { self.vicky.unlock().next_merkle_index_b(round_index_1) }
            { self.vicky.unlock().merkle_index_b() }
        }
    }
}

#[derive(LeafGetters)]
pub struct MerkleHashARootLeftLeaf<'a> {
    pub paul: &'a mut dyn Paul,
    pub vicky: &'a mut dyn Vicky,
    pub trace_round_index: u8
}
impl<'a> Leaf for MerkleHashARootLeftLeaf<'a> {

    fn lock(&mut self) -> Script {
        script! {
            // Verify we're executing the correct leaf
            { self.vicky.push().merkle_index_a() }
            0
            OP_EQUALVERIFY

            { self.vicky.push().trace_index() }
            OP_TOALTSTACK
            { self.vicky.push().next_trace_index(self.trace_round_index) }
            OP_FROMALTSTACK
            OP_EQUALVERIFY

            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            // { self.paul.push().address_a_bit_at(PATH_LEN - 1) }
            OP_NOT
            OP_VERIFY

            // Read the child nodes
            { self.paul.push().merkle_response_a(LOG_PATH_LEN as u8 - 1) }
            // Hash the child nodes
            blake3_160
            u160_toaltstack
            // Read the parent hash
            { self.paul.push().trace_response(self.trace_round_index) }
            
            u160_fromaltstack
            u160_swap_endian
            u160_equalverify
            
            /* OP_TRUE */ 1 // TODO: verify the covenant here
        }
    }

    fn unlock(&mut self) -> Script {
        script! {
            { self.paul.unlock().trace_response(self.trace_round_index) }
            { self.paul.unlock().merkle_response_a_sibling(LOG_PATH_LEN as u8 - 1) }
            { self.paul.unlock().merkle_response_a(LOG_PATH_LEN as u8 - 1) }
            // { self.paul.unlock().address_a_bit_at(PATH_LEN - 1) }
            { self.vicky.unlock().next_trace_index(self.trace_round_index) }
            { self.vicky.unlock().trace_index() }
            { self.vicky.unlock().merkle_index_a() }
        }
    }
}


#[derive(LeafGetters)]
pub struct MerkleHashBRootLeftLeaf<'a> {
    pub paul: &'a mut dyn Paul,
    pub vicky: &'a mut dyn Vicky,
    pub trace_round_index: u8
}

impl<'a> Leaf for MerkleHashBRootLeftLeaf<'a> {

    fn lock(&mut self) -> Script {
        script! {
            // Verify we're executing the correct leaf
            { self.vicky.push().merkle_index_b() }
            0
            OP_EQUALVERIFY

            { self.vicky.push().trace_index() }
            OP_TOALTSTACK
            { self.vicky.push().next_trace_index(self.trace_round_index) }
            OP_FROMALTSTACK
            OP_EQUALVERIFY


            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            // { self.paul.push().address_b_bit_at(PATH_LEN - 1) }
            OP_NOT
            OP_VERIFY

            // Read the child nodes
            { self.paul.push().merkle_response_b(LOG_PATH_LEN as u8 - 1) }
            // Hash the child nodes
            blake3_160
            u160_toaltstack
            // Read the parent hash
            { self.paul.push().trace_response(self.trace_round_index) }
            
            u160_fromaltstack
            u160_swap_endian
            u160_equalverify
            
            /* OP_TRUE */ 1 // TODO: verify the covenant here
        }
    }

    fn unlock(&mut self) -> Script {
        script! {
            { self.paul.unlock().trace_response(self.trace_round_index) }
            { self.paul.unlock().merkle_response_b_sibling(LOG_PATH_LEN as u8 - 1) }
            { self.paul.unlock().merkle_response_b(LOG_PATH_LEN as u8 - 1) }
            // { self.paul.unlock().address_b_bit_at(PATH_LEN - 1) }
            { self.vicky.unlock().next_trace_index(self.trace_round_index) }
            { self.vicky.unlock().trace_index() }
            { self.vicky.unlock().merkle_index_b() }
        }
    }
}

#[derive(LeafGetters)]
pub struct MerkleHashARootRightLeaf<'a> {
    pub paul: &'a mut dyn Paul,
    pub vicky: &'a mut dyn Vicky,
    pub trace_index: u8
}
impl<'a> Leaf for MerkleHashARootRightLeaf<'a> {

    fn lock(&mut self) -> Script {
        script! {
            // Verify we're executing the correct leaf
            { self.vicky.push().merkle_index_a() }
            0
            OP_EQUALVERIFY

            { self.vicky.push().trace_index() }
            { self.trace_index }
            OP_EQUALVERIFY

            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            // { self.paul.push().address_a_bit_at(PATH_LEN - 1) }
            OP_VERIFY

            // Read the child nodes
            u160_toaltstack
            { self.paul.push().merkle_response_a(LOG_PATH_LEN as u8 - 1) }
            u160_fromaltstack
            // Hash the child nodes
            blake3_160
            u160_toaltstack
            // Read the parent hash
            { self.paul.push().trace_response(self.trace_index) }
            
            u160_fromaltstack
            u160_swap_endian
            u160_equalverify
            /* OP_TRUE */ 1 // TODO: verify the covenant here
        }
    }

    fn unlock(&mut self) -> Script {
        script! {
            { self.paul.unlock().trace_response(self.trace_index) }
            { self.paul.unlock().merkle_response_a(LOG_PATH_LEN as u8 - 1) }
            { self.paul.unlock().merkle_response_a_sibling(LOG_PATH_LEN as u8 - 1) }
            // { self.paul.unlock().address_a_bit_at(PATH_LEN - 1) }
            { self.vicky.unlock().trace_index() }
            { self.vicky.unlock().merkle_index_a() }
        }
    }
}


#[derive(LeafGetters)]
pub struct MerkleHashBRootRightLeaf<'a> {
    pub paul: &'a mut dyn Paul,
    pub vicky: &'a mut dyn Vicky,
    pub trace_index: u8
}
impl<'a> Leaf for MerkleHashBRootRightLeaf<'a> {

    fn lock(&mut self) -> Script {
        script! {
            // Verify we're executing the correct leaf
            { self.vicky.push().merkle_index_b() }
            0
            OP_EQUALVERIFY

            { self.vicky.push().trace_index() }
            { self.trace_index }
            OP_EQUALVERIFY


            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            // { self.paul.push().address_b_bit_at(PATH_LEN - 1) }
            OP_VERIFY

            // Read the child nodes
            u160_toaltstack
            { self.paul.push().merkle_response_b(LOG_PATH_LEN as u8 - 1) }
            u160_fromaltstack
            // Hash the child nodes
            blake3_160
            u160_toaltstack
            // Read the parent hash
            { self.paul.push().trace_response(self.trace_index) }
            
            u160_fromaltstack
            u160_swap_endian
            u160_equalverify
            /* OP_TRUE */ 1 // TODO: verify the covenant here
        }
    }

    fn unlock(&mut self) -> Script {
        script! {
            { self.paul.unlock().trace_response(self.trace_index) }
            { self.paul.unlock().merkle_response_b(LOG_PATH_LEN as u8 - 1) }
            { self.paul.unlock().merkle_response_b_sibling(LOG_PATH_LEN as u8 - 1) }
            // { self.paul.unlock().address_b_bit_at(PATH_LEN - 1) }
            { self.vicky.unlock().trace_index() }
            { self.vicky.unlock().merkle_index_b() }
        }
    }
}

// impl<'a> Leaf for MerkleALeafHashLeftLeaf<'a> {

//     fn lock(&mut self) -> Script {
//         script! {
//             // Verify we're executing the correct leaf
//             { self.vicky.push().merkle_index_a() }
//             { PATH_LEN - 1 }
//             OP_EQUALVERIFY

//             // Read the bit from address to figure out if we have to swap the two nodes before hashing
//             { self.paul.push().address_a_bit_at(0) }
//             OP_NOT
//             OP_VERIFY

//             // Read valueA
//             { self.paul.push().value_a }
//             // Pad with 16 zero bytes
//             u32_toaltstack
//             { unroll(16, |_| 0) }
//             u32_fromaltstack
//             // Hash the child nodes
//             blake3_160
//             u160_toaltstack
//             // Read the parent hash
//             { self.paul.push().merkle_response_a(LOG_PATH_LEN as u8 - 1) }
            
//             u160_fromaltstack
//             u160_swap_endian
//             u160_equalverify
//             /* OP_TRUE */ 1 // TODO: verify the covenant here
//         }
//     }

//     fn unlock(&mut self) -> Script {
//         script! {
//             { self.paul.unlock().merkle_response_a(LOG_PATH_LEN as u8 - 1) }
//             { self.paul.unlock().merkle_response_a_sibling(LOG_PATH_LEN) }
//             { self.paul.unlock().value_a }
//             { self.paul.unlock().address_a_bit_at(0) }
//             { self.vicky.unlock().merkle_index_a }
//         }
//     }
// }

// impl<'a> Leaf for MerkleBLeafHashLeftLeaf<'a> {

//     fn lock(&mut self) -> Script {
//         script! {
//             // Verify we're executing the correct leaf
//             { vicky.push().merkle_index_b }
//             { PATH_LEN - 1 }
//             OP_EQUALVERIFY

//             // Read the bit from address to figure out if we have to swap the two nodes before hashing
//             paul.push().address_b_bit_at(0),
//             OP_NOT
//             OP_VERIFY

//             // Read value_b
//             paul.push().value_b,
//             // Pad with 16 zero bytes
//             u32_toaltstack
//             unroll(16, |_| 0),
//             u32_fromaltstack
//             // Hash the child nodes
//             blake3_160
//             u160_toaltstack
//             // Read the parent hash
//             paul.push().merkle_response_b(LOG_PATH_LEN as u8 - 1),
            
//             u160_fromaltstack
//             u160_swap_endian
//             u160_equalverify
//             /* OP_TRUE */ 1 // TODO: verify the covenant here
//         }
//     }

//     fn unlock(&mut self) -> Script {
//         script! {
//             { self.paul.unlock().merkle_response_b(LOG_PATH_LEN as u8 - 1) }
//             { self.paul.unlock().merkle_response_b_sibling(LOG_PATH_LEN) }
//             { self.paul.unlock().value_b }
//             { self.paul.unlock().address_b_bit_at(0) }
//             { self.vicky.unlock().merkle_index_b }
//         }
//     }
// }


#[derive(LeafGetters)]
pub struct MerkleALeafHashRightLeaf<'a> {
    pub paul: &'a mut dyn Paul,
    pub vicky: &'a mut dyn Vicky,
}
impl<'a> Leaf for MerkleALeafHashRightLeaf<'a> {

    fn lock(&mut self) -> Script {
        script! {
            // Verify we're executing the correct leaf
            { self.vicky.push().merkle_index_a() }
            { PATH_LEN - 1 }
            OP_EQUALVERIFY

            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            // { self.paul.push().address_a_bit_at(0) }
            OP_VERIFY


            u160_toaltstack
            // Read valueA
            { self.paul.push().value_a() }
            // Pad with 16 zero bytes
            u32_toaltstack
            { unroll(16, |_| 0) }
            u32_fromaltstack
            u160_fromaltstack
            // Hash the child nodes
            blake3_160
            u160_toaltstack
            // Read the parent hash
            { self.paul.push().merkle_response_a(LOG_PATH_LEN as u8 - 1) }
            
            u160_fromaltstack
            u160_swap_endian
            u160_equalverify
            /* OP_TRUE */ 1 // TODO: verify the covenant here
        }
    }

    fn unlock(&mut self) -> Script {
        script! {
            { self.paul.unlock().merkle_response_a(LOG_PATH_LEN as u8 - 1) }
            { self.paul.unlock().value_a() }
            { self.paul.unlock().merkle_response_a_sibling(LOG_PATH_LEN as u8) }
            // { self.paul.unlock().address_a_bit_at(0) }
            { self.vicky.unlock().merkle_index_a() }
        }
    }
}

#[derive(LeafGetters)]
pub struct MerkleBLeafHashRightLeaf<'a> {
    pub paul: &'a mut dyn Paul,
    pub vicky: &'a mut dyn Vicky,
}
impl<'a> Leaf for MerkleBLeafHashRightLeaf<'a> {

    fn lock(&mut self) -> Script {
        script! {
            // Verify we're executing the correct leaf
            { self.vicky.push().merkle_index_b() }
            { PATH_LEN - 1 }
            OP_EQUALVERIFY

            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            // { self.paul.push().address_b_bit_at(0) }
            OP_VERIFY


            u160_toaltstack
            // Read value_b
            { self.paul.push().value_b() }
            // Pad with 16 zero bytes
            u32_toaltstack
            { unroll(16, |_| 0) }
            u32_fromaltstack
            u160_fromaltstack
            // Hash the child nodes
            blake3_160
            u160_toaltstack
            // Read the parent hash
            { self.paul.push().merkle_response_b(LOG_PATH_LEN as u8 - 1) }
            
            u160_fromaltstack
            u160_swap_endian
            u160_equalverify
            /* OP_TRUE */ 1 // TODO: verify the covenant here
        }
    }

    fn unlock(&mut self) -> Script {
        script! {
            { self.paul.unlock().merkle_response_b(LOG_PATH_LEN as u8 - 1) }
            { self.paul.unlock().value_b() }
            { self.paul.unlock().merkle_response_b_sibling(LOG_PATH_LEN as u8) }
            // { self.paul.unlock().address_b_bit_at(0) }
            { self.vicky.unlock().merkle_index_b() }
        }
    }
}

// export class MerkleHashA extends Transaction {
//     static ACTOR = PAUL
//     static taproot(params) {
//         let {&mut self} = params;;
//         script! {
//             ...loop(PATH_LEN - 2, merkle_index_a => [MerkleHashALeftLeaf, &mut self + 1]),
//             ...loop(PATH_LEN - 2, merkle_index_a => [MerkleHashARightLeaf, &mut self + 1]),
//             ...loop(LOG_TRACE_LEN, traceRoundIndex => [MerkleHashARootLeftLeaf, &mut self, traceRoundIndex]),
//             ...loop(LOG_TRACE_LEN, traceRoundIndex => [MerkleHashARootRightLeaf, &mut self, traceRoundIndex]),
//             [MerkleALeafHashLeftLeaf, &mut self],
//             [MerkleALeafHashRightLeaf, &mut self],
//         ]
//     }
// }

// export class MerkleHashB extends Transaction {
//     static ACTOR = PAUL
//     static taproot(params) {
//         let {&mut self} = params;;
//         script! {
//             ...loop(PATH_LEN - 2, _merkle_index_b => [MerkleHashBLeftLeaf, &mut self, _merkle_index_b + 1]),
//             ...loop(PATH_LEN - 2, _merkle_index_b => [MerkleHashBRightLeaf, &mut self, _merkle_index_b + 1]),
//             ...loop(LOG_TRACE_LEN, traceRoundIndex => [MerkleHashBRootLeftLeaf, &mut self, traceRoundIndex]),
//             ...loop(LOG_TRACE_LEN, traceRoundIndex => [MerkleHashBRootRightLeaf, &mut self, traceRoundIndex]),
//             [MerkleBLeafHashLeftLeaf, &mut self],
//             [MerkleBLeafHashRightLeaf, &mut self],
//         ]
//     }
// }

#[derive(LeafGetters)]
pub struct MerkleHashTimeoutALeaf<'a> {
    pub paul: &'a mut dyn Paul,
    pub vicky: &'a mut dyn Vicky,
    pub timeout: u32
}
impl<'a> Leaf for MerkleHashTimeoutALeaf<'a> { 

    fn lock(&mut self) -> Script {
        script! {
            { self.timeout }
            // OP_CHECKSEQUENCEVERIFY
            OP_DROP
            // { self.vicky.pubkey }
            OP_CHECKSIG
        }
    }

    fn unlock(&mut self) -> Script {
        script! { 
            // { self.vicky.sign(this) }
        }
    }
}

#[derive(LeafGetters)]
pub struct MerkleHashTimeoutBLeaf<'a> {
    pub paul: &'a mut dyn Paul,
    pub vicky: &'a mut dyn Vicky,
    pub timeout: u32
}
impl<'a> Leaf for MerkleHashTimeoutBLeaf<'a> { 

    fn lock(&mut self) -> Script {
        script! {
            { self.timeout }
            // OP_CHECKSEQUENCEVERIFY
            OP_DROP
            // { self.vicky.pubkey }
            OP_CHECKSIG
        }
    }

    fn unlock(&mut self) -> Script {
        script! { 
            // { self.vicky.sign(this) }
        }
    }
}

// impl<'a> MerkleHashTimeoutA extends EndTransaction<'a> {
//     static ACTOR = VICKY
//     static taproot(state){
//         script! {[ MerkleHashTimeoutALeaf, state.vicky, state.paul]]
//     }
// }

// impl<'a> MerkleHashTimeoutB extends EndTransaction<'a> {
//     static ACTOR = VICKY
//     static taproot(state){
//         script! {[ MerkleHashTimeoutBLeaf, state.vicky, state.paul]]
//     }
// }

// impl<'a> MerkleEquivocationA extends EndTransaction<'a> {
//     static ACTOR = VICKY

//     static taproot(params) {
//         console.warn(`${this.name} not implemented`)
//         script! {[ class extends Leaf {
//             fn lock(){
//                 script! {'OP_4']
//             }
//             fn unlock(){
//                 script! {]
//             }
//         }]]
//     }
// }

// impl<'a> MerkleEquivocationB extends EndTransaction<'a> {
//     static ACTOR = VICKY

//     static taproot(params) {
//         console.warn(`${this.name} not implemented`)
//         script! {[ class extends Leaf {
//             fn lock(){
//                 script! {'OP_4']
//             }
//             fn unlock(){
//                 script! {]
//             }
//         }]]
//     }
// }

// impl<'a> MerkleEquivocationTimeoutA extends EndTransaction<'a> {
//     static ACTOR = PAUL

//     static taproot(params) {
//         script! {[ 
//             class extends TimeoutLeaf { 
//                 fn lock(&mut self) -> Script {
//                     script! {
//                         TIMEOUT
//                         OP_CHECKSEQUENCEVERIFY
//                         OP_DROP
//                         paul.pubkey
//                         OP_CHECKSIG
//                     ]
//                 }

//                 fn unlock(&mut self) -> Script {
//                     script! { 
//                         paul.sign(this) 
//                     ]
//                 }
//             }, 
//             params.vicky, 
//             params.paul 
//         ]]
//     }
// }

// impl<'a> MerkleEquivocationTimeoutB extends EndTransaction<'a> {
//     static ACTOR = PAUL

//     static taproot(params) {
//         script! {[ 
//             class extends TimeoutLeaf { 
//                 fn lock(&mut self) -> Script {
//                     script! {
//                         TIMEOUT
//                         OP_CHECKSEQUENCEVERIFY
//                         OP_DROP
//                         paul.pubkey
//                         OP_CHECKSIG
//                     ]
//                 }

//                 fn unlock(&mut self) -> Script {
//                     script! { 
//                         paul.sign(this) 
//                     ]
//                 }
//             }, 
//             params.vicky, 
//             params.paul 
//         ]]
//     }
// }
