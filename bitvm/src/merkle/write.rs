// use scripts::opcodes::pseudo::OP_CHECKSEQUENCEVERIFY;
// use scripts::{opcodes::pushable, leaf::Leaf};
// use bitcoin_script::bitcoin_script as script;
// use bitcoin::blockdata::script::ScriptBuf as Script;
// use scripts::opcodes::blake3::blake3_160;
// use scripts::opcodes::{
//     unroll,
//     u160_std::{
//         u160_fromaltstack,
//         u160_toaltstack,
//         u160_equalverify,
//         u160_swap_endian,
//     },
//     u32_std::{
//         u32_fromaltstack,
//         u32_toaltstack,
//     },
// };
// use crate::model::{Paul, Vicky};
// use crate::constants::{PATH_LEN, LOG_PATH_LEN};

// struct MerkleChallengeCLeaf<'a> {
//     pub paul: &'a mut dyn Paul,
//     pub vicky: &'a mut dyn Vicky,
//     pub merkle_index: u8
// }
// impl<'a> Leaf for MerkleChallengeCLeaf<'a> {

//     fn lock(&mut self) -> Script {
//         script! {
//             { self.merkle_index }
//             OP_DROP // This is just a marker to make the TXIDs unique
//             // { self.vicky.pubkey, }
//             OP_CHECKSIGVERIFY
//             // paul.pubkey
//             OP_CHECKSIG
//         }
//     }

//     fn unlock(&mut self) -> Script {
//         script! {
//             // paul.sign(this), // TODO
//             // { self.vicky.sign(this), }
//         }
//     }
// }

// // export class MerkleChallengeC extends Transaction {
// //     static ACTOR = VICKY
// //     static taproot(model) -> Script {
// //         return [
// //             [MerkleChallengeCLeaf, model.vicky, model.paul, this.INDEX]
// //         ]
// //     }
// // }

// struct MerkleChallengeCTimeoutLeaf<'a> {
//     pub paul: &'a mut dyn Paul,
//     pub vicky: &'a mut dyn Vicky,
//     pub timeout: u32,
// }
// impl<'a> Leaf for MerkleChallengeCTimeoutLeaf<'a> {

//     fn lock(&mut self) -> Script {
//         script! {
//             { self.timeout }
//             OP_CHECKSEQUENCEVERIFY
//             OP_DROP
//             // { self.paul.pubkey }
//             OP_CHECKSIG
//         }
//     }

//     fn unlock(&mut self) -> Script {
//         script! {
//             // { self.paul.sign(this) }
//         }
//     }
// }



// // export class MerkleChallengeCTimeout extends EndTransaction {
// //     static ACTOR = PAUL
// //     static taproot(state) -> Script {
// //         return [
// //             [MerkleChallengeCTimeoutLeaf, state.vicky, state.paul]
// //         ]
// //     }
// // }


// struct MerkleResponseCLeaf<'a> {
//     pub paul: &'a mut dyn Paul,
//     pub vicky: &'a mut dyn Vicky,
//     merkle_index: u8
// }

// impl<'a> Leaf for MerkleResponseCLeaf<'a> {

//     fn lock(&mut self) -> Script {
//         script! {
//             { self.paul.commit().merkle_response_c_next_sibling(self.merkle_index) }
//             { self.paul.commit().merkle_response_c_next(self.merkle_index) }
//             // vicky.pubkey
//             OP_CHECKSIGVERIFY
//             // { self.paul.pubkey }
//             OP_CHECKSIG
//         }
//     }

//     fn unlock(&mut self) -> Script {
//         script! {
//             // paul.sign(this)
//             // vicky.sign(this)
//             { self.paul.unlock().merkle_response_c_next(self.merkle_index) }
//             { self.paul.unlock().merkle_response_c_next_sibling(self.merkle_index) }
//         }
//     }
// }

// // export class MerkleResponseC extends Transaction {
// //     static ACTOR = PAUL
// //     static taproot(model) -> Script {
// //         return [
// //             [MerkleResponseCLeaf, model.vicky, model.paul, this.INDEX]
// //         ]
// //     }
// // }



// struct MerkleResponseCTimeoutLeaf<'a> {
//     pub paul: &'a mut dyn Paul,
//     pub vicky: &'a mut dyn Vicky,
//     pub timeout: u32,
// }
// impl<'a> Leaf for MerkleResponseCTimeoutLeaf<'a> {

//     fn lock(&mut self) -> Script {
//         script! {
//             { self.timeout }
//             OP_CHECKSEQUENCEVERIFY
//             OP_DROP
//             // { self.vicky.pubkey }
//             OP_CHECKSIG
//         }
//     }

//     fn unlock(&mut self) -> Script {
//         script! {
//             // { self.vicky.sign(this) }
//         }
//     }
// }


// // export class MerkleResponseCTimeout extends EndTransaction {
// //     static ACTOR = VICKY
// //     static taproot(state) -> Script {
// //         return [
// //             [MerkleResponseCTimeoutLeaf, state.vicky, state.paul]
// //         ]
// //     }
// // }




// struct MerkleHashCLeftLeaf<'a> {
//     pub paul: &'a mut dyn Paul,
//     pub vicky: &'a mut dyn Vicky,
//     pub merkle_index: u8
// }
// impl<'a> Leaf for MerkleHashCLeftLeaf<'a> {

//     fn lock(&mut self) -> Script {
//         script! {
//             // Read the bit from address to figure out if we have to swap the two nodes before hashing
//             { self.paul.push().address_c_bit_at(PATH_LEN as u8 - 1 - self.merkle_index) }
//             OP_NOT
//             OP_VERIFY

//             // Read the child node
//             { self.paul.push().merkle_response_c_next(self.merkle_index) }
//             // Read the child's sibling
//             u160_toaltstack
//             { self.paul.push().merkle_response_c_next_sibling(self.merkle_index) }
//             u160_fromaltstack

//             // Hash the child nodes
//             blake3_160
//             u160_toaltstack
//             // Read the parent hash
//             { self.paul.push().merkle_response_c_next(self.merkle_index + 1) }

//             u160_fromaltstack
//             u160_swap_endian
//             u160_equalverify
//             OP_TRUE // TODO: verify the covenant here
//         }
//     }

//     fn unlock(&mut self) -> Script {
//         script! {
//             { self.paul.unlock().merkle_response_c_next(self.merkle_index) }
//             { self.paul.unlock().merkle_response_c_next_sibling(self.merkle_index) }
//             { self.paul.unlock().merkle_response_c_next(self.merkle_index + 1) }
//             { self.paul.unlock().address_c_bit_at(PATH_LEN as u8 - 1 - self.merkle_index) }
//         }
//     }
// }


// struct MerkleHashCRightLeaf<'a> {
//     pub paul: &'a mut dyn Paul,
//     pub vicky: &'a mut dyn Vicky,
//     pub merkle_index_c: u8
// }
// impl<'a> Leaf for MerkleHashCRightLeaf<'a> {

//     fn lock(&mut self) -> Script {
//         script! {
//             // Read the bit from address to figure out if we have to swap the two nodes before hashing
//             { self.paul.push().address_c_bit_at(PATH_LEN as u8 - 1 - self.merkle_index_c) }
//             OP_VERIFY

//             // Read the child's sibling
//             { self.paul.push().merkle_response_c_next_sibling(self.merkle_index_c) }
//             // Read the child node
//             u160_toaltstack
//             { self.paul.push().merkle_response_c_next(self.merkle_index_c) }
//             u160_fromaltstack

//             // Hash the child nodes
//             blake3_160
//             u160_toaltstack
//             // Read the parent hash
//             { self.paul.push().merkle_response_c_next(self.merkle_index_c + 1) }

//             u160_fromaltstack
//             u160_swap_endian
//             u160_equalverify
//             OP_TRUE // TODO: verify the covenant here
//         }
//     }

//     fn unlock(&mut self) -> Script {
//         script! {
//             { self.paul.unlock().merkle_response_c_next_sibling(self.merkle_index_c) }
//             { self.paul.unlock().merkle_response_c_next(self.merkle_index_c) }
//             { self.paul.unlock().merkle_response_c_next(self.merkle_index_c + 1) }
//             { self.paul.unlock().address_c_bit_at(PATH_LEN as u8 - 1 - self.merkle_index_c) }
//         }
//     }
// }


// struct MerkleHashCRootLeftLeaf<'a> {
//     pub paul: &'a mut dyn Paul,
//     pub vicky: &'a mut dyn Vicky,
//     pub trace_round_index: u8
// }
// impl<'a> Leaf for MerkleHashCRootLeftLeaf<'a> {

//     fn lock(&mut self) -> Script {
//         script! {
//             // Verify we're executing the correct leaf

//             { self.vicky.push().trace_index() }
//             OP_TOALTSTACK
//             { self.vicky.push().next_trace_index(self.trace_round_index) }
//             OP_FROMALTSTACK
//             OP_EQUALVERIFY

//             // Read the bit from address to figure out if we have to swap the two nodes before hashing
//             { self.paul.push().address_c_bit_at(PATH_LEN as u8 - 1) }
//             OP_NOT
//             OP_VERIFY

//             // Read the child nodes
//             { self.paul.push().merkle_response_c_next(PATH_LEN as u8 - 1) }
//             // Read the child's sibling
//             u160_toaltstack
//             { self.paul.push().merkle_response_c_next_sibling(PATH_LEN as u8 - 1) }
//             u160_fromaltstack

//             // Hash the child nodes
//             blake3_160
//             u160_toaltstack
//             // Read the parent hash
//             { self.paul.push().trace_response(self.trace_round_index) }

//             u160_fromaltstack
//             u160_swap_endian
//             u160_equalverify

//             OP_TRUE // TODO: verify the covenant here
//         }
//     }

//     fn unlock(&mut self) -> Script {
//         script! {
//             { self.paul.unlock().trace_response(self.trace_round_index) }
//             { self.paul.unlock().merkle_response_c_next_sibling(PATH_LEN as u8 - 1) }
//             { self.paul.unlock().merkle_response_c_next(PATH_LEN as u8 - 1) }
//             { self.paul.unlock().address_c_bit_at(PATH_LEN as u8 - 1) }
//             { self.vicky.unlock().next_trace_index(self.trace_round_index) }
//             { self.vicky.unlock().trace_index() }
//         }
//     }
// }


// struct MerkleHashCRootRightLeaf<'a> {
//     pub paul: &'a mut dyn Paul,
//     pub vicky: &'a mut dyn Vicky,
//     pub trace_round_index: u8
// }
// impl<'a> Leaf for MerkleHashCRootRightLeaf<'a> {

//     fn lock(&mut self) -> Script {
//         script! {
//             // Verify we're executing the correct leaf

//             { self.vicky.push().trace_index() }
//             OP_TOALTSTACK
//             { self.vicky.push().next_trace_index(self.trace_round_index) }
//             OP_FROMALTSTACK
//             OP_EQUALVERIFY

//             // Read the bit from address to figure out if we have to swap the two nodes before hashing
//             { self.paul.push().address_c_bit_at(PATH_LEN as u8 - 1) }
//             OP_VERIFY

//             // Read the child's sibling
//             { self.paul.push().merkle_response_c_next_sibling(PATH_LEN as u8 - 1) }
//             // Read the child nodes
//             { self.paul.push().merkle_response_c_next(PATH_LEN as u8 - 1) }
//             u160_toaltstack
//             u160_fromaltstack

//             // Hash the child nodes
//             blake3_160
//             u160_toaltstack
//             // Read the parent hash
//             { self.paul.push().trace_response(self.trace_round_index) }

//             u160_fromaltstack
//             u160_swap_endian
//             u160_equalverify

//             OP_TRUE // TODO: verify the covenant here
//         }
//     }

//     fn unlock(&mut self) -> Script {
//         script! {
//             { self.paul.unlock().trace_response(self.trace_round_index) }
//             { self.paul.unlock().merkle_response_c_next(PATH_LEN as u8 - 1) }
//             { self.paul.unlock().merkle_response_c_next_sibling(PATH_LEN as u8 - 1) }
//             { self.paul.unlock().address_c_bit_at(PATH_LEN as u8 - 1) }
//             { self.vicky.unlock().next_trace_index(self.trace_round_index) }
//             { self.vicky.unlock().trace_index() } // TODO: Vicky can equivocate here
//         }
//     }
// }



// struct MerkleCLeafHashLeftLeaf<'a> {
//     pub paul: &'a mut dyn Paul,
//     pub vicky: &'a mut dyn Vicky,
// }
// impl<'a> Leaf for MerkleCLeafHashLeftLeaf<'a> {

//     fn lock(&mut self) -> Script {
//         script! {

//             // Read the bit from address to figure out if we have to swap the two nodes before hashing
//             { self.paul.push().address_c_bit_at(0) }
//             OP_NOT
//             OP_VERIFY

//             // Read value_c
//             { self.paul.push().value_c() }
//             // Pad with 16 zero bytes
//             u32_toaltstack
//             { unroll(16, |_| 0) }
//             u32_fromaltstack
            
//             // Read sibling
//             u160_toaltstack
//             { self.paul.push().merkle_response_c_next_sibling(0) }
//             u160_fromaltstack

//             // Hash the child nodes
//             blake3_160
//             u160_toaltstack
//             // Read the parent hash
//             { self.paul.push().merkle_response_c_next(LOG_PATH_LEN as u8 - 1) }

//             u160_fromaltstack
//             u160_swap_endian
//             u160_equalverify
//             OP_TRUE // TODO: verify the covenant here
//         }
//     }

//     fn unlock(&mut self) -> Script {
//         script! {
//             { self.paul.unlock().merkle_response_c_next(1) }
//             { self.paul.unlock().merkle_response_c_next_sibling(0) }
//             { self.paul.unlock().value_c() }
//             { self.paul.unlock().address_c_bit_at(0) }
//         }
//     }
// }
// struct MerkleCLeafHashRightLeaf<'a> {
//     pub paul: &'a mut dyn Paul,
//     pub vicky: &'a mut dyn Vicky,
// }
// impl<'a> Leaf for MerkleCLeafHashRightLeaf<'a> {

//     fn lock(&mut self) -> Script {
//         script! {
//             // Read the bit from address to figure out if we have to swap the two nodes before hashing
//             { self.paul.push().address_c_bit_at(0) }
//             OP_VERIFY

//             // Read sibling
//             { self.paul.push().merkle_response_c_next_sibling(0) }
            
//             // Read value_c
//             u160_toaltstack
//             { self.paul.push().value_c() }
//             // Pad with 16 zero bytes
//             u32_toaltstack
//             { unroll(16, |_| 0) }
//             u32_fromaltstack
//             u160_fromaltstack
            
//             // Hash the child nodes
//             blake3_160
//             u160_toaltstack
//             // Read the parent hash
//             { self.paul.push().merkle_response_c_next(LOG_PATH_LEN as u8 - 1) }

//             u160_fromaltstack
//             u160_swap_endian
//             u160_equalverify
//             OP_TRUE // TODO: verify the covenant here
//         }
//     }

//     fn unlock(&mut self) -> Script {
//         script! {
//             { self.paul.unlock().merkle_response_c_next(1) }
//             { self.paul.unlock().value_c() }
//             { self.paul.unlock().merkle_response_c_next_sibling(0) }
//             { self.paul.unlock().address_c_bit_at(0) }
//         }
//     }
// }



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


