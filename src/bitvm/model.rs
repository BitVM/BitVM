// use core::fmt;
// use std::collections::HashMap;
// use scanf::sscanf;

// use crate::actor::HashDigest;

// // Currently a digit is a u2
// type Digit = u8;

// // VM specific word
// type Word = u32;

// pub enum CommitmentValue {
//     Bit(u8),
//     Word,
//     Hash(HashDigest),
// }

// pub enum Identifier {
//     // Vicky's trace challenges
//     TraceChallenge(u8),
//     // Paul's trace responses
//     TraceResponse(u8),
//     // Paul's trace response program counters
//     TraceResponsePC(u8),
//     // Vicky's Merkle challenges for the operand A
//     MerkleChallengeA(u8),
//     // Paul's Merkle responses for the operand A
//     MerkleResponseA(u8),
//     // Vicky's Merkle challenges for the operand B
//     MerkleChallengeB(u8),
//     // Paul's Merkle responses for the operand B
//     MerkleResponseB(u8),
//     // Vicky's Merkle challenges for the result C
//     MerkleChallengeCPrev(u8),
//     // Paul's Merkle responses for the result C
//     MerkleResponseCPrev(u8),
//     MerkleResponseCNext(u8),
//     MerkleResponseCNextSibling(u8),
//     // Paul's instruction
//     InstructionType,
//     InstructionValueA,
//     InstructionAddressA,
//     InstructionValueB,
//     InstructionAddressB,
//     InstructionValueC,
//     InstructionAddressC,
//     InstructionPCCurr,
//     InstructionPCNext,
// }


// impl Identifier {
//     // TODO: Return a Result<> with Error
//     fn from_string(s: &str) -> Identifier {
//         // Parse the string and match it to the corresponding enum variant
//         match s {
//             s if s.starts_with("TRACE_CHALLENGE_") => {
//                 let mut index = 0;
//                 sscanf!(s, "TRACE_CHALLENGE_{u8}", index).unwrap();
//                 Identifier::TraceChallenge(index)
//             },
//             s if s.starts_with("TRACE_RESPONSE_") => {
//             },
//             s if s.starts_with("TRACE_RESPONSE_PC_") => {
//             },
//             s if s.starts_with("MERKLE_CHALLENGE_A_") => {
//             },
//             // Add more patterns for other enum variants as needed
//             _ => panic!("Unrecognizable identifier"),
//         }
//     }
// }

// impl fmt::Display for Identifier {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         match self {
//             Identifier::TraceChallenge(index) => write!(f, "TRACE_CHALLENGE_{}", index),
//             Identifier::TraceResponse(index) => write!(f, "TRACE_RESPONSE_{}", index),
//             Identifier::TraceResponsePC(index) => write!(f, "TRACE_RESPONSE_PC_{}", index),
//             Identifier::MerkleChallengeA(index) => write!(f, "MERKLE_CHALLENGE_A_{}", index),
//             Identifier::MerkleResponseA(index) => write!(f, "MERKLE_RESPONSE_A_{}", index),
//             Identifier::MerkleChallengeB(index) => write!(f, "MERKLE_CHALLENGE_B_{}", index),
//             Identifier::MerkleResponseB(index) => write!(f, "MERKLE_RESPONSE_B_{}", index),
//             Identifier::MerkleChallengeCPrev(index) => write!(f, "MERKLE_CHALLENGE_C_PREV_{}", index),
//             Identifier::MerkleResponseCNext(index) => write!(f, "MERKLE_RESPONSE_C_NEXT{}", index),
//             Identifier::MerkleResponseCNextSibling(index) => write!(f, "MERKLE_RESPONSE_C_NEXT_SIBLING_{}", index),
//             Identifier::MerkleResponseCPrev(index) => write!(f, "MERKLE_RESPONSE_C_PREV_{}", index),
//             Identifier::InstructionType => write!(f, "INSTRUCTION_TYPE"),
//             Identifier::InstructionValueA => write!(f, "INSTRUCTION_VALUE_A"),
//             Identifier::InstructionAddressA => write!(f, "INSTRUCTION_ADDRESS_A"),
//             Identifier::InstructionValueB => write!(f, "INSTRUCTION_VALUE_B"),
//             Identifier::InstructionAddressB => write!(f, "INSTRUCTION_ADDRESS_B"),
//             Identifier::InstructionValueC => write!(f, "INSTRUCTION_VALUE_C"),
//             Identifier::InstructionAddressC => write!(f, "INSTRUCTION_ADDRESS_C"),
//             Identifier::InstructionPCCurr => write!(f, "INSTRUCTION_PC_CURR"),
//             Identifier::InstructionPCNext => write!(f, "INSTRUCTION_PC_NEXT"),
//         }
//     }
// }

// // TODO: Currently the model is only ever used to retrieve u32 or u160 values and for u1 bits in case of Challenges. All values are stored as u1 or u2 though so it seems like we can improve that
// struct Model {
//     complete_values: HashMap<Identifier, CommitmentValue>,
//     unfinished_words: HashMap<Identifier, [Option<u8>; 32]>,
//     unfinished_hashes: HashMap<Identifier, [Option<u8>; 32]>
// }


// trait ModelTrait {
//     // TODO: In case the Player sets the CommitmentValue itself they could instantly store an entire
//     // Word or Hash without having to specify all u2 values. In javascript player.preimage()
//     // sets the value when actor.preimage() is called in a script (which is only for u2 values)
//     //
//     // Set identifiers bit_commitment digit or single bit to value
//     fn set(&self, id: &str, value: Digit) {
           

//     }


// }
