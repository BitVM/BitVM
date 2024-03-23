use crate::graph::BitVmLeaf;
use bitcoin_script::bitcoin_script as script;
use tapscripts::opcodes::pushable;


pub fn kick_off() -> Vec<BitVmLeaf> {
    vec![BitVmLeaf {
        lock: |model| script! {
            OP_TRUE
        },
        
        unlock: |model| script! {
        },
    }]
}

pub fn trace_challenge<const ROUND_INDEX: u8>() -> Vec<BitVmLeaf> {
    vec![BitVmLeaf {
        lock: |model| script! {
            { model.vicky.commit().trace_challenge(ROUND_INDEX) }
            // { model.vicky.pubkey}
            // OP_CHECKSIGVERIFY
            // { model.paul.pubkey }
            // OP_CHECKSIG
            OP_TRUE
        },

        unlock: |model| script! {
            // { model.paul.sign(this) } // TODO
            // { model.vicky.sign(this) } // TODO
            { model.vicky.unlock().trace_challenge(ROUND_INDEX) }
        }
    }]
}

pub fn trace_response<const ROUND_INDEX: u8>() -> Vec<BitVmLeaf> {
    vec![BitVmLeaf {
        lock: |model| script! {
            { model.paul.commit().trace_response(ROUND_INDEX) }
            { model.paul.commit().trace_response_pc(ROUND_INDEX) }
            // { model.vicky.pubkey }
            // OP_CHECKSIGVERIFY
            // { model.paul.pubkey }
            // OP_CHECKSIG
            OP_TRUE
        },

        unlock: |model| script! {
            // { model.paul.sign(this) }
            // { model.vicky.sign(this) }  // TODO
            { model.paul.unlock().trace_response_pc(ROUND_INDEX) }
            { model.paul.unlock().trace_response(ROUND_INDEX) }
        }
    }]
}


// impl Leaf for TraceResponseTimeoutLeaf<'_> {
//     fn lock(&mut self) -> Script {
//         script! {
//             { model.timeout}
//             OP_CSV
//             OP_DROP
//             // { model.vicky.pubkey}
//             // OP_CHECKSIG
//             OP_TRUE
//         }
//     }

//     fn unlock(&mut self) -> Script {
//         script! {
//             // { model.vicky.sign(this), // TODO}
//         }
//     }
// }

// export class TraceResponseTimeout extends EndTransaction {
//     static ACTOR = VICKY
//     static taproot(state){
//         script!{[ TraceResponseTimeoutLeaf, state.vicky, state.paul]]
//     }
// }


// impl Leaf for TraceChallengeTimeoutLeaf<'_> {
//     fn lock(&mut self) -> Script {
//         script! {
//             { model.timeout}
//             { model.timeout}
//             OP_CSV
//             OP_DROP
//             // // model.paul.pubkey
//             // OP_CHECKSIG
//             {OP_TRUE}
//         }
//     }

//     fn unlock(&mut self) -> Script {
//         script! {
//             1 // model.paul.sign(this),
//         }
//     }
// }

// export class TraceChallengeTimeout extends EndTransaction {
//     static ACTOR = PAUL
//     static taproot(state){
//         script!{[ TraceChallengeTimeoutLeaf, state.vicky, state.paul]]
//     }
// }
