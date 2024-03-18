use bitcoin::ScriptBuf as Script;
use bitcoin::opcodes::{OP_TRUE};
use bitvm_macros::LeafGetters;
use crate::scripts::opcodes::{pushable};

use crate::scripts::transaction::{Leaf, LeafGetters};
use bitcoin_script::bitcoin_script as script;
use super::model::{Paul, Vicky};



#[derive(LeafGetters)]
pub struct TraceChallengeLeaf<'a> {
    pub paul: &'a mut dyn Paul,
    pub vicky: &'a mut dyn Vicky,
    pub round_index: u8
}

impl Leaf for TraceChallengeLeaf<'_> { 

    fn lock(&mut self) -> Script {
        script!{
            {self.vicky.commit().trace_challenge(self.round_index)}
            // {self.vicky.pubkey}
            // OP_CHECKSIGVERIFY
            // // self.paul.pubkey
            // OP_CHECKSIG
            { OP_TRUE }
        }
    }

    fn unlock(&mut self) -> Script {
        script!{ 
            // {self.paul.sign(this)} // TODO
            // {self.vicky.sign(this)} // TODO
            {self.vicky.unlock().trace_challenge(self.round_index)}
        }
    }
}

#[derive(LeafGetters)]
pub struct TraceResponseLeaf<'a> {
    pub paul: &'a mut dyn Paul,
    pub vicky: &'a mut dyn Vicky,
    pub round_index: u8
}

impl Leaf for TraceResponseLeaf<'_> { 

    fn lock(&mut self) -> Script {
        script!{
            { self.paul.commit().trace_response(self.round_index) }
            { self.paul.commit().trace_response_pc(self.round_index) }
            // {self.vicky.pubkey}
            // OP_CHECKSIGVERIFY
            // self.paul.pubkey
            // OP_CHECKSIG
            { OP_TRUE }
        }
    }

    fn unlock(&mut self) -> Script {
        script! { 
            // { self.paul.sign(this) }
            // { self.vicky.sign(this) }  // TODO
            {self.paul.unlock().trace_response_pc(self.round_index)}
            {self.paul.unlock().trace_response(self.round_index)}
        }
    }
}




// export class TraceResponse extends Transaction {
//     static ACTOR = PAUL
//     static taproot(state){
//         script!{[ TraceResponseLeaf, state.vicky, state.paul, this.INDEX]]
//     }
// } 

// export class TraceChallenge extends Transaction {
//     static ACTOR = VICKY
//     static taproot(state){
//         script!{[ TraceChallengeLeaf, state.vicky, state.paul, this.INDEX]]
//     }
// } 




#[derive(LeafGetters)]
pub struct TraceResponseTimeoutLeaf<'a> {
    pub paul: &'a mut dyn Paul,
    pub vicky: &'a mut dyn Vicky,
    pub timeout: u32
}

impl Leaf for TraceResponseTimeoutLeaf<'_> { 

    fn lock(&mut self) -> Script {
        script!{
            {self.timeout}
            OP_CSV
            OP_DROP
            // {self.vicky.pubkey}
            // OP_CHECKSIG
            { OP_TRUE }
        }
    }

    fn unlock(&mut self) -> Script {
        script!{ 
            // {self.vicky.sign(this), // TODO}
        }
    }
}


// export class TraceResponseTimeout extends EndTransaction {
//     static ACTOR = VICKY
//     static taproot(state){
//         script!{[ TraceResponseTimeoutLeaf, state.vicky, state.paul]]
//     }
// } 

#[derive(LeafGetters)]
pub struct TraceChallengeTimeoutLeaf<'a> {
    pub paul: &'a mut dyn Paul,
    pub vicky: &'a mut dyn Vicky,
    pub timeout: u32
}

impl Leaf for TraceChallengeTimeoutLeaf<'_> { 

    fn lock(&mut self) -> Script {
        script! {
            {self.timeout}
            OP_CSV
            OP_DROP
            // // self.paul.pubkey
            // OP_CHECKSIG
            {OP_TRUE}
        }
    }

    fn unlock(&mut self) -> Script {
        script!{ 
            1 // self.paul.sign(this), 
        }
    }
}

// export class TraceChallengeTimeout extends EndTransaction {
//     static ACTOR = PAUL
//     static taproot(state){
//         script!{[ TraceChallengeTimeoutLeaf, state.vicky, state.paul]]
//     }
// } 


