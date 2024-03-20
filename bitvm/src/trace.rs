use bitcoin::ScriptBuf as Script;
use bitcoin::opcodes::{OP_TRUE};
use bitvm_macros::LeafGetters;
use scripts::opcodes::{pushable};
use scripts::leaf::{Leaf, LeafGetters, Leaves};
use bitcoin_script::bitcoin_script as script;
use super::model::{Paul, Vicky};
use super::graph::BitVmParams;

#[derive(LeafGetters)]
pub struct KickOffLeaf<'a> {
    paul: &'a mut dyn Paul,
    vicky: &'a mut dyn Vicky,
}

impl Leaf for KickOffLeaf<'_> {
    fn lock(&mut self) -> Script {
        todo!("Implement me")
    }

    fn unlock(&mut self) -> Script {
        todo!("Implement me")
    }
}

pub fn kick_off<'a>(params: BitVmParams) -> Leaves<'a> {
    vec![
        &KickOffLeaf{ vicky: todo!(), paul: todo!()}
    ]
}


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

pub fn trace_challenge<'a, const ROUND_INDEX: u8>(params: BitVmParams) -> Leaves<'a> {
    vec![
        &TraceChallengeLeaf{ vicky: todo!(), paul: todo!(), round_index: ROUND_INDEX }
    ]
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


