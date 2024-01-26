import { Leaf, TimeoutLeaf, Transaction, EndTransaction } from '../scripts/transaction.js'
import { u160_state_justice_leaves } from '../scripts/justice-leaf.js';
import { LOG_TRACE_LEN, TIMEOUT, VICKY, PAUL } from './constants.js';


export class TraceChallengeLeaf extends Leaf { 

    lock(vicky, paul, roundIndex) {
        return [
            vicky.commit.traceChallenge(roundIndex),
            vicky.pubkey,
            // OP_CHECKSIGVERIFY,
            // paul.pubkey,
            OP_CHECKSIG,
        ]
    }

    unlock(vicky, paul, roundIndex){
        return [ 
            // paul.sign(this), // TODO
            vicky.sign(this), 
            vicky.unlock.traceChallenge(roundIndex),
        ]
    }
}

export class TraceResponseLeaf extends Leaf { 

    lock(vicky, paul, roundIndex) {
        return [
            paul.commit.traceResponse(roundIndex),
            paul.commit.traceResponsePc(roundIndex),
            // vicky.pubkey,
            // OP_CHECKSIGVERIFY,
            paul.pubkey,
            OP_CHECKSIG,
        ]
    }

    unlock(vicky, paul, roundIndex){
        return [ 
            paul.sign(this), 
            // vicky.sign(this),
            paul.unlock.traceResponsePc(roundIndex),
            paul.unlock.traceResponse(roundIndex),
        ]
    }
}




export class TraceResponse extends Transaction {
    static ACTOR = PAUL
    static taproot(state){
        return [[ TraceResponseLeaf, state.vicky, state.paul, this.INDEX]]
    }
} 

export class TraceChallenge extends Transaction {
    static ACTOR = VICKY
    static taproot(state){
        return [[ TraceChallengeLeaf, state.vicky, state.paul, this.INDEX]]
    }
} 




export class TraceResponseTimeoutLeaf extends TimeoutLeaf { 

    lock(vicky, paul) {
        return [
            TIMEOUT,
            OP_CHECKSEQUENCEVERIFY,
            OP_DROP,
            vicky.pubkey,
            OP_CHECKSIG,
        ]
    }

    unlock(vicky, paul){
        return [ 
            vicky.sign(this), 
        ]
    }
}


export class TraceResponseTimeout extends EndTransaction {
    static ACTOR = VICKY
    static taproot(state){
        return [[ TraceResponseTimeoutLeaf, state.vicky, state.paul]]
    }
} 

export class TraceChallengeTimeoutLeaf extends TimeoutLeaf { 

    lock(vicky, paul) {
        return [
            TIMEOUT,
            OP_CHECKSEQUENCEVERIFY,
            OP_DROP,
            paul.pubkey,
            OP_CHECKSIG,
        ]
    }

    unlock(vicky, paul){
        return [ 
            paul.sign(this), 
        ]
    }
}

export class TraceChallengeTimeout extends EndTransaction {
    static ACTOR = PAUL
    static taproot(state){
        return [[ TraceChallengeTimeoutLeaf, state.vicky, state.paul]]
    }
} 


