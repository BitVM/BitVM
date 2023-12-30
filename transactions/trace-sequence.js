import { Leaf, Transaction, EndTransaction } from '../transactions/transaction.js'
import { u160_state_justice_leaves } from './justice-leaf.js';
import { LOG_TRACE_LEN, TIMEOUT, VICKY, PAUL } from './bitvm-player.js';


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
            paul.unlock.traceResponse(roundIndex),
        ]
    }
}




export class TraceResponse extends Transaction {
    static taproot(state){
        return [[ TraceResponseLeaf, state.vicky, state.paul, this.INDEX]]
    }
} 

export class TraceChallenge extends Transaction {
    static taproot(state){
        return [[ TraceChallengeLeaf, state.vicky, state.paul, this.INDEX]]
    }
} 




export class TraceResponseTimeoutLeaf extends Leaf { 

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

export class TraceChallengeTimeoutLeaf extends Leaf { 

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



export function traceSequence(vicky, paul){
    let result = []
    for (let i=0; i < LOG_TRACE_LEN; i++){
        result.push([[TraceResponseLeaf, vicky, paul, i]])
        result.push([[TraceChallengeLeaf, vicky, paul, i]])
    }
    return result
}




export function justiceRoot(vicky, paul, roundCount, responseIdFn) {
    // The tree contains all equivocation leaves
    return loop(roundCount, i => u160_state_justice_leaves(paul, vicky, responseIdFn(i) )).flat(1)
        // [
        // // TODO: add a timeout clause here 
        // // for the Prover to take if he's innocent
        
        // // TODO: implement this too
        // // paul.pubkey,
        // // OP_CHECKSIG
        // ]
    // ]
}
