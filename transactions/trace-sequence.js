import { Leaf } from '../transactions/transaction.js'
import { u160_state_justice_leaves } from './justice-leaf.js';
import { LOG_TRACE_LEN } from './bitvm-player.js';


export class TraceChallengeLeaf extends Leaf { 

    lock(vicky, paul, roundIndex) {
        return [
            vicky.commit.traceChallenge(roundIndex),
            vicky.pubkey,
            // OP_CHECKSIGVERIFY,
            // paul.pubkey,
            OP_CHECKSIG
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
