import { bit_state_commit, bit_state_unlock } from '../scripts/opcodes/u32_state.js';
import { u160_state_commit, u160_state_unlock } from '../scripts/opcodes/u160_std.js';
import { Leaf } from '../transactions/transaction.js'
import { u160_state_justice_leaves } from './justice-leaf.js';


export class Commit1BitLeaf extends Leaf { 

    lock(vicky, paul, identifier) {
        this._identifier = identifier
        return [
            bit_state_commit(vicky, identifier),
            vicky.pubkey,
            OP_CHECKSIGVERIFY,
            paul.pubkey,
            OP_CHECKSIG
        ]
    }

    unlock(vicky, paul, value){
        return [ 
            paul.sign(this), 
            vicky.sign(this), 
            bit_state_unlock(vicky, this._identifier, value)
        ]
    }
}


export class Commit160BitLeaf extends Leaf { 

    lock(vicky, paul, identifier) {
        this._identifier = identifier
        return [
            u160_state_commit(paul, identifier),
            vicky.pubkey,
            OP_CHECKSIGVERIFY,
            paul.pubkey,
            OP_CHECKSIG
        ]
    }

    unlock(vicky, paul, value){
        return [ 
            paul.sign(this), 
            vicky.sign(this), 
            u160_state_unlock(paul, this._identifier, value)
        ]
    }
}


export function challengeResponseSequence(vicky, paul, identifier, length){
    let result = []
    for (let i=0; i < length; i++){
        result.push([[Commit160BitLeaf, vicky, paul, `${identifier}_response_${i}`]])
        result.push([[Commit1BitLeaf, vicky, paul, `${identifier}_challenge_${i}`]])
    }
    return result
}




export function justiceRoot(vicky, paul, roundCount, identifier = '') {
    // The tree contains all equivocation leaves
    return loop(roundCount, i => u160_state_justice_leaves(paul, vicky, `${identifier}_response_${i}`)).flat(1)
        // [
        // // TODO: add a timeout clause here 
        // // for the Prover to take if he's innocent
        
        // // TODO: implement this too
        // // paul.pubkey,
        // // OP_CHECKSIG
        // ]
    // ]
}
