import { Leaf } from '../transactions/transaction.js'
import { u160_state_justice_leaves } from './justice-leaf.js';


export const MERKLE_CHALLENGE = index => `MERKLE_CHALLENGE_${index}`
export const MERKLE_RESPONSE = index => `MERKLE_RESPONSE_${index}`

export const TRACE_CHALLENGE = index => `TRACE_CHALLENGE_${index}`
export const TRACE_RESPONSE = index => `TRACE_RESPONSE_${index}`


export class Commit1BitLeaf extends Leaf { 

    lock(vicky, paul, identifier) {
        return [
            vicky.commit.bit_state(identifier),
            //bit_state_commit(vicky, identifier),
            vicky.pubkey,
            // OP_CHECKSIGVERIFY,
            // paul.pubkey,
            OP_CHECKSIG
        ]
    }

    unlock(vicky, paul, identifier, value){
        return [ 
            // paul.sign(this), 
            vicky.sign(this), 
            vicky.unlock.bit_state(identifier),
            //bit_state_unlock(vicky, identifier, value)
        ]
    }
}


export class Commit160BitLeaf extends Leaf { 

    lock(vicky, paul, identifier) {
        return [
            paul.commit.u160_state(identifier),
            // vicky.pubkey,
            // OP_CHECKSIGVERIFY,
            paul.pubkey,
            OP_CHECKSIG,
        ]
    }

    unlock(vicky, paul, identifier){
        return [ 
            paul.sign(this), 
            // vicky.sign(this), 
            paul.unlock.u160_state(identifier),
        ]
    }
}

export class Commit320BitLeaf extends Leaf { 

    lock(vicky, paul, identifierA, identifierB) {
        return [
            paul.commit.u160_state(identifierA),
            paul.commit.u160_state(identifierB),
            vicky.pubkey,
            OP_CHECKSIGVERIFY,
            paul.pubkey,
            OP_CHECKSIG
        ]
    }
    // TODO Unlock order is incorrect for A and B
    unlock(vicky, paul, identifierA, identifierB, value){
        return [ 
            paul.sign(this), 
            vicky.sign(this), 
            paul.unlock.u160_state(identifierA),
            paul.unlock.u160_state(identifierB),
        ]
    }
}


export function binarySearchSequence(vicky, paul, challengeIdFn, responseIdFn, length){
    let result = []
    for (let i=0; i < length; i++){
        result.push([[Commit160BitLeaf, vicky, paul, responseIdFn(i) ]])
        result.push([[Commit1BitLeaf, vicky, paul, challengeIdFn(i) ]])
    }
    return result
}


export function binarySearchSequence320(vicky, paul, challengeIdFn, responseIdFnA, responseIdFnB, length){
    let result = []
    for (let i=0; i < length; i++){
        result.push([[Commit320BitLeaf, vicky, paul, responseIdFnA(i), responseIdFnB(i) ]])
        result.push([[Commit1BitLeaf, vicky, paul, challengeIdFn(i) ]])
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
