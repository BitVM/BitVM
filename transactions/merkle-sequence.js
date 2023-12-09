import { pushHex, pushHexEndian } from '../scripts/utils.js'
import { bit_state, bit_state_commit, bit_state_unlock } from '../scripts/opcodes/u32_state.js'
import {
    u160_state_commit,
    u160_state_unlock,
    u160_state,
    u160_equalverify,
    u160_push,
    u160_swap_endian,
    u160_toaltstack,
    u160_fromaltstack
} from '../scripts/opcodes/u160_std.js'
import { Tap, Tx, Address, Signer } from '../libs/tapscript.js'
import { broadcastTransaction } from '../libs/esplora.js'
import { blake3_160 } from '../scripts/opcodes/blake3.js'
import { Leaf } from '../transactions/transaction.js'
import { 
    LOG_PATH_LEN,
    PATH_LEN,
    MERKLE_CHALLENGE,
    MERKLE_CHALLENGE_SELECT
} from '../transactions/bitvm-player.js'



export class MerkleChallengeLeaf extends Leaf { 

    lock(vicky, paul, roundIndex) {
        return [
            vicky.commit.merkleChallenge(roundIndex),
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
            vicky.unlock.merkleChallenge(roundIndex),
        ]
    }
}

export class MerkleResponseLeaf extends Leaf { 

    lock(vicky, paul, roundIndex) {
        return [
            paul.commit.merkleResponse(roundIndex),
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
            paul.unlock.merkleResponse(roundIndex),
        ]
    }
}



const trailingZeros = n => {
    let count = 0
    while ((n & 1) === 0 && n !== 0) count++, n >>= 1
    return count
}

export class SelectorLeaf extends Leaf {

    lock(vicky, roundIndex, isAbove) {
        return [

            OP_RIPEMD160,
            vicky.hashlock(MERKLE_CHALLENGE_SELECT, roundIndex, isAbove),
            OP_EQUALVERIFY,

            // Read siblingIndex
            vicky.push.nextMerkleIndex(roundIndex),
            OP_TOALTSTACK,


            // Read endIndex
            vicky.push.merkleIndex,
            

            // Check  |siblingIndex - endIndex| == 1
            OP_FROMALTSTACK,
            OP_SUB,
            isAbove ? OP_NOP : OP_NEGATE,
            OP_1,
            OP_NUMEQUALVERIFY,

            // TODO: Verify the covenant
            OP_TRUE
        ]
    }

    unlock(vicky, roundIndex, isAbove) {
        return [
            // endIndex
            vicky.unlock.merkleIndex,

            // siblingIndex
            vicky.unlock.nextMerkleIndex(roundIndex),

            // unlock the corresponding challenge
            vicky.preimage(MERKLE_CHALLENGE_SELECT, roundIndex, isAbove),
        ]
    }
}


export const selectorRoot = vicky => [
    [SelectorLeaf, vicky, 0, 0],
    [SelectorLeaf, vicky, 1, 0],
    [SelectorLeaf, vicky, 2, 0],
    [SelectorLeaf, vicky, 3, 0],

    [SelectorLeaf, vicky, 0, 1],
    [SelectorLeaf, vicky, 1, 1],
    [SelectorLeaf, vicky, 2, 1],
    [SelectorLeaf, vicky, 3, 1],
]



export class MerkleRoundLeaf extends Leaf {
    lock(vicky, paul, index, isAbove) {
        return [
            OP_RIPEMD160,
            vicky.hashlock(MERKLE_CHALLENGE_SELECT, index, isAbove),
            OP_EQUALVERIFY,
            paul.push.merkleResponse(LOG_PATH_LEN),
            blake3_160,
            u160_toaltstack,
            paul.push.merkleResponse(index),
            // TODO: add root here 
            u160_fromaltstack,
            u160_swap_endian,
            u160_equalverify,
            OP_TRUE, // TODO: verify the covenant here
        ]
    }

    unlock(vicky, paul, index, isAbove, sibling) {
        return [
            paul.unlock.merkleResponse(LOG_PATH_LEN),
            pushHexEndian(sibling),  // TODO: where does sibling come from??
            paul.unlock.merkleResponse(index),
            vicky.preimage(MERKLE_CHALLENGE_SELECT, index, isAbove),
        ]
    }

}



export const merkleRoundRoot = (vicky, paul) => [
    [MerkleRoundLeaf, vicky, paul, 0, 0],
    [MerkleRoundLeaf, vicky, paul, 1, 0],
    [MerkleRoundLeaf, vicky, paul, 2, 0],
    [MerkleRoundLeaf, vicky, paul, 3, 0],

    [MerkleRoundLeaf, vicky, paul, 0, 1],
    [MerkleRoundLeaf, vicky, paul, 1, 1],
    [MerkleRoundLeaf, vicky, paul, 2, 1],
    [MerkleRoundLeaf, vicky, paul, 3, 1]
]




export class DisproveMerkleRootLeaf extends Leaf {
    // TODO: we can optimize this. only a single bit is required to prove non-equality of two hashes
    lock(vicky, paul, traceIndex) {
        return [
            // Verify that endIndex == 0
            vicky.push.merkleIndex,
            0,
            OP_EQUALVERIFY,

            // TODO: Verify that we're picking the correct root from the trace
            // verify sum(for i in [0..32], 2**i * trace_challenge_i) == index

            paul.push.merkleResponse(LOG_PATH_LEN),
            u160_toaltstack,
            paul.push.traceResponse(traceIndex),
            u160_fromaltstack,
            u160_equalverify, // TODO: should be u160_NOTequalverify
            OP_TRUE // TODO: verify the covenant here
        ]
    }

    unlock(vicky, paul, traceIndex) {
        return [
            paul.unlock.merkleResponse(LOG_PATH_LEN),
            // pushHexEndian(sibling),
            paul.unlock.merkleResponseSibling(LOG_PATH_LEN),
            // TODO: figure out which trace response is the correct one
            paul.unlock.traceResponse(traceIndex),
            // vicky.preimage(MERKLE_CHALLENGE_SELECT, index, isAbove),
            vicky.unlock.merkleIndex,
        ]
    }
}

export const merkleJusticeRoot = (vicky, paul, roundCount) => [
    // The tree contains all equivocation leaves
    // ...justiceRoot(vicky, paul, roundCount, MERKLE_RESPONSE),  // TODO
    ...loop(PATH_LEN, i => [DisproveMerkleRootLeaf, vicky, paul, i])
]

function bisectionSequence(vicky, paul){
    let result = []
    for (let i=0; i < LOG_PATH_LEN; i++){
        result.push([[MerkleResponseLeaf, vicky, paul, i]])
        result.push([[MerkleChallengeLeaf, vicky, paul, i]])
    }
    return result
}

export const merkleSequence = (vicky, paul) => [
    ...bisectionSequence(vicky, paul),
    selectorRoot(vicky),
    merkleRoundRoot(vicky, paul),
    merkleJusticeRoot(vicky, paul, LOG_PATH_LEN),
]