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
    u160_fromaltstack,
    u160_notequal,
} from '../scripts/opcodes/u160_std.js'
import { Tap, Tx, Address, Signer } from '../libs/tapscript.js'
import { broadcastTransaction } from '../libs/esplora.js'
import { blake3_160 } from '../scripts/opcodes/blake3.js'
import { Leaf } from '../transactions/transaction.js'
import { 
    LOG_PATH_LEN,
    PATH_LEN,
    LOG_TRACE_LEN,
    MERKLE_CHALLENGE_SELECT,
    MERKLE_ROOT_CHALLENGE_SELECT
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

    lock(vicky, roundIndex) {
        return [
            // Unlock a challenge for Paul
            OP_RIPEMD160,
            vicky.hashlock(MERKLE_CHALLENGE_SELECT, roundIndex),
            OP_EQUALVERIFY,

            // Read childIndex
            vicky.push.nextMerkleIndex(roundIndex),
            OP_TOALTSTACK,


            // Read parentIndex
            vicky.push.merkleIndex,
            

            // Check childIndex - parentIndex == 1
            OP_FROMALTSTACK,
            OP_SUB,
            OP_1,
            OP_NUMEQUALVERIFY,

            // TODO: Verify the covenant
            OP_TRUE
        ]
    }

    unlock(vicky, roundIndex) {
        return [
            vicky.unlock.merkleIndex,
            vicky.unlock.nextMerkleIndex(roundIndex),
            vicky.preimage(MERKLE_CHALLENGE_SELECT, roundIndex),
        ]
    }
}

export class RootSelectorLeaf extends Leaf {

    lock(vicky, roundIndex) {
        return [
            // Unlock a challenge for Paul
            OP_RIPEMD160,
            vicky.hashlock(MERKLE_ROOT_CHALLENGE_SELECT),
            OP_EQUALVERIFY,

            // Read parentIndex and ensure it is 0
            vicky.push.merkleIndex,
            0, OP_EQUALVERIFY,

            // TODO: Verify the covenant
            OP_TRUE
        ]
    }

    unlock(vicky, roundIndex) {
        return [
            vicky.unlock.merkleIndex,
            vicky.preimage(MERKLE_ROOT_CHALLENGE_SELECT),
        ]
    }
}


export const selectorRoot = vicky => [
    [SelectorLeaf, vicky, 0],
    [SelectorLeaf, vicky, 1],
    [SelectorLeaf, vicky, 2],
    [SelectorLeaf, vicky, 3],
    [RootSelectorLeaf, vicky],
]


export class MerkleHashLeaf extends Leaf {

    lock(vicky, paul, roundIndex) {
        return [
            // Ensure we're executing only the challenge that Vicky unlocked
            OP_RIPEMD160,
            vicky.hashlock(MERKLE_CHALLENGE_SELECT, roundIndex),
            OP_EQUALVERIFY,

            // Read the child hash
            paul.push.merkleResponse(roundIndex),
            blake3_160,
            u160_toaltstack,
            // Read the parent hash
            paul.push.merkleResponse(LOG_PATH_LEN - 1),
            
            // TODO: read the bit from address to figure out if we have to swap the two nodes before hashing
            u160_fromaltstack,
            u160_swap_endian,
            u160_equalverify,
            OP_TRUE, // TODO: verify the covenant here
        ]
    }

    unlock(vicky, paul, roundIndex) {
        return [
            paul.unlock.merkleResponse(roundIndex),
            paul.unlock.merkleResponseSibling(roundIndex),
            paul.unlock.merkleResponse(LOG_PATH_LEN - 1),
            vicky.preimage(MERKLE_CHALLENGE_SELECT, roundIndex),
        ]
    }

}


export class MerkleRootHashLeaf extends Leaf {

    lock(vicky, paul) {
        return [
            // Ensure we're executing only the challenge that Vicky unlocked
            OP_RIPEMD160,
            vicky.hashlock(MERKLE_ROOT_CHALLENGE_SELECT),
            OP_EQUALVERIFY,

            // Read the child hash
            paul.push.merkleResponse(LOG_PATH_LEN - 1),
            blake3_160,
            u160_toaltstack,
            // Read the parent hash
            paul.push.traceResponse(LOG_TRACE_LEN - 1),
            
            // TODO: read the bit from address to figure out if we have to swap the two nodes before hashing
            u160_fromaltstack,
            u160_swap_endian,
            u160_equalverify,
            OP_TRUE, // TODO: verify the covenant here
        ]
    }

    unlock(vicky, paul) {
        return [
            paul.unlock.merkleResponse(LOG_PATH_LEN - 1),
            paul.unlock.merkleResponseSibling(LOG_PATH_LEN - 1),
            paul.unlock.traceResponse(LOG_TRACE_LEN - 1),
            vicky.preimage(MERKLE_ROOT_CHALLENGE_SELECT),
        ]
    }
}



export const merkleHashRoot = (vicky, paul) => [
    [MerkleHashLeaf, vicky, paul, 0],
    [MerkleHashLeaf, vicky, paul, 1],
    [MerkleHashLeaf, vicky, paul, 2],
    [MerkleHashLeaf, vicky, paul, 3],
    [MerkleRootHashLeaf, vicky, paul],
]



export class DisproveMerkleRootLeaf extends Leaf {
    // TODO: we can optimize this. only a single bit is required to prove non-equality of two hashes
    lock(vicky, paul, traceIndex) {
        return [
            
            // Verify that the merkleIndex is zero
            vicky.push.merkleIndex,
            0,
            OP_EQUALVERIFY,

            // Verify that we're using the correct trace response
            vicky.push.traceIndex,
            traceIndex,
            OP_EQUALVERIFY,

            // Verify that the Merkle root is not equal to the trace response
            paul.push.merkleResponse(LOG_PATH_LEN - 1),
            u160_toaltstack,
            paul.push.traceResponse(traceIndex),
            u160_fromaltstack,
            u160_notequal,
            OP_VERIFY,

            // TODO: verify the covenant here
            OP_TRUE,
        ]
    }

    unlock(vicky, paul, traceIndex) {
        return [
            paul.unlock.merkleResponse(LOG_PATH_LEN - 1),
            paul.unlock.traceResponse(traceIndex),
            vicky.unlock.traceIndex,
            vicky.unlock.merkleIndex,
        ]
    }
}

export const merkleJusticeRoot = (vicky, paul) => [
    // The tree contains all equivocation leaves
    // ...justiceRoot(vicky, paul, roundCount, MERKLE_RESPONSE),  // TODO
    ...loop(PATH_LEN, i => [DisproveMerkleRootLeaf, vicky, paul, i])
]

const bisectionSequence = (vicky, paul) => {
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
    merkleHashRoot(vicky, paul),
    merkleJusticeRoot(vicky, paul)
]