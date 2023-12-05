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
    justiceRoot,
    binarySearchSequence,
    TRACE_RESPONSE,
    MERKLE_CHALLENGE,
    MERKLE_RESPONSE,
} from './binary-search-sequence.js'

const MERKLE_CHALLENGE_SELECT = 'MERKLE_CHALLENGE_SELECT'



// Depth of the Merkle tree 
const N = 32
// Number of queries we need
const H = 5 // = log2(N)


const trailingZeros = n => {
    let count = 0
    while ((n & 1) === 0 && n !== 0) count++, n >>= 1
    return count
}


const endIndex = vicky => [
    0,
    loop(H, i => [
        OP_SWAP,
        bit_state(vicky, MERKLE_CHALLENGE(H - 1 - i)),
        OP_IF,
            2 ** (H - 1 - i),
            OP_ADD,
        OP_ENDIF
    ])
    // Now endIndex is on the stack
]

const endIndex_unlock = (vicky, endIndex) =>
    loop(H, i => bit_state_unlock(vicky, MERKLE_CHALLENGE(H - 1 - i), endIndex >>> (H - 1 - i) & 1))
    .reverse()


const sibelIndex = (vicky, length) => [
    // sibelIndex = i0 i1 i2 ... i_{length-1} 1 0 0 ... 0 0
    0,
    loop(length, i => [
        OP_SWAP,
        bit_state(vicky, MERKLE_CHALLENGE(H - 1 - i)),
        OP_IF,
            2 ** (H - 1 - i),
            OP_ADD,
        OP_ENDIF
    ]),
    2 ** (H - 1 - length),
    OP_ADD,
    // Now sibelIndex is on the stack
]


const sibelIndex_unlock = (vicky, length, sibelIndex) =>
    loop(length, i => bit_state_unlock(vicky, MERKLE_CHALLENGE(H - 1 - i), sibelIndex >>> (H - 1 - i) & 1))
    .reverse()


export class SelectorLeaf extends Leaf {

    lock(vicky, length, isAbove) {
        return [

            OP_RIPEMD160,
            vicky.hashlock(MERKLE_CHALLENGE_SELECT, length, isAbove),
            OP_EQUALVERIFY,

            // Read sibelIndex
            sibelIndex(vicky, length),
            OP_TOALTSTACK,


            // Read endIndex
            endIndex(vicky),
            

            // Check  |sibelIndex - endIndex| == 1
            OP_FROMALTSTACK,
            OP_SUB,
            isAbove ? OP_NOP : OP_NEGATE,
            OP_1,
            OP_NUMEQUALVERIFY,

            // TODO: Verify the covenant
            OP_TRUE
        ]
    }

    unlock(vicky, length, isAbove, endIndex) {
        const sibelIndex = endIndex + (isAbove ? -1 : 1)
        const expectedLength = H - trailingZeros(sibelIndex) - 1
        if (expectedLength != length)
            throw `Invalid leaf: endIndex: 0b${endIndex.toString(2)}, length: ${length}, expectedLength: ${expectedLength}`

        return [

            // endIndex
            endIndex_unlock(vicky, endIndex),

            // sibelIndex
            sibelIndex_unlock(vicky, length, sibelIndex),

            // unlock the corresponding challenge
            vicky.preimage(MERKLE_CHALLENGE_SELECT, length, isAbove),
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
            u160_state(paul, MERKLE_RESPONSE(isAbove ? index : H)),
            blake3_160,
            u160_toaltstack,
            u160_state(paul, MERKLE_RESPONSE(isAbove ? H : index)),
            // TODO: add root here 
            u160_fromaltstack,
            u160_swap_endian,
            u160_equalverify,
            OP_TRUE, // TODO: verify the covenant here
        ]
    }

    unlock(vicky, paul, index, isAbove, sibling, childHash, parentHash, merkleIndex) {
        return [
            u160_state_unlock(paul, MERKLE_RESPONSE(H), parentHash),
            pushHexEndian(sibling),
            u160_state_unlock(paul, MERKLE_RESPONSE(index), childHash),
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
    lock(vicky, paul, index) {
        return [
            // Verify that endIndex == 0
            endIndex(vicky),
            0,
            OP_EQUALVERIFY,

            // TODO: Verify that we're picking the correct root from the trace
            // verify sum(for i in [0..32], 2**i * trace_challenge_i) == index

            u160_state(paul, MERKLE_RESPONSE(H)),
            u160_toaltstack,
            u160_state(paul, TRACE_RESPONSE(index)),
            u160_fromaltstack,
            u160_equalverify, // TODO: should be u160_NOTequalverify
            OP_TRUE // TODO: verify the covenant here
        ]
    }

    unlock(vicky, paul, index, sibling, childHash, parentHash, merkleIndex, isAbove) {
        return [
            u160_state_unlock(paul, MERKLE_RESPONSE(H), parentHash),
            pushHexEndian(sibling),
            // TODO: figure out which trace response is the correct one
            u160_state_unlock(paul, TRACE_RESPONSE(index), childHash),
            // vicky.preimage(MERKLE_CHALLENGE_SELECT, index, isAbove),
            endIndex_unlock(vicky, endIndex),
        ]
    }
}

export const merkleJusticeRoot = (vicky, paul, roundCount) => [
    // The tree contains all equivocation leaves
    ...justiceRoot(vicky, paul, roundCount, MERKLE_RESPONSE),
    ...loop(32, i => [DisproveMerkleRootLeaf, vicky, paul, i])
]

export const merkleSequence = (vicky, paul) => [
    ...binarySearchSequence(vicky, paul, MERKLE_CHALLENGE, MERKLE_RESPONSE, H),
    selectorRoot(vicky),
    merkleRoundRoot(vicky, paul),
    merkleJusticeRoot(vicky, paul, H),
]