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
import { justiceRoot, challengeResponseSequence } from './reveal-sequence.js'

const IDENTIFIER_MERKLE = 'MERKLE_CHALLENGE'

// Depth of the Merkle tree 
const N = 32
// Number of queries we need
const H = 5 // = log2(N)


function trailingZeros(n) {
    let count = 0;
    while ((n & 1) === 0 && n !== 0) count++, n >>= 1;
    return count;
}


export class SelectorLeaf extends Leaf {

    lock(vicky, length, isAbove) {
        return [

            OP_RIPEMD160,
            vicky.hashlock(IDENTIFIER_MERKLE, length, isAbove),
            OP_EQUALVERIFY,

            // sibelIndex = i0 i1 i2 ... i_{length-1} 1 0 0 ... 0 0
            0,
            loop(length, i => [
                OP_SWAP,
                bit_state(vicky, `merkle_challenge_${H - 1 - i}`),
                OP_IF,
                2 ** (H - 1 - i),
                OP_ADD,
                OP_ENDIF
            ]),
            2 ** (H - 1 - length),
            OP_ADD,
            OP_TOALTSTACK,
            // Now sibelIndex is on the stack


            // endIndex
            0,
            loop(H, i => [
                OP_SWAP,
                bit_state(vicky, `merkle_challenge_${H - 1 - i}`),
                OP_IF,
                2 ** (H - 1 - i),
                OP_ADD,
                OP_ENDIF
            ]),
            // Now endIndex is on the stack


            // check  |sibelIndex - endIndex| == 1
            // 
            OP_FROMALTSTACK,
            OP_SUB,
            !isAbove ? OP_NEGATE : '',
            OP_1,
            OP_NUMEQUALVERIFY,
            OP_TRUE // TODO: verify the covenant here
        ]
    }

    unlock(vicky, length, isAbove, endIndex) {
        const sibelIndex = endIndex + (isAbove ? -1 : 1)
        const expectedLength = H - trailingZeros(sibelIndex) - 1
        if (expectedLength != length)
            throw `Invalid leaf: endIndex: 0b${endIndex.toString(2)}, length: ${length}, expectedLength: ${expectedLength}`

        return [

            // endIndex
            loop(H, i => bit_state_unlock(vicky, `merkle_challenge_${H - 1 - i}`, endIndex >>> (H - 1 - i) & 1)).reverse(),

            // sibelIndex
            loop(length, i => bit_state_unlock(vicky, `merkle_challenge_${H - 1 - i}`, sibelIndex >>> (H - 1 - i) & 1)).reverse(),

            // unlock the corresponding challenge
            vicky.preimage(IDENTIFIER_MERKLE, length, isAbove),
        ]
    }
}


export function selectorRoot(vicky) {
    return [
        [SelectorLeaf, vicky, 0, 0],
        [SelectorLeaf, vicky, 1, 0],
        [SelectorLeaf, vicky, 2, 0],
        [SelectorLeaf, vicky, 3, 0],

        [SelectorLeaf, vicky, 0, 1],
        [SelectorLeaf, vicky, 1, 1],
        [SelectorLeaf, vicky, 2, 1],
        [SelectorLeaf, vicky, 3, 1],
    ]
}


export class MerkleRoundLeaf extends Leaf {
    lock(vicky, paul, index, isAbove) {
        return [
            OP_RIPEMD160,
            vicky.hashlock(IDENTIFIER_MERKLE, index, isAbove),
            OP_EQUALVERIFY,
            u160_state(paul, `merkle_response_${ isAbove ? index : H }`),
            blake3_160,
            u160_toaltstack,
            u160_state(paul, `merkle_response_${ isAbove ? H : index }`),
            // TODO: add root here 
            u160_fromaltstack,
            u160_swap_endian,
            u160_equalverify,
            OP_TRUE, // TODO: verify the covenant here
        ]
    }

    unlock(vicky, paul, index, isAbove, sibling, childHash, parentHash, merkleIndex) {
        return [
            u160_state_unlock(paul, `merkle_response_${H}`, parentHash),
            pushHexEndian(sibling),
            u160_state_unlock(paul, `merkle_response_${index}`, childHash),
            vicky.preimage(IDENTIFIER_MERKLE, index, isAbove),
        ]
    }

}



export function blakeRoot(vicky, paul) {
    return [
        [MerkleRoundLeaf, vicky, paul, 0, 0],
        [MerkleRoundLeaf, vicky, paul, 1, 0],
        [MerkleRoundLeaf, vicky, paul, 2, 0],
        [MerkleRoundLeaf, vicky, paul, 3, 0],

        [MerkleRoundLeaf, vicky, paul, 0, 1],
        [MerkleRoundLeaf, vicky, paul, 1, 1],
        [MerkleRoundLeaf, vicky, paul, 2, 1],
        [MerkleRoundLeaf, vicky, paul, 3, 1]
    ]
}



export class DisproveMerkleLeaf extends Leaf {
    // TODO: we can optimize this. only a single bit is required to prove non-equality of two hashes
    lock(vicky, paul, index) {
        return [
            // TODO: Verify that we're in the case containing the root hash of the Merkle path
            // verify for i in [0..H]: merkle_challenge_i == 0

            // TODO: Verify that we're picking the correct root from the trace
            // verify sum(for i in [0..32], 2**i * trace_challenge_i) == index

            u160_state(paul, `merkle_response_${H}`),
            u160_toaltstack,
            u160_state(paul, `trace_response_${index}`),
            u160_fromaltstack,
            u160_equalverify, // TODO: should be u160_NOTequalverify
            OP_TRUE // TODO: verify the covenant here
        ]
    }

    unlock(vicky, paul, index, sibling, childHash, parentHash, merkleIndex, isAbove) {
        return [
            u160_state_unlock(paul, `merkle_response_${H}`, parentHash),
            pushHexEndian(sibling),
            u160_state_unlock(paul, `merkle_response_${index}`, childHash),
            vicky.preimage(IDENTIFIER_MERKLE, index, isAbove),
        ]
    }
}


export function merkleJusticeRoot(vicky, paul, roundCount) {
    // The tree contains all equivocation leaves
    return [
        ...justiceRoot(vicky, paul, roundCount, 'merkle'),
        ...loop(32, i => [DisproveMerkleLeaf, vicky, paul, i])
    ]
}


export function merkleSequence(vicky, paul) {
    return [
        ...challengeResponseSequence(vicky, paul, 'merkle', H),
        selectorRoot(vicky),
        blakeRoot(vicky, paul),
        merkleJusticeRoot(vicky, paul, H),
    ]
}