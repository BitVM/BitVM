import { pushHex, pushHexEndian } from '../scripts/utils.js'
import { trailingZeros } from '../libs/common.js'
import { bit_state, bit_state_commit, bit_state_unlock } from '../scripts/opcodes/u32_state.js'
import { u32_toaltstack, u32_fromaltstack } from '../scripts/opcodes/u32_std.js'
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
import { broadcastTransaction } from '../libs/esplora.js'
import { blake3_160 } from '../scripts/opcodes/blake3.js'
import { Leaf, TimeoutLeaf, Transaction, EndTransaction } from '../scripts/transaction.js'
import { 
    LOG_TRACE_LEN,
    LOG_PATH_LEN,
    PATH_LEN,
    VICKY,
    PAUL,
    TIMEOUT
} from './constants.js'



export class MerkleChallengeALeaf extends Leaf { 

    lock(vicky, paul, roundIndex) {
        return [
            vicky.commit.merkleChallengeA(roundIndex),
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
            vicky.unlock.merkleChallengeA(roundIndex),
        ]
    }
}

export class MerkleChallengeBLeaf extends Leaf { 

    lock(vicky, paul, roundIndex) {
        return [
            vicky.commit.merkleChallengeB(roundIndex),
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
            vicky.unlock.merkleChallengeB(roundIndex),
        ]
    }
}


export class MerkleChallengeA extends Transaction {
    static ACTOR = VICKY
    static taproot(params) {
        return [
            [MerkleChallengeALeaf, params.vicky, params.paul, this.INDEX]
        ]
    }
}

export class MerkleChallengeB extends Transaction {
    static ACTOR = VICKY
    static taproot(params) {
        return [
            [MerkleChallengeBLeaf, params.vicky, params.paul, this.INDEX]
        ]
    }
}


export class MerkleChallengeATimeoutLeaf extends TimeoutLeaf { 

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

export class MerkleChallengeBTimeoutLeaf extends TimeoutLeaf { 

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


export class MerkleChallengeATimeout extends EndTransaction {
    static ACTOR = PAUL
    static taproot(state){
        return [[ MerkleChallengeATimeoutLeaf, state.vicky, state.paul]]
    }
}

export class MerkleChallengeBTimeout extends EndTransaction {
    static ACTOR = PAUL
    static taproot(state){
        return [[ MerkleChallengeBTimeoutLeaf, state.vicky, state.paul]]
    }
} 


export class MerkleResponseALeaf extends Leaf { 

    lock(vicky, paul, roundIndex) {
        return [
            paul.commit.merkleResponseA(roundIndex),
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
            paul.unlock.merkleResponseA(roundIndex),
        ]
    }
}

export class MerkleResponseBLeaf extends Leaf { 

    lock(vicky, paul, roundIndex) {
        return [
            paul.commit.merkleResponseB(roundIndex),
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
            paul.unlock.merkleResponseB(roundIndex),
        ]
    }
}

export class MerkleResponseA extends Transaction {
    static ACTOR = PAUL
    static taproot(params) {
        return [
            [MerkleResponseALeaf, params.vicky, params.paul, this.INDEX]
        ]
    }
}

export class MerkleResponseB extends Transaction {
    static ACTOR = PAUL
    static taproot(params) {
        return [
            [MerkleResponseBLeaf, params.vicky, params.paul, this.INDEX]
        ]
    }
}


export class MerkleResponseATimeoutLeaf extends TimeoutLeaf { 

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

export class MerkleResponseBTimeoutLeaf extends TimeoutLeaf { 

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


export class MerkleResponseATimeout extends EndTransaction {
    static ACTOR = VICKY
    static taproot(state){
        return [[ MerkleResponseATimeoutLeaf, state.vicky, state.paul]]
    }
} 

export class MerkleResponseBTimeout extends EndTransaction {
    static ACTOR = VICKY
    static taproot(state){
        return [[ MerkleResponseBTimeoutLeaf, state.vicky, state.paul]]
    }
} 


export class MerkleHashALeftLeaf extends Leaf {

    lock(vicky, paul, merkleIndexA) {
        const roundIndex1 = LOG_PATH_LEN - 1 - trailingZeros(merkleIndexA)
        const roundIndex2 = LOG_PATH_LEN - 1 - trailingZeros(merkleIndexA + 1)
        return [
            // Verify we're executing the correct leaf
            vicky.push.merkleIndexA,
            merkleIndexA,
            OP_EQUALVERIFY,

            vicky.push.nextMerkleIndexA(roundIndex1),
            merkleIndexA,
            OP_EQUALVERIFY,


            vicky.push.nextMerkleIndexA(roundIndex2),
            merkleIndexA + 1,
            OP_EQUALVERIFY,

            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            paul.push.addressABitAt(PATH_LEN - 1 - merkleIndexA),
            OP_NOT,
            OP_VERIFY,

            // Read the child nodes
            paul.push.merkleResponseA(roundIndex2),
            // Hash the child nodes
            blake3_160,
            u160_toaltstack,
            // Read the parent hash
            paul.push.merkleResponseA(roundIndex1),
            
            u160_fromaltstack,
            u160_swap_endian,
            u160_equalverify,
            OP_TRUE, // TODO: verify the covenant here
        ]
    }

    unlock(vicky, paul, merkleIndexA) {
        const roundIndex1 = LOG_PATH_LEN - 1 - trailingZeros(merkleIndexA)
        const roundIndex2 = LOG_PATH_LEN - 1 - trailingZeros(merkleIndexA + 1)
        return [
            paul.unlock.merkleResponseA(roundIndex1),
            paul.unlock.merkleResponseASibling(roundIndex2),
            paul.unlock.merkleResponseA(roundIndex2),
            paul.unlock.addressABitAt(PATH_LEN - 1 - merkleIndexA),
            vicky.unlock.nextMerkleIndexA(roundIndex2),
            vicky.unlock.nextMerkleIndexA(roundIndex1),
            vicky.unlock.merkleIndexA,
        ]
    }
}

export class MerkleHashBLeftLeaf extends Leaf {

    lock(vicky, paul, merkleIndexB) {
        const roundIndex1 = LOG_PATH_LEN - 1 - trailingZeros(merkleIndexB)
        const roundIndex2 = LOG_PATH_LEN - 1 - trailingZeros(merkleIndexB + 1)
        return [
            // Verify we're executing the correct leaf
            vicky.push.merkleIndexB,
            merkleIndexB,
            OP_EQUALVERIFY,

            vicky.push.nextMerkleIndexB(roundIndex1),
            merkleIndexB,
            OP_EQUALVERIFY,


            vicky.push.nextMerkleIndexB(roundIndex2),
            merkleIndexB + 1,
            OP_EQUALVERIFY,

            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            paul.push.addressBBitAt(PATH_LEN - 1 - merkleIndexB),
            OP_NOT,
            OP_VERIFY,

            // Read the child nodes
            paul.push.merkleResponseB(roundIndex2),
            // Hash the child nodes
            blake3_160,
            u160_toaltstack,
            // Read the parent hash
            paul.push.merkleResponseB(roundIndex1),
            
            u160_fromaltstack,
            u160_swap_endian,
            u160_equalverify,
            OP_TRUE, // TODO: verify the covenant here
        ]
    }

    unlock(vicky, paul, merkleIndexB) {
        const roundIndex1 = LOG_PATH_LEN - 1 - trailingZeros(merkleIndexB)
        const roundIndex2 = LOG_PATH_LEN - 1 - trailingZeros(merkleIndexB + 1)
        return [
            paul.unlock.merkleResponseB(roundIndex1),
            paul.unlock.merkleResponseBSibling(roundIndex2),
            paul.unlock.merkleResponseB(roundIndex2),
            paul.unlock.addressBBitAt(PATH_LEN - 1 - merkleIndexB),
            vicky.unlock.nextMerkleIndexB(roundIndex2),
            vicky.unlock.nextMerkleIndexB(roundIndex1),
            vicky.unlock.merkleIndexB,
        ]
    }
}


export class MerkleHashARightLeaf extends Leaf {

    lock(vicky, paul, merkleIndexA) {
        const roundIndex1 = LOG_PATH_LEN - 1 - trailingZeros(merkleIndexA)
        const roundIndex2 = LOG_PATH_LEN - 1 - trailingZeros(merkleIndexA + 1)
        return [
            // Verify we're executing the correct leaf
            vicky.push.merkleIndexA,
            merkleIndexA,
            OP_EQUALVERIFY,

            vicky.push.nextMerkleIndexA(roundIndex1),
            merkleIndexA,
            OP_EQUALVERIFY,

            vicky.push.nextMerkleIndexA(roundIndex2),
            merkleIndexA + 1,
            OP_EQUALVERIFY,

            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            paul.push.addressABitAt(PATH_LEN - 1 - merkleIndexA),
            OP_VERIFY,

            // Read the child nodes
            u160_toaltstack,
            paul.push.merkleResponseA(roundIndex2),
            u160_fromaltstack,
            // Hash the child nodes
            blake3_160,
            u160_toaltstack,
            // Read the parent hash
            paul.push.merkleResponseA(roundIndex1),
            
            u160_fromaltstack,
            u160_swap_endian,
            u160_equalverify,
            OP_TRUE, // TODO: verify the covenant here
        ]
    }

    unlock(vicky, paul, merkleIndexA) {
        const roundIndex1 = LOG_PATH_LEN - 1 - trailingZeros(merkleIndexA)
        const roundIndex2 = LOG_PATH_LEN - 1 - trailingZeros(merkleIndexA + 1)
        return [
            paul.unlock.merkleResponseA(roundIndex1),
            paul.unlock.merkleResponseA(roundIndex2),
            paul.unlock.merkleResponseASibling(roundIndex2),
            paul.unlock.addressABitAt(PATH_LEN - 1 - merkleIndexA),
            vicky.unlock.nextMerkleIndexA(roundIndex2),
            vicky.unlock.nextMerkleIndexA(roundIndex1),
            vicky.unlock.merkleIndexA,
        ]
    }
}

export class MerkleHashBRightLeaf extends Leaf {

    lock(vicky, paul, merkleIndexB) {
        const roundIndex1 = LOG_PATH_LEN - 1 - trailingZeros(merkleIndexB)
        const roundIndex2 = LOG_PATH_LEN - 1 - trailingZeros(merkleIndexB + 1)
        return [
            // Verify we're executing the correct leaf
            vicky.push.merkleIndexB,
            merkleIndexB,
            OP_EQUALVERIFY,

            vicky.push.nextMerkleIndexB(roundIndex1),
            merkleIndexB,
            OP_EQUALVERIFY,

            vicky.push.nextMerkleIndexB(roundIndex2),
            merkleIndexB + 1,
            OP_EQUALVERIFY,

            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            paul.push.addressBBitAt(PATH_LEN - 1 - merkleIndexB),
            OP_VERIFY,

            // Read the child nodes
            u160_toaltstack,
            paul.push.merkleResponseB(roundIndex2),
            u160_fromaltstack,
            // Hash the child nodes
            blake3_160,
            u160_toaltstack,
            // Read the parent hash
            paul.push.merkleResponseB(roundIndex1),
            
            u160_fromaltstack,
            u160_swap_endian,
            u160_equalverify,
            OP_TRUE, // TODO: verify the covenant here
        ]
    }

    unlock(vicky, paul, merkleIndexB) {
        const roundIndex1 = LOG_PATH_LEN - 1 - trailingZeros(merkleIndexB)
        const roundIndex2 = LOG_PATH_LEN - 1 - trailingZeros(merkleIndexB + 1)
        return [
            paul.unlock.merkleResponseB(roundIndex1),
            paul.unlock.merkleResponseB(roundIndex2),
            paul.unlock.merkleResponseBSibling(roundIndex2),
            paul.unlock.addressBBitAt(PATH_LEN - 1 - merkleIndexB),
            vicky.unlock.nextMerkleIndexB(roundIndex2),
            vicky.unlock.nextMerkleIndexB(roundIndex1),
            vicky.unlock.merkleIndexB,
        ]
    }
}


export class MerkleHashARootLeftLeaf extends Leaf {

    lock(vicky, paul, traceRoundIndex) {
        return [
            // Verify we're executing the correct leaf
            vicky.push.merkleIndexA,
            0,
            OP_EQUALVERIFY,

            vicky.push.traceIndex,
            OP_TOALTSTACK,
            vicky.push.nextTraceIndex(traceRoundIndex),
            OP_FROMALTSTACK,
            OP_EQUALVERIFY,

            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            paul.push.addressABitAt(PATH_LEN - 1),
            OP_NOT,
            OP_VERIFY,

            // Read the child nodes
            paul.push.merkleResponseA(LOG_PATH_LEN - 1),
            // Hash the child nodes
            blake3_160,
            u160_toaltstack,
            // Read the parent hash
            paul.push.traceResponse(traceRoundIndex),
            
            u160_fromaltstack,
            u160_swap_endian,
            u160_equalverify,
            
            OP_TRUE, // TODO: verify the covenant here
        ]
    }

    unlock(vicky, paul, traceRoundIndex) {
        return [
            paul.unlock.traceResponse(traceRoundIndex),
            paul.unlock.merkleResponseASibling(LOG_PATH_LEN - 1),
            paul.unlock.merkleResponseA(LOG_PATH_LEN - 1),
            paul.unlock.addressABitAt(PATH_LEN - 1),
            vicky.unlock.nextTraceIndex(traceRoundIndex),
            vicky.unlock.traceIndex,
            vicky.unlock.merkleIndexA,
        ]
    }
}

export class MerkleHashBRootLeftLeaf extends Leaf {

    lock(vicky, paul, traceRoundIndex) {
        return [
            // Verify we're executing the correct leaf
            vicky.push.merkleIndexB,
            0,
            OP_EQUALVERIFY,

            vicky.push.traceIndex,
            OP_TOALTSTACK,
            vicky.push.nextTraceIndex(traceRoundIndex),
            OP_FROMALTSTACK,
            OP_EQUALVERIFY,


            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            paul.push.addressBBitAt(PATH_LEN - 1),
            OP_NOT,
            OP_VERIFY,

            // Read the child nodes
            paul.push.merkleResponseB(LOG_PATH_LEN - 1),
            // Hash the child nodes
            blake3_160,
            u160_toaltstack,
            // Read the parent hash
            paul.push.traceResponse(traceRoundIndex),
            
            u160_fromaltstack,
            u160_swap_endian,
            u160_equalverify,
            
            OP_TRUE, // TODO: verify the covenant here
        ]
    }

    unlock(vicky, paul, traceRoundIndex) {
        return [
            paul.unlock.traceResponse(traceRoundIndex),
            paul.unlock.merkleResponseBSibling(LOG_PATH_LEN - 1),
            paul.unlock.merkleResponseB(LOG_PATH_LEN - 1),
            paul.unlock.addressBBitAt(PATH_LEN - 1),
            vicky.unlock.nextTraceIndex(traceRoundIndex),
            vicky.unlock.traceIndex,
            vicky.unlock.merkleIndexB,
        ]
    }
}




export class MerkleHashARootRightLeaf extends Leaf {

    lock(vicky, paul, traceIndex) {
        return [
            // Verify we're executing the correct leaf
            vicky.push.merkleIndexA,
            0,
            OP_EQUALVERIFY,

            vicky.push.traceIndex,
            traceIndex,
            OP_EQUALVERIFY,


            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            paul.push.addressABitAt(PATH_LEN - 1),
            OP_VERIFY,

            // Read the child nodes
            u160_toaltstack,
            paul.push.merkleResponseA(LOG_PATH_LEN - 1),
            u160_fromaltstack,
            // Hash the child nodes
            blake3_160,
            u160_toaltstack,
            // Read the parent hash
            paul.push.traceResponse(traceIndex),
            
            u160_fromaltstack,
            u160_swap_endian,
            u160_equalverify,
            OP_TRUE, // TODO: verify the covenant here
        ]
    }

    unlock(vicky, paul, traceIndex) {
        return [
            paul.unlock.traceResponse(traceIndex),
            paul.unlock.merkleResponseA(LOG_PATH_LEN - 1),
            paul.unlock.merkleResponseASibling(LOG_PATH_LEN - 1),
            paul.unlock.addressABitAt(PATH_LEN - 1),
            vicky.unlock.traceIndex,
            vicky.unlock.merkleIndexA,
        ]
    }
}


export class MerkleHashBRootRightLeaf extends Leaf {

    lock(vicky, paul, traceIndex) {
        return [
            // Verify we're executing the correct leaf
            vicky.push.merkleIndexB,
            0,
            OP_EQUALVERIFY,

            vicky.push.traceIndex,
            traceIndex,
            OP_EQUALVERIFY,


            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            paul.push.addressBBitAt(PATH_LEN - 1),
            OP_VERIFY,

            // Read the child nodes
            u160_toaltstack,
            paul.push.merkleResponseB(LOG_PATH_LEN - 1),
            u160_fromaltstack,
            // Hash the child nodes
            blake3_160,
            u160_toaltstack,
            // Read the parent hash
            paul.push.traceResponse(traceIndex),
            
            u160_fromaltstack,
            u160_swap_endian,
            u160_equalverify,
            OP_TRUE, // TODO: verify the covenant here
        ]
    }

    unlock(vicky, paul, traceIndex) {
        return [
            paul.unlock.traceResponse(traceIndex),
            paul.unlock.merkleResponseB(LOG_PATH_LEN - 1),
            paul.unlock.merkleResponseBSibling(LOG_PATH_LEN - 1),
            paul.unlock.addressBBitAt(PATH_LEN - 1),
            vicky.unlock.traceIndex,
            vicky.unlock.merkleIndexB,
        ]
    }
}



export class MerkleALeafHashLeftLeaf extends Leaf {

    lock(vicky, paul) {
        return [
            // Verify we're executing the correct leaf
            vicky.push.merkleIndexA,
            PATH_LEN - 1,
            OP_EQUALVERIFY,

            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            paul.push.addressABitAt(0),
            OP_NOT,
            OP_VERIFY,

            // Read valueA
            paul.push.valueA,
            // Pad with 16 zero bytes
            u32_toaltstack,
            loop(16, _ => 0),
            u32_fromaltstack,
            // Hash the child nodes
            blake3_160,
            u160_toaltstack,
            // Read the parent hash
            paul.push.merkleResponseA(LOG_PATH_LEN - 1),
            
            u160_fromaltstack,
            u160_swap_endian,
            u160_equalverify,
            OP_TRUE, // TODO: verify the covenant here
        ]
    }

    unlock(vicky, paul) {
        return [
            paul.unlock.merkleResponseA(LOG_PATH_LEN - 1),
            paul.unlock.merkleResponseASibling(LOG_PATH_LEN),
            paul.unlock.valueA,
            paul.unlock.addressABitAt(0),
            vicky.unlock.merkleIndexA,
        ]
    }
}

export class MerkleBLeafHashLeftLeaf extends Leaf {

    lock(vicky, paul) {
        return [
            // Verify we're executing the correct leaf
            vicky.push.merkleIndexB,
            PATH_LEN - 1,
            OP_EQUALVERIFY,

            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            paul.push.addressBBitAt(0),
            OP_NOT,
            OP_VERIFY,

            // Read valueB
            paul.push.valueB,
            // Pad with 16 zero bytes
            u32_toaltstack,
            loop(16, _ => 0),
            u32_fromaltstack,
            // Hash the child nodes
            blake3_160,
            u160_toaltstack,
            // Read the parent hash
            paul.push.merkleResponseB(LOG_PATH_LEN - 1),
            
            u160_fromaltstack,
            u160_swap_endian,
            u160_equalverify,
            OP_TRUE, // TODO: verify the covenant here
        ]
    }

    unlock(vicky, paul) {
        return [
            paul.unlock.merkleResponseB(LOG_PATH_LEN - 1),
            paul.unlock.merkleResponseBSibling(LOG_PATH_LEN),
            paul.unlock.valueB,
            paul.unlock.addressBBitAt(0),
            vicky.unlock.merkleIndexB,
        ]
    }
}

export class MerkleALeafHashRightLeaf extends Leaf {

    lock(vicky, paul) {
        return [
            // Verify we're executing the correct leaf
            vicky.push.merkleIndexA,
            PATH_LEN - 1,
            OP_EQUALVERIFY,

            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            paul.push.addressABitAt(0),
            OP_VERIFY,


            u160_toaltstack,
            // Read valueA
            paul.push.valueA,
            // Pad with 16 zero bytes
            u32_toaltstack,
            loop(16, _ => 0),
            u32_fromaltstack,
            u160_fromaltstack,
            // Hash the child nodes
            blake3_160,
            u160_toaltstack,
            // Read the parent hash
            paul.push.merkleResponseA(LOG_PATH_LEN - 1),
            
            u160_fromaltstack,
            u160_swap_endian,
            u160_equalverify,
            OP_TRUE, // TODO: verify the covenant here
        ]
    }

    unlock(vicky, paul) {
        return [
            paul.unlock.merkleResponseA(LOG_PATH_LEN - 1),
            paul.unlock.valueA,
            paul.unlock.merkleResponseASibling(LOG_PATH_LEN),
            paul.unlock.addressABitAt(0),
            vicky.unlock.merkleIndexA,
        ]
    }
}

export class MerkleBLeafHashRightLeaf extends Leaf {

    lock(vicky, paul) {
        return [
            // Verify we're executing the correct leaf
            vicky.push.merkleIndexB,
            PATH_LEN - 1,
            OP_EQUALVERIFY,

            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            paul.push.addressBBitAt(0),
            OP_VERIFY,


            u160_toaltstack,
            // Read valueB
            paul.push.valueB,
            // Pad with 16 zero bytes
            u32_toaltstack,
            loop(16, _ => 0),
            u32_fromaltstack,
            u160_fromaltstack,
            // Hash the child nodes
            blake3_160,
            u160_toaltstack,
            // Read the parent hash
            paul.push.merkleResponseB(LOG_PATH_LEN - 1),
            
            u160_fromaltstack,
            u160_swap_endian,
            u160_equalverify,
            OP_TRUE, // TODO: verify the covenant here
        ]
    }

    unlock(vicky, paul) {
        return [
            paul.unlock.merkleResponseB(LOG_PATH_LEN - 1),
            paul.unlock.valueB,
            paul.unlock.merkleResponseBSibling(LOG_PATH_LEN),
            paul.unlock.addressBBitAt(0),
            vicky.unlock.merkleIndexB,
        ]
    }
}



export class MerkleHashA extends Transaction {
    static ACTOR = PAUL
    static taproot(params) {
        const {vicky, paul} = params;
        return [
            ...loop(PATH_LEN - 2, merkleIndexA => [MerkleHashALeftLeaf, vicky, paul, merkleIndexA + 1]),
            ...loop(PATH_LEN - 2, merkleIndexA => [MerkleHashARightLeaf, vicky, paul, merkleIndexA + 1]),
            ...loop(LOG_TRACE_LEN, traceIndex => [MerkleHashARootLeftLeaf, vicky, paul, traceIndex]),
            ...loop(LOG_TRACE_LEN, traceIndex => [MerkleHashARootRightLeaf, vicky, paul, traceIndex]),
            [MerkleALeafHashLeftLeaf, vicky, paul],
            [MerkleALeafHashRightLeaf, vicky, paul],
        ]
    }
}

export class MerkleHashB extends Transaction {
    static ACTOR = PAUL
    static taproot(params) {
        const {vicky, paul} = params;
        return [
            ...loop(PATH_LEN - 2, merkleIndexB => [MerkleHashBLeftLeaf, vicky, paul, merkleIndexB + 1]),
            ...loop(PATH_LEN - 2, merkleIndexB => [MerkleHashBRightLeaf, vicky, paul, merkleIndexB + 1]),
            ...loop(LOG_TRACE_LEN, traceRoundIndex => [MerkleHashBRootLeftLeaf, vicky, paul, traceRoundIndex]),
            ...loop(LOG_TRACE_LEN, traceRoundIndex => [MerkleHashBRootRightLeaf, vicky, paul, traceRoundIndex]),
            [MerkleBLeafHashLeftLeaf, vicky, paul],
            [MerkleBLeafHashRightLeaf, vicky, paul],
        ]
    }
}


export class MerkleHashTimeoutALeaf extends TimeoutLeaf { 

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

export class MerkleHashTimeoutBLeaf extends TimeoutLeaf { 

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

export class MerkleHashTimeoutA extends EndTransaction {
    static ACTOR = VICKY
    static taproot(state){
        return [[ MerkleHashTimeoutALeaf, state.vicky, state.paul]]
    }
}

export class MerkleHashTimeoutB extends EndTransaction {
    static ACTOR = VICKY
    static taproot(state){
        return [[ MerkleHashTimeoutBLeaf, state.vicky, state.paul]]
    }
}


export class MerkleEquivocationA extends EndTransaction {
    static ACTOR = VICKY

    static taproot(params) {
        console.warn(`${this.name} not implemented`)
        return [[ class extends Leaf {
            lock(){
                return ['OP_4']
            }
            unlock(){
                return []
            }
        }]]
    }
}


export class MerkleEquivocationB extends EndTransaction {
    static ACTOR = VICKY

    static taproot(params) {
        console.warn(`${this.name} not implemented`)
        return [[ class extends Leaf {
            lock(){
                return ['OP_4']
            }
            unlock(){
                return []
            }
        }]]
    }
}




export class MerkleEquivocationTimeoutA extends EndTransaction {
    static ACTOR = PAUL

    static taproot(params) {
        return [[ 
            class extends TimeoutLeaf { 
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
            }, 
            params.vicky, 
            params.paul 
        ]]
    }
}

export class MerkleEquivocationTimeoutB extends EndTransaction {
    static ACTOR = PAUL

    static taproot(params) {
        return [[ 
            class extends TimeoutLeaf { 
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
            }, 
            params.vicky, 
            params.paul 
        ]]
    }
}