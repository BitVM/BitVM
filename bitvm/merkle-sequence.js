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
    PAUL
} from './constants.js'



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


export class MerkleChallenge extends Transaction {
    static ACTOR = VICKY
    static taproot(params) {
        return [
            [ChallengeValueLeaf, params.vicky, params.paul, this.INDEX]
        ]
    }
}


export class MerkleChallengeTimeoutLeaf extends TimeoutLeaf { 

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


export class MerkleChallengeTimeout extends EndTransaction {
    static ACTOR = PAUL
    static taproot(state){
        return [[ MerkleChallengeTimeoutLeaf, state.vicky, state.paul]]
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

export class MerkleResponse extends Transaction {
    static ACTOR = PAUL
    static taproot(params) {
        return [
            [MerkleResponseLeaf, params.vicky, params.paul, this.INDEX]
        ]
    }
}


export class MerkleResponseTimeoutLeaf extends TimeoutLeaf { 

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


export class MerkleResponseTimeout extends EndTransaction {
    static ACTOR = VICKY
    static taproot(state){
        return [[ MerkleResponseTimeoutLeaf, state.vicky, state.paul]]
    }
} 


export class MerkleHashLeftLeaf extends Leaf {

    lock(vicky, paul, merkleIndex) {
        const roundIndex1 = LOG_PATH_LEN - 1 - trailingZeros(merkleIndex)
        const roundIndex2 = LOG_PATH_LEN - 1 - trailingZeros(merkleIndex + 1)
        return [
            // Verify we're executing the correct leaf
            vicky.push.merkleIndex,
            merkleIndex,
            OP_EQUALVERIFY,

            vicky.push.nextMerkleIndex(roundIndex1),
            merkleIndex,
            OP_EQUALVERIFY,


            vicky.push.nextMerkleIndex(roundIndex2),
            merkleIndex + 1,
            OP_EQUALVERIFY,

            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            paul.push.addressABitAt(PATH_LEN - 1 - merkleIndex),
            OP_NOT,
            OP_VERIFY,

            // Read the child nodes
            paul.push.merkleResponse(roundIndex2),
            // Hash the child nodes
            blake3_160,
            u160_toaltstack,
            // Read the parent hash
            paul.push.merkleResponse(roundIndex1),
            
            u160_fromaltstack,
            u160_swap_endian,
            u160_equalverify,
            OP_TRUE, // TODO: verify the covenant here
        ]
    }

    unlock(vicky, paul, merkleIndex) {
        const roundIndex1 = LOG_PATH_LEN - 1 - trailingZeros(merkleIndex)
        const roundIndex2 = LOG_PATH_LEN - 1 - trailingZeros(merkleIndex + 1)
        return [
            paul.unlock.merkleResponse(roundIndex1),
            paul.unlock.merkleResponseSibling(roundIndex2),
            paul.unlock.merkleResponse(roundIndex2),
            paul.unlock.addressABitAt(PATH_LEN - 1 - merkleIndex),
            vicky.unlock.nextMerkleIndex(roundIndex2),
            vicky.unlock.nextMerkleIndex(roundIndex1),
            vicky.unlock.merkleIndex,
        ]
    }
}


export class MerkleHashRightLeaf extends Leaf {

    lock(vicky, paul, merkleIndex) {
        const roundIndex1 = LOG_PATH_LEN - 1 - trailingZeros(merkleIndex)
        const roundIndex2 = LOG_PATH_LEN - 1 - trailingZeros(merkleIndex + 1)
        return [
            // Verify we're executing the correct leaf
            vicky.push.merkleIndex,
            merkleIndex,
            OP_EQUALVERIFY,

            vicky.push.nextMerkleIndex(roundIndex1),
            merkleIndex,
            OP_EQUALVERIFY,

            vicky.push.nextMerkleIndex(roundIndex2),
            merkleIndex + 1,
            OP_EQUALVERIFY,

            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            paul.push.addressABitAt(PATH_LEN - 1 - merkleIndex),
            OP_VERIFY,

            // Read the child nodes
            u160_toaltstack,
            paul.push.merkleResponse(roundIndex2),
            u160_fromaltstack,
            // Hash the child nodes
            blake3_160,
            u160_toaltstack,
            // Read the parent hash
            paul.push.merkleResponse(roundIndex1),
            
            u160_fromaltstack,
            u160_swap_endian,
            u160_equalverify,
            OP_TRUE, // TODO: verify the covenant here
        ]
    }

    unlock(vicky, paul, merkleIndex) {
        const roundIndex1 = LOG_PATH_LEN - 1 - trailingZeros(merkleIndex)
        const roundIndex2 = LOG_PATH_LEN - 1 - trailingZeros(merkleIndex + 1)
        return [
            paul.unlock.merkleResponse(roundIndex1),
            paul.unlock.merkleResponse(roundIndex2),
            paul.unlock.merkleResponseSibling(roundIndex2),
            paul.unlock.addressABitAt(PATH_LEN - 1 - merkleIndex),
            vicky.unlock.nextMerkleIndex(roundIndex2),
            vicky.unlock.nextMerkleIndex(roundIndex1),
            vicky.unlock.merkleIndex,
        ]
    }
}


export class MerkleHashRootLeftLeaf extends Leaf {

    lock(vicky, paul, traceIndex) {
        return [
            // Verify we're executing the correct leaf
            vicky.push.merkleIndex,
            0,
            OP_EQUALVERIFY,

            vicky.push.traceIndex,
            traceIndex,
            OP_EQUALVERIFY,


            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            paul.push.addressABitAt(PATH_LEN - 1),
            OP_NOT,
            OP_VERIFY,

            // Read the child nodes
            paul.push.merkleResponse(LOG_PATH_LEN - 1),
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
            paul.unlock.merkleResponseSibling(LOG_PATH_LEN - 1),
            paul.unlock.merkleResponse(LOG_PATH_LEN - 1),
            paul.unlock.addressABitAt(PATH_LEN - 1),
            vicky.unlock.traceIndex,
            vicky.unlock.merkleIndex,
        ]
    }
}




export class MerkleHashRootRightLeaf extends Leaf {

    lock(vicky, paul, traceIndex) {
        return [
            // Verify we're executing the correct leaf
            vicky.push.merkleIndex,
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
            paul.push.merkleResponse(LOG_PATH_LEN - 1),
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
            paul.unlock.merkleResponse(LOG_PATH_LEN - 1),
            paul.unlock.merkleResponseSibling(LOG_PATH_LEN - 1),
            paul.unlock.addressABitAt(PATH_LEN - 1),
            vicky.unlock.traceIndex,
            vicky.unlock.merkleIndex,
        ]
    }
}



export class MerkleLeafHashLeftLeaf extends Leaf {

    lock(vicky, paul) {
        return [
            // Verify we're executing the correct leaf
            vicky.push.merkleIndex,
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
            paul.push.merkleResponse(LOG_PATH_LEN - 1),
            
            u160_fromaltstack,
            u160_swap_endian,
            u160_equalverify,
            OP_TRUE, // TODO: verify the covenant here
        ]
    }

    unlock(vicky, paul) {
        return [
            paul.unlock.merkleResponse(LOG_PATH_LEN - 1),
            paul.unlock.merkleResponseSibling(LOG_PATH_LEN),
            paul.unlock.valueA,
            paul.unlock.addressABitAt(0),
            vicky.unlock.merkleIndex,
        ]
    }
}

export class MerkleLeafHashRightLeaf extends Leaf {

    lock(vicky, paul) {
        return [
            // Verify we're executing the correct leaf
            vicky.push.merkleIndex,
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
            paul.push.merkleResponse(LOG_PATH_LEN - 1),
            
            u160_fromaltstack,
            u160_swap_endian,
            u160_equalverify,
            OP_TRUE, // TODO: verify the covenant here
        ]
    }

    unlock(vicky, paul) {
        return [
            paul.unlock.merkleResponse(LOG_PATH_LEN - 1),
            paul.unlock.valueA,
            paul.unlock.merkleResponseSibling(LOG_PATH_LEN),
            paul.unlock.addressABitAt(0),
            vicky.unlock.merkleIndex,
        ]
    }
}




export class MerkleHash extends Transaction {
    static ACTOR = PAUL
    static taproot(params) {
        const {vicky, paul} = params;
        return [
            ...loop(32, merkleIndex => [MerkleHashLeftLeaf, vicky, paul, merkleIndex]),
            ...loop(32, merkleIndex => [MerkleHashLeftRight, vicky, paul, merkleIndex]),
            ...loop(32, traceIndex => [MerkleHashRootLeftLeaf, vicky, paul, traceIndex]),
            ...loop(32, traceIndex => [MerkleHashRootRightLeaf, vicky, paul, traceIndex]),
            [MerkleLeafHashLeftLeaf, vicky, paul],
            [MerkleLeafHashRightLeaf, vicky, paul],
        ]
    }
}
