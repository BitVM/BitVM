import { trailingZeros } from '../../libs/common.js'
import { u32_toaltstack, u32_fromaltstack } from '../../scripts/opcodes/u32_std.js'
import {
    u160_equalverify,
    u160_push,
    u160_swap_endian,
    u160_toaltstack,
    u160_fromaltstack
} from '../../scripts/opcodes/u160_std.js'
import { blake3_160 } from '../../scripts/opcodes/blake3.js'
import { Leaf, Transaction, EndTransaction } from '../../scripts/transaction.js'
import { 
    LOG_TRACE_LEN,
    LOG_PATH_LEN,
    PATH_LEN,
    VICKY,
    PAUL,
} from '../constants.js'



export class MerkleChallengeCStartPrevLeaf extends Leaf {

    lock(vicky, paul, merkleIndex) {
        return [
            vicky.pubkey,
            // OP_CHECKSIGVERIFY,
            // paul.pubkey,
            OP_CHECKSIG
        ]
    }

    unlock(vicky, paul, merkleIndex) {
        return [
            // paul.sign(this), // TODO
            vicky.sign(this),
        ]
    }
}


export class MerkleChallengeCStartPrev extends Transaction {
    static ACTOR = VICKY
    static taproot(params) {
        return [
            [MerkleChallengeCStartPrevLeaf, params.vicky, params.paul]
        ]
    }
}


export class MerkleChallengeCPrevLeaf extends Leaf {

    lock(vicky, paul, roundIndex, faultyIndex) {
        return [
            vicky.commit.merkleChallengeCPrev(roundIndex, faultyIndex),
            vicky.pubkey,
            // OP_CHECKSIGVERIFY,
            // paul.pubkey,
            OP_CHECKSIG
        ]
    }

    unlock(vicky, paul, roundIndex, faultyIndex) {
        return [
            // paul.sign(this), // TODO
            vicky.sign(this),
            vicky.unlock.merkleChallengeCPrev(roundIndex, faultyIndex),
        ]
    }
}

export class MerkleChallengeCPrev extends Transaction {
    static ACTOR = VICKY
    static taproot(params) {
        return [
            [MerkleChallengeCPrevLeaf, params.vicky, params.paul, this.ROUND, this.INDEX]
        ]
    }
}

export class MerkleResponseCPrevLeaf extends Leaf {

    lock(vicky, paul, roundIndex, faultyIndex) {
        return [
            paul.commit.merkleResponseCPrev(roundIndex, faultyIndex),
            // vicky.pubkey,
            // OP_CHECKSIGVERIFY,
            paul.pubkey,
            OP_CHECKSIG,
        ]
    }

    unlock(vicky, paul, roundIndex, faultyIndex) {
        return [
            paul.sign(this),
            // vicky.sign(this),
            paul.unlock.merkleResponseCPrev(roundIndex, faultyIndex),
        ]
    }
}


export class MerkleResponseCPrev extends Transaction {
    static ACTOR = PAUL
    static taproot(params) {
        return [
            [MerkleResponseCPrevLeaf, params.vicky, params.paul, this.ROUND, this.INDEX]
        ]
    }
}



export class MerkleHashCPrevNodeLeftLeaf extends Leaf {

    lock(vicky, paul, merkleIndexC) {
        const roundIndex1 = LOG_PATH_LEN - 1 - trailingZeros(merkleIndexC)
        const roundIndex2 = LOG_PATH_LEN - 1 - trailingZeros(merkleIndexC + 1)
        return [
            // Verify we're executing the correct leaf
            vicky.push.merkleIndexC,
            merkleIndexC,
            OP_EQUALVERIFY,

            vicky.push.nextMerkleIndexCPrev(roundIndex1),
            merkleIndexC,
            OP_EQUALVERIFY,


            vicky.push.nextMerkleIndexCPrev(roundIndex2),
            merkleIndexC + 1,
            OP_EQUALVERIFY,

            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            paul.push.addressCBitAt(PATH_LEN - 1 - merkleIndexC),
            OP_NOT,
            OP_VERIFY,

            // Read the child nodes
            paul.push.merkleResponseCPrev(roundIndex2),
            // Hash the child nodes
            blake3_160,
            u160_toaltstack,
            // Read the parent hash
            paul.push.merkleResponseCPrev(roundIndex1),
            
            u160_fromaltstack,
            u160_swap_endian,
            u160_equalverify,
            OP_TRUE, // TODO: verify the covenant here
        ]
    }

    unlock(vicky, paul, merkleIndexC) {
        const roundIndex1 = LOG_PATH_LEN - 1 - trailingZeros(merkleIndexC)
        const roundIndex2 = LOG_PATH_LEN - 1 - trailingZeros(merkleIndexC + 1)
        return [
            paul.unlock.merkleResponseCPrev(roundIndex1),
            paul.unlock.merkleResponseCPrevSibling(roundIndex2),
            paul.unlock.merkleResponseCPrev(roundIndex2),
            paul.unlock.addressCBitAt(PATH_LEN - 1 - merkleIndexC),
            vicky.unlock.nextMerkleIndexCPrev(roundIndex2),
            vicky.unlock.nextMerkleIndexCPrev(roundIndex1),
            vicky.unlock.merkleIndexC,
        ]
    }
}



export class MerkleHashCPrevNodeRightLeaf extends Leaf {

    lock(vicky, paul, merkleIndexC) {
        const roundIndex1 = LOG_PATH_LEN - 1 - trailingZeros(merkleIndexC)
        const roundIndex2 = LOG_PATH_LEN - 1 - trailingZeros(merkleIndexC + 1)
        return [
            // Verify we're executing the correct leaf
            vicky.push.merkleIndexC,
            merkleIndexC,
            OP_EQUALVERIFY,

            vicky.push.nextMerkleIndexCPrev(roundIndex1),
            merkleIndexC,
            OP_EQUALVERIFY,

            vicky.push.nextMerkleIndexCPrev(roundIndex2),
            merkleIndexC + 1,
            OP_EQUALVERIFY,

            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            paul.push.addressCBitAt(PATH_LEN - 1 - merkleIndexC),
            OP_VERIFY,

            // Read the child nodes
            u160_toaltstack,
            paul.push.merkleResponseCPrev(roundIndex2),
            u160_fromaltstack,
            // Hash the child nodes
            blake3_160,
            u160_toaltstack,
            // Read the parent hash
            paul.push.merkleResponseCPrev(roundIndex1),
            
            u160_fromaltstack,
            u160_swap_endian,
            u160_equalverify,
            OP_TRUE, // TODO: verify the covenant here
        ]
    }

    unlock(vicky, paul, merkleIndexC) {
        const roundIndex1 = LOG_PATH_LEN - 1 - trailingZeros(merkleIndexC)
        const roundIndex2 = LOG_PATH_LEN - 1 - trailingZeros(merkleIndexC + 1)
        return [
            paul.unlock.merkleResponseCPrev(roundIndex1),
            paul.unlock.merkleResponseCPrev(roundIndex2),
            paul.unlock.merkleResponseCPrevSibling(roundIndex2),
            paul.unlock.addressCBitAt(PATH_LEN - 1 - merkleIndexC),
            vicky.unlock.nextMerkleIndexCPrev(roundIndex2),
            vicky.unlock.nextMerkleIndexCPrev(roundIndex1),
            vicky.unlock.merkleIndexC,
        ]
    }
}

export class MerkleHashCPrevRootLeftLeaf extends Leaf {

    lock(vicky, paul, traceRoundIndex) {
        return [
            // Verify we're executing the correct leaf
            vicky.push.merkleIndexC,
            0,
            OP_EQUALVERIFY,

            vicky.push.traceIndex,
            OP_TOALTSTACK,
            vicky.push.nextTraceIndex(traceRoundIndex),
            OP_FROMALTSTACK,
            OP_EQUALVERIFY,

            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            paul.push.addressCBitAt(PATH_LEN - 1),
            OP_NOT,
            OP_VERIFY,

            // Read the child nodes
            paul.push.merkleResponseCPrev(LOG_PATH_LEN - 1),
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
            paul.unlock.merkleResponseCPrevSibling(LOG_PATH_LEN - 1),
            paul.unlock.merkleResponseCPrev(LOG_PATH_LEN - 1),
            paul.unlock.addressCBitAt(PATH_LEN - 1),
            vicky.unlock.nextTraceIndex(traceRoundIndex),
            vicky.unlock.traceIndex,
            vicky.unlock.merkleIndexC,
        ]
    }
}



export class MerkleHashCPrevRootRightLeaf extends Leaf {

    lock(vicky, paul, traceIndex) {
        return [
            // Verify we're executing the correct leaf
            vicky.push.merkleIndexC,
            0,
            OP_EQUALVERIFY,

            vicky.push.traceIndex,
            traceIndex,
            OP_EQUALVERIFY,


            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            paul.push.addressCBitAt(PATH_LEN - 1),
            OP_VERIFY,

            // Read the child nodes
            u160_toaltstack,
            paul.push.merkleResponseCPrev(LOG_PATH_LEN - 1),
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
            paul.unlock.merkleResponseCPrev(LOG_PATH_LEN - 1),
            paul.unlock.merkleResponseCPrevSibling(LOG_PATH_LEN - 1),
            paul.unlock.addressCBitAt(PATH_LEN - 1),
            vicky.unlock.traceIndex,
            vicky.unlock.merkleIndexC,
        ]
    }
}




export class MerkleHashCPrevSiblingLeftLeaf extends Leaf {

    lock(vicky, paul, siblingIndex) {
        return [
            // Verify we're executing the correct leaf
            vicky.push.merkleIndexC,
            PATH_LEN - 1,
            OP_EQUALVERIFY,

            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            paul.push.addressCBitAt(siblingIndex),
            OP_VERIFY,

            // Read valueC
            paul.push.valueC,
            // Pad with 16 zero bytes
            u32_toaltstack,
            loop(16, _ => 0),
            u32_fromaltstack,
            // Hash the child nodes
            blake3_160,
            u160_toaltstack,
            // Read the parent hash
            paul.push.merkleResponseCPrev(LOG_PATH_LEN - 1),
            
            u160_fromaltstack,
            u160_swap_endian,
            u160_equalverify,
            OP_TRUE, // TODO: verify the covenant here
        ]
    }

    unlock(vicky, paul, siblingIndex) {
        return [
            paul.unlock.merkleResponseCPrev(LOG_PATH_LEN - 1),
            paul.unlock.merkleResponseCPrevSibling(LOG_PATH_LEN),
            paul.unlock.valueC,
            paul.unlock.addressCBitAt(siblingIndex),
            vicky.unlock.merkleIndexC,
        ]
    }
}

export class MerkleHashCPrevSiblingRightLeaf extends Leaf {

    lock(vicky, paul, siblingIndex) {
        return [
            // Verify we're executing the correct leaf
            vicky.push.merkleIndexC,
            PATH_LEN - 1,
            OP_EQUALVERIFY,

            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            paul.push.addressCBitAt(siblingIndex),
            OP_NOT,
            OP_VERIFY,


            u160_toaltstack,
            // Read valueC
            paul.push.valueC,
            // Pad with 16 zero bytes
            u32_toaltstack,
            loop(16, _ => 0),
            u32_fromaltstack,
            u160_fromaltstack,
            // Hash the child nodes
            blake3_160,
            u160_toaltstack,
            // Read the parent hash
            paul.push.merkleResponseCPrev(LOG_PATH_LEN - 1),
            
            u160_fromaltstack,
            u160_swap_endian,
            u160_equalverify,
            OP_TRUE, // TODO: verify the covenant here
        ]
    }

    unlock(vicky, paul, siblingIndex) {
        return [
            paul.unlock.merkleResponseCPrev(LOG_PATH_LEN - 1),
            paul.unlock.valueC,
            paul.unlock.merkleResponseCPrevSibling(LOG_PATH_LEN),
            paul.unlock.addressCBitAt(siblingIndex),
            vicky.unlock.merkleIndexC,
        ]
    }
}



export class MerkleHashCPrev extends Transaction {
    static ACTOR = PAUL
    static taproot(params) {
        const {vicky, paul} = params;
        return [
            ...loop(PATH_LEN - 2, merkleIndexC => [MerkleHashCPrevNodeLeftLeaf, vicky, paul, merkleIndexC + 1]),
            ...loop(PATH_LEN - 2, merkleIndexC => [MerkleHashCPrevNodeRightLeaf, vicky, paul, merkleIndexC + 1]),
            ...loop(LOG_TRACE_LEN, traceIndexRound => [MerkleHashCPrevRootLeftLeaf, vicky, paul, traceIndexRound]),
            ...loop(LOG_TRACE_LEN, traceIndexRound => [MerkleHashCPrevRootRightLeaf, vicky, paul, traceIndexRound]),
            [MerkleHashCPrevSiblingLeftLeaf, vicky, paul, this.INDEX],
            [MerkleHashCPrevSiblingRightLeaf, vicky, paul, this.INDEX],
        ]
    }
}


export class MerkleEquivocationCPrev extends EndTransaction {
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
 


