import { trailingZeros } from '../../libs/common.js'
import { bit_state, bit_state_commit, bit_state_unlock } from '../../scripts/opcodes/u32_state.js'
import { u32_toaltstack, u32_fromaltstack } from '../../scripts/opcodes/u32_std.js'
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
} from '../../scripts/opcodes/u160_std.js'
import { blake3_160 } from '../../scripts/opcodes/blake3.js'
import { Leaf, TimeoutLeaf, Transaction, EndTransaction } from '../../scripts/transaction.js'
import {
    LOG_TRACE_LEN,
    LOG_PATH_LEN,
    PATH_LEN,
    VICKY,
    PAUL,
    TIMEOUT
} from '../constants.js'


export class MerkleChallengeCLeaf extends Leaf {

    lock(vicky, paul, merkleIndex) {
        return [
            merkleIndex, OP_DROP, // This is just a marker to make the TXIDs unique
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

export class MerkleChallengeC extends Transaction {
    static ACTOR = VICKY
    static taproot(params) {
        return [
            [MerkleChallengeCLeaf, params.vicky, params.paul, this.INDEX]
        ]
    }
}


export class MerkleChallengeCTimeoutLeaf extends TimeoutLeaf {

    lock(vicky, paul) {
        return [
            TIMEOUT,
            OP_CHECKSEQUENCEVERIFY,
            OP_DROP,
            paul.pubkey,
            OP_CHECKSIG,
        ]
    }

    unlock(vicky, paul) {
        return [
            paul.sign(this),
        ]
    }
}



export class MerkleChallengeCTimeout extends EndTransaction {
    static ACTOR = PAUL
    static taproot(state) {
        return [
            [MerkleChallengeCTimeoutLeaf, state.vicky, state.paul]
        ]
    }
}



export class MerkleResponseCLeaf extends Leaf {

    lock(vicky, paul, merkleIndex) {
        return [
            paul.commit.merkleResponseCNextSibling(merkleIndex),
            paul.commit.merkleResponseCNext(merkleIndex),
            // vicky.pubkey,
            // OP_CHECKSIGVERIFY,
            paul.pubkey,
            OP_CHECKSIG,
        ]
    }

    unlock(vicky, paul, merkleIndex) {
        return [
            paul.sign(this),
            // vicky.sign(this),
            paul.unlock.merkleResponseCNext(merkleIndex),
            paul.unlock.merkleResponseCNextSibling(merkleIndex),
        ]
    }
}

export class MerkleResponseC extends Transaction {
    static ACTOR = PAUL
    static taproot(params) {
        return [
            [MerkleResponseCLeaf, params.vicky, params.paul, this.INDEX]
        ]
    }
}




export class MerkleResponseCTimeoutLeaf extends TimeoutLeaf {

    lock(vicky, paul) {
        return [
            TIMEOUT,
            OP_CHECKSEQUENCEVERIFY,
            OP_DROP,
            vicky.pubkey,
            OP_CHECKSIG,
        ]
    }

    unlock(vicky, paul) {
        return [
            vicky.sign(this),
        ]
    }
}


export class MerkleResponseCTimeout extends EndTransaction {
    static ACTOR = VICKY
    static taproot(state) {
        return [
            [MerkleResponseCTimeoutLeaf, state.vicky, state.paul]
        ]
    }
}





export class MerkleHashCLeftLeaf extends Leaf {

    lock(vicky, paul, merkleIndexC) {
        return [
            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            paul.push.addressCBitAt(PATH_LEN - 1 - merkleIndexC),
            OP_NOT,
            OP_VERIFY,

            // Read the child node
            paul.push.merkleResponseCNext(merkleIndexC),
            // Read the child's sibling
            u160_toaltstack,
            paul.push.merkleResponseCNextSibling(merkleIndexC),
            u160_fromaltstack,

            // Hash the child nodes
            blake3_160,
            u160_toaltstack,
            // Read the parent hash
            paul.push.merkleResponseCNext(merkleIndexC + 1),

            u160_fromaltstack,
            u160_swap_endian,
            u160_equalverify,
            OP_TRUE, // TODO: verify the covenant here
        ]
    }

    unlock(vicky, paul, merkleIndexC) {
        return [
            paul.unlock.merkleResponseCNext(merkleIndex),
            paul.unlock.merkleResponseCNextSibling(merkleIndex),
            paul.unlock.merkleResponseCNext(merkleIndex + 1),
            paul.unlock.addressCBitAt(PATH_LEN - 1 - merkleIndexC),
        ]
    }
}



export class MerkleHashCRightLeaf extends Leaf {

    lock(vicky, paul, merkleIndexC) {
        return [
            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            paul.push.addressCBitAt(PATH_LEN - 1 - merkleIndexC),
            OP_VERIFY,

            // Read the child's sibling
            paul.push.merkleResponseCNextSibling(merkleIndexC),
            // Read the child node
            u160_toaltstack,
            paul.push.merkleResponseCNext(merkleIndexC),
            u160_fromaltstack,

            // Hash the child nodes
            blake3_160,
            u160_toaltstack,
            // Read the parent hash
            paul.push.merkleResponseCNext(merkleIndexC + 1),

            u160_fromaltstack,
            u160_swap_endian,
            u160_equalverify,
            OP_TRUE, // TODO: verify the covenant here
        ]
    }

    unlock(vicky, paul, merkleIndexC) {
        return [
            paul.unlock.merkleResponseCNextSibling(merkleIndex),
            paul.unlock.merkleResponseCNext(merkleIndex),
            paul.unlock.merkleResponseCNext(merkleIndex + 1),
            paul.unlock.addressCBitAt(PATH_LEN - 1 - merkleIndexC),
        ]
    }
}



export class MerkleHashCRootLeftLeaf extends Leaf {

    lock(vicky, paul, traceRoundIndex) {
        return [
            // Verify we're executing the correct leaf

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
            paul.push.merkleResponseCNext(PATH_LEN - 1),
            // Read the child's sibling
            u160_toaltstack,
            paul.push.merkleResponseCNextSibling(PATH_LEN - 1),
            u160_fromaltstack,

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
            paul.unlock.merkleResponseCNextSibling(PATH_LEN - 1),
            paul.unlock.merkleResponseCNext(PATH_LEN - 1),
            paul.unlock.addressCBitAt(PATH_LEN - 1),
            vicky.unlock.nextTraceIndex(traceRoundIndex),
            vicky.unlock.traceIndex,
        ]
    }
}



export class MerkleHashCRootRightLeaf extends Leaf {

    lock(vicky, paul, traceRoundIndex) {
        return [
            // Verify we're executing the correct leaf

            vicky.push.traceIndex,
            OP_TOALTSTACK,
            vicky.push.nextTraceIndex(traceRoundIndex),
            OP_FROMALTSTACK,
            OP_EQUALVERIFY,

            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            paul.push.addressCBitAt(PATH_LEN - 1),
            OP_VERIFY,

            // Read the child's sibling
            paul.push.merkleResponseCNextSibling(PATH_LEN - 1),
            // Read the child nodes
            paul.push.merkleResponseCNext(PATH_LEN - 1),
            u160_toaltstack,
            u160_fromaltstack,

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
            paul.unlock.merkleResponseCNext(PATH_LEN - 1),
            paul.unlock.merkleResponseCNextSibling(PATH_LEN - 1),
            paul.unlock.addressCBitAt(PATH_LEN - 1),
            vicky.unlock.nextTraceIndex(traceRoundIndex),
            vicky.unlock.traceIndex, // TODO: Vicky can equivocate here
        ]
    }
}




export class MerkleCLeafHashLeftLeaf extends Leaf {

    lock(vicky, paul) {
        return [

            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            paul.push.addressCBitAt(0),
            OP_NOT,
            OP_VERIFY,

            // Read valueC
            paul.push.valueC,
            // Pad with 16 zero bytes
            u32_toaltstack,
            loop(16, _ => 0),
            u32_fromaltstack,
            
            // Read sibling
            u160_toaltstack,
            paul.push.merkleResponseCNextSibling(0),
            u160_fromaltstack,

            // Hash the child nodes
            blake3_160,
            u160_toaltstack,
            // Read the parent hash
            paul.push.merkleResponseCNext(LOG_PATH_LEN - 1),

            u160_fromaltstack,
            u160_swap_endian,
            u160_equalverify,
            OP_TRUE, // TODO: verify the covenant here
        ]
    }

    unlock(vicky, paul) {
        return [
            paul.unlock.merkleResponseCNext(1),
            paul.unlock.merkleResponseCNextSibling(0),
            paul.unlock.valueC,
            paul.unlock.addressCBitAt(0),
        ]
    }
}

export class MerkleCLeafHashRightLeaf extends Leaf {

    lock(vicky, paul) {
        return [
            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            paul.push.addressCBitAt(0),
            OP_VERIFY,

            // Read sibling
            paul.push.merkleResponseCNextSibling(0),
            
            // Read valueC
            u160_toaltstack,
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
            paul.push.merkleResponseCNext(LOG_PATH_LEN - 1),

            u160_fromaltstack,
            u160_swap_endian,
            u160_equalverify,
            OP_TRUE, // TODO: verify the covenant here
        ]
    }

    unlock(vicky, paul) {
        return [
            paul.unlock.merkleResponseCNext(1),
            paul.unlock.valueC,
            paul.unlock.merkleResponseCNextSibling(0),
            paul.unlock.addressCBitAt(0),
        ]
    }
}



export class MerkleHashC extends Transaction {
    static ACTOR = PAUL
    static taproot(params) {
        const { vicky, paul } = params;
        switch (this.INDEX) {
            case 0:
                return [
                    [MerkleCLeafHashLeftLeaf, vicky, paul],
                    [MerkleCLeafHashRightLeaf, vicky, paul],
                ];
            case (PATH_LEN - 1):
                return [
                    ...loop(LOG_TRACE_LEN, traceRoundIndex => [MerkleHashCRootLeftLeaf, vicky, paul, traceRoundIndex]),
                    ...loop(LOG_TRACE_LEN, traceRoundIndex => [MerkleHashCRootRightLeaf, vicky, paul, traceRoundIndex]),
                ];
            default:
                return [
                    [MerkleHashCLeftLeaf, vicky, paul, this.INDEX],
                    [MerkleHashCRightLeaf, vicky, paul, this.INDEX],
                ];
        }
    }
}



export class MerkleEquivocationC extends EndTransaction {
    static ACTOR = VICKY

    static taproot(params) {
        console.warn(`${this.name} not implemented`)
        return [
            [class extends Leaf {
                lock() {
                    return ['OP_4']
                }
                unlock() {
                    return []
                }
            }]
        ]
    }
}







