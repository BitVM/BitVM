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


export class MerkleChallengeCLeaf extends Leaf { 

    lock(vicky, paul, roundIndex) {
        return [
            vicky.commit.merkleChallengeC(roundIndex),
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
            vicky.unlock.merkleChallengeC(roundIndex),
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

    unlock(vicky, paul){
        return [ 
            paul.sign(this), 
        ]
    }
}



export class MerkleChallengeCTimeout extends EndTransaction {
    static ACTOR = PAUL
    static taproot(state){
        return [[ MerkleChallengeCTimeoutLeaf, state.vicky, state.paul]]
    }
}



export class MerkleResponseCLeaf extends Leaf { 

    lock(vicky, paul, roundIndex) {
        return [
            paul.commit.merkleResponseC(roundIndex),
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
            paul.unlock.merkleResponseC(roundIndex),
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

    unlock(vicky, paul){
        return [ 
            vicky.sign(this), 
        ]
    }
}



export class MerkleResponseCTimeout extends EndTransaction {
    static ACTOR = VICKY
    static taproot(state){
        return [[ MerkleResponseCTimeoutLeaf, state.vicky, state.paul]]
    }
} 


export class MerkleHashCLeftLeaf extends Leaf {

    lock(vicky, paul, merkleIndexC) {
        const roundIndex1 = LOG_PATH_LEN - 1 - trailingZeros(merkleIndexC)
        const roundIndex2 = LOG_PATH_LEN - 1 - trailingZeros(merkleIndexC + 1)
        return [
            // Verify we're executing the correct leaf
            vicky.push.merkleIndexC,
            merkleIndexC,
            OP_EQUALVERIFY,

            vicky.push.nextMerkleIndexC(roundIndex1),
            merkleIndexC,
            OP_EQUALVERIFY,


            vicky.push.nextMerkleIndexC(roundIndex2),
            merkleIndexC + 1,
            OP_EQUALVERIFY,

            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            paul.push.addressCBitAt(PATH_LEN - 1 - merkleIndexC),
            OP_NOT,
            OP_VERIFY,

            // Read the child nodes
            paul.push.merkleResponseC(roundIndex2),
            // Hash the child nodes
            blake3_160,
            u160_toaltstack,
            // Read the parent hash
            paul.push.merkleResponseC(roundIndex1),
            
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
            paul.unlock.merkleResponseC(roundIndex1),
            paul.unlock.merkleResponseCSibling(roundIndex2),
            paul.unlock.merkleResponseC(roundIndex2),
            paul.unlock.addressCBitAt(PATH_LEN - 1 - merkleIndexC),
            vicky.unlock.nextMerkleIndexC(roundIndex2),
            vicky.unlock.nextMerkleIndexC(roundIndex1),
            vicky.unlock.merkleIndexC,
        ]
    }
}



export class MerkleHashCRightLeaf extends Leaf {

    lock(vicky, paul, merkleIndexC) {
        const roundIndex1 = LOG_PATH_LEN - 1 - trailingZeros(merkleIndexC)
        const roundIndex2 = LOG_PATH_LEN - 1 - trailingZeros(merkleIndexC + 1)
        return [
            // Verify we're executing the correct leaf
            vicky.push.merkleIndexC,
            merkleIndexC,
            OP_EQUALVERIFY,

            vicky.push.nextMerkleIndexC(roundIndex1),
            merkleIndexC,
            OP_EQUALVERIFY,

            vicky.push.nextMerkleIndexC(roundIndex2),
            merkleIndexC + 1,
            OP_EQUALVERIFY,

            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            paul.push.addressCBitAt(PATH_LEN - 1 - merkleIndexC),
            OP_VERIFY,

            // Read the child nodes
            u160_toaltstack,
            paul.push.merkleResponseC(roundIndex2),
            u160_fromaltstack,
            // Hash the child nodes
            blake3_160,
            u160_toaltstack,
            // Read the parent hash
            paul.push.merkleResponseC(roundIndex1),
            
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
            paul.unlock.merkleResponseC(roundIndex1),
            paul.unlock.merkleResponseC(roundIndex2),
            paul.unlock.merkleResponseCSibling(roundIndex2),
            paul.unlock.addressCBitAt(PATH_LEN - 1 - merkleIndexC),
            vicky.unlock.nextMerkleIndexC(roundIndex2),
            vicky.unlock.nextMerkleIndexC(roundIndex1),
            vicky.unlock.merkleIndexC,
        ]
    }
}

export class MerkleHashCRootLeftLeaf extends Leaf {

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
            paul.push.merkleResponseC(LOG_PATH_LEN - 1),
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
            paul.unlock.merkleResponseCSibling(LOG_PATH_LEN - 1),
            paul.unlock.merkleResponseC(LOG_PATH_LEN - 1),
            paul.unlock.addressCBitAt(PATH_LEN - 1),
            vicky.unlock.nextTraceIndex(traceRoundIndex),
            vicky.unlock.traceIndex,
            vicky.unlock.merkleIndexC,
        ]
    }
}



export class MerkleHashCRootRightLeaf extends Leaf {

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
            paul.push.merkleResponseC(LOG_PATH_LEN - 1),
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
            paul.unlock.merkleResponseC(LOG_PATH_LEN - 1),
            paul.unlock.merkleResponseCSibling(LOG_PATH_LEN - 1),
            paul.unlock.addressCBitAt(PATH_LEN - 1),
            vicky.unlock.traceIndex,
            vicky.unlock.merkleIndexC,
        ]
    }
}




export class MerkleCLeafHashLeftLeaf extends Leaf {

    lock(vicky, paul) {
        return [
            // Verify we're executing the correct leaf
            vicky.push.merkleIndexC,
            PATH_LEN - 1,
            OP_EQUALVERIFY,

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
            // Hash the child nodes
            blake3_160,
            u160_toaltstack,
            // Read the parent hash
            paul.push.merkleResponseC(LOG_PATH_LEN - 1),
            
            u160_fromaltstack,
            u160_swap_endian,
            u160_equalverify,
            OP_TRUE, // TODO: verify the covenant here
        ]
    }

    unlock(vicky, paul) {
        return [
            paul.unlock.merkleResponseC(LOG_PATH_LEN - 1),
            paul.unlock.merkleResponseCSibling(LOG_PATH_LEN),
            paul.unlock.valueC,
            paul.unlock.addressCBitAt(0),
            vicky.unlock.merkleIndexC,
        ]
    }
}

export class MerkleCLeafHashRightLeaf extends Leaf {

    lock(vicky, paul) {
        return [
            // Verify we're executing the correct leaf
            vicky.push.merkleIndexC,
            PATH_LEN - 1,
            OP_EQUALVERIFY,

            // Read the bit from address to figure out if we have to swap the two nodes before hashing
            paul.push.addressCBitAt(0),
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
            paul.push.merkleResponseC(LOG_PATH_LEN - 1),
            
            u160_fromaltstack,
            u160_swap_endian,
            u160_equalverify,
            OP_TRUE, // TODO: verify the covenant here
        ]
    }

    unlock(vicky, paul) {
        return [
            paul.unlock.merkleResponseC(LOG_PATH_LEN - 1),
            paul.unlock.valueC,
            paul.unlock.merkleResponseCSibling(LOG_PATH_LEN),
            paul.unlock.addressCBitAt(0),
            vicky.unlock.merkleIndexC,
        ]
    }
}



export class MerkleHashC extends Transaction {
    static ACTOR = PAUL
    static taproot(params) {
        const {vicky, paul} = params;
        return [
            ...loop(PATH_LEN - 2, merkleIndexC => [MerkleHashCLeftLeaf, vicky, paul, merkleIndexC + 1]),
            ...loop(PATH_LEN - 2, merkleIndexC => [MerkleHashCRightLeaf, vicky, paul, merkleIndexC + 1]),
            ...loop(LOG_TRACE_LEN, traceIndex => [MerkleHashCRootLeftLeaf, vicky, paul, traceIndex]),
            ...loop(LOG_TRACE_LEN, traceIndex => [MerkleHashCRootRightLeaf, vicky, paul, traceIndex]),
            [MerkleCLeafHashLeftLeaf, vicky, paul],
            [MerkleCLeafHashRightLeaf, vicky, paul],
        ]
    }
}


export class MerkleHashTimeoutCLeaf extends TimeoutLeaf { 

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


export class MerkleHashTimeoutC extends EndTransaction {
    static ACTOR = VICKY
    static taproot(state){
        return [[ MerkleHashTimeoutCLeaf, state.vicky, state.paul]]
    }
}



export class MerkleEquivocationC extends EndTransaction {
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



export class MerkleEquivocationTimeoutC extends EndTransaction {
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
