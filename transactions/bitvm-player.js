import { bit_state_justice_unlock } from '../scripts/opcodes/u32_state.js'
import { Player, Opponent } from '../scripts/player.js'
import { 
	bit_state,
	bit_state_commit,
	bit_state_unlock,
	u8_state_commit,
	u8_state,
	u8_state_unlock,
	u32_state_unlock, 
	u32_state_commit,
	u32_state,
 } from '../scripts/opcodes/u32_state.js'

import { 
	u160_state,
	u160_state_commit,
	u160_state_unlock
} from '../scripts/opcodes/u160_std.js'


// Trace

// Logarithm of the length of the trace
export const LOG_TRACE_LEN = 2 // TODO: this should be 32
// Length of the trace
export const TRACE_LEN = 2 ** LOG_TRACE_LEN

// Trace Challenges
export const TRACE_CHALLENGE = index => `TRACE_CHALLENGE_${index}`
// Trace Responses
export const TRACE_RESPONSE = index => `TRACE_RESPONSE_${index}`

// Instruction
const INSTRUCTION_TYPE = 'INSTRUCTION_TYPE'
const INSTRUCTION_VALUE_A = 'INSTRUCTION_VALUE_A'
const INSTRUCTION_ADDRESS_A = 'INSTRUCTION_ADDRESS_A'
const INSTRUCTION_VALUE_B = 'INSTRUCTION_VALUE_B'
const INSTRUCTION_ADDRESS_B = 'INSTRUCTION_ADDRESS_B'
const INSTRUCTION_VALUE_C = 'INSTRUCTION_VALUE_C'
const INSTRUCTION_ADDRESS_C = 'INSTRUCTION_ADDRESS_C'
const INSTRUCTION_PC_CURR = 'INSTRUCTION_PC_CURR'
const INSTRUCTION_PC_NEXT = 'INSTRUCTION_PC_NEXT'

// Challenges
export const CHALLENGE_VALUE_A = 'CHALLENGE_VALUE_A'
export const CHALLENGE_VALUE_B = 'CHALLENGE_VALUE_B'
export const CHALLENGE_VALUE_C = 'CHALLENGE_VALUE_C'
export const CHALLENGE_PC_CURR = 'CHALLENGE_PC_CURR'

export const MERKLE_CHALLENGE_SELECT = 'MERKLE_CHALLENGE_SELECT'


// Merkle Path

// Logarithm of the length of a Merkle path
export const LOG_PATH_LEN = 5
// Length of a Merkle path
export const PATH_LEN = 2 ** LOG_PATH_LEN

// Merkle Challenges
export const MERKLE_CHALLENGE = index => `MERKLE_CHALLENGE_${index}`
// Merkle Responses
export const MERKLE_RESPONSE = index => `MERKLE_RESPONSE_${index}`



class Wrapper {
    actor

    constructor(actor) {
        this.actor = actor
    }
}


export class PaulPlayer extends Player {

    constructor(secret, opponent, vm) {
        super(secret, opponent, vm, ...PAUL_WRAPPERS)
    }

    get valueA() {
        const traceIndex = this.opponent.traceIndex
        const snapshot = this.vm.run(traceIndex)
        return snapshot.read(this.addressA)
    }

    get valueB() {
        const traceIndex = this.opponent.traceIndex
        const snapshot = this.vm.run(traceIndex)
        return snapshot.read(this.addressB)
    }

    get valueC() {
        const traceIndex = this.opponent.traceIndex
        const snapshot = this.vm.run(traceIndex)
        return snapshot.read(this.addressC)
    }

    get addressA() {
    	const traceIndex = this.opponent.traceIndex
        const snapshot = this.vm.run(traceIndex)
        return snapshot.instruction.addressA
    }

    get addressB() {
        const traceIndex = this.opponent.traceIndex
        const snapshot = this.vm.run(traceIndex)
        return snapshot.instruction.addressB
    }

    get addressC() {
        const traceIndex = this.opponent.traceIndex
        const snapshot = this.vm.run(traceIndex)
        return snapshot.instruction.addressC
    }

    get pcCurr() {
        const traceIndex = this.opponent.traceIndex
        const snapshot = this.vm.run(traceIndex)
        return snapshot.pc
    }

    get pcNext() {
        const traceIndex = this.opponent.traceIndex + 1
        // if (traceIndex > TRACE_LEN)
        // 	throw `${traceIndex} > TRACE_LEN`
        const snapshot = this.vm.run(traceIndex)
        return snapshot.pc
    }

    get instructionType() {
        const traceIndex = this.opponent.traceIndex
        const snapshot = this.vm.run(traceIndex)
        return snapshot.instruction.type
    }

    merkleResponse(roundIndex) {
        const traceIndex = this.opponent.traceIndex
        const snapshot = this.vm.run(traceIndex)
        // TODO: figure out if we are challenging valueA or valueB
        const path = snapshot.path(snapshot.instruction.addressA)
        const merkleIndex = this.opponent.nextMerkleIndex(roundIndex)
        // TODO: we have to return a hash here, not a node of the path
        return path[merkleIndex]  
    }

    traceResponse(roundIndex) {
        const traceIndex = this.opponent.nextTraceIndex(roundIndex)
        const snapshot = this.vm.run(traceIndex)
        return snapshot.root
    }

}


export class PaulOpponent extends Opponent {
    
    constructor(hashes) {
        super(hashes, ...PAUL_WRAPPERS)
    }

    get valueA() {
        return this.model.get_u32(INSTRUCTION_VALUE_A)
    }

    get valueB() {
        return this.model.get_u32(INSTRUCTION_VALUE_B)
    }

    get valueC() {
        return this.model.get_u32(INSTRUCTION_VALUE_C)
    }

    get addressA() {
    	return this.model.get_u32(INSTRUCTION_ADDRESS_A)
    }

    get addressB() {
    	return this.model.get_u32(INSTRUCTION_ADDRESS_B)
    }

    get addressC() {
        return this.model.get_u32(INSTRUCTION_ADDRESS_C)
    }

    get pcCurr() {
        return this.model.get_u32(INSTRUCTION_PC_CURR)
    }

    get pcNext() {
        return this.model.get_u32(INSTRUCTION_PC_NEXT)
    }

    get instructionType() {
        return this.model.get_u32(INSTRUCTION_TYPE)
    }

    traceResponse(roundIndex) {
        return this.model.get_u160(TRACE_RESPONSE(roundIndex))
    }

    merkleResponse(roundIndex) {
        return this.model.get_u160(MERKLE_RESPONSE(roundIndex))
    }
}




class PaulCommitWrapper extends Wrapper {

    get valueA() {
        return u32_state_commit(this.actor, INSTRUCTION_VALUE_A)
    }

    get valueB() {
        return u32_state_commit(this.actor, INSTRUCTION_VALUE_B)
    }

    get valueC() {
        return u32_state_commit(this.actor, INSTRUCTION_VALUE_C)
    }

    get addressA() {
        return u32_state_commit(this.actor, INSTRUCTION_ADDRESS_A)
    }

    get addressB() {
        return u32_state_commit(this.actor, INSTRUCTION_ADDRESS_B)
    }

    get addressC() {
        return u32_state_commit(this.actor, INSTRUCTION_ADDRESS_C)
    }

    get pcCurr() {
        return u32_state_commit(this.actor, INSTRUCTION_PC_CURR)
    }

    get pcNext() {
        return u32_state_commit(this.actor, INSTRUCTION_PC_NEXT)
    }

    get instructionType() {
        return u8_state_commit(this.actor, INSTRUCTION_TYPE)
    }

    traceResponse(roundIndex) {
        return u160_state_commit(this.actor, TRACE_RESPONSE(roundIndex))
    }

    merkleResponse(roundIndex) {
        return u160_state_commit(this.actor, MERKLE_RESPONSE(roundIndex))
    }
}

class PaulPushWrapper extends Wrapper {

    get valueA() {
        return u32_state(this.actor, INSTRUCTION_VALUE_A)
    }

    get valueB() {
        return u32_state(this.actor, INSTRUCTION_VALUE_B)
    }

    get valueC() {
        return u32_state(this.actor, INSTRUCTION_VALUE_C)
    }

    get addressA() {
        return u32_state(this.actor, INSTRUCTION_ADDRESS_A)
    }

    get addressB() {
        return u32_state(this.actor, INSTRUCTION_ADDRESS_B)
    }

    get addressC() {
        return u32_state(this.actor, INSTRUCTION_ADDRESS_C)
    }

    get pcCurr() {
        return u32_state(this.actor, INSTRUCTION_PC_CURR)
    }

    get pcNext() {
        return u32_state(this.actor, INSTRUCTION_PC_NEXT)
    }

    get instructionType() {
        return u8_state(this.actor, INSTRUCTION_TYPE)
    }

    traceResponse(roundIndex) {
        return u160_state(this.actor, TRACE_RESPONSE(roundIndex))
    }

    merkleResponse(roundIndex) {
        return u160_state(this.actor, MERKLE_RESPONSE(roundIndex))
    }
}


class PaulUnlockWrapper extends Wrapper {

    get valueA() {
        return u32_state_unlock(this.actor, INSTRUCTION_VALUE_A, this.actor.valueA)
    }

    get valueB() {
        return u32_state_unlock(this.actor, INSTRUCTION_VALUE_B, this.actor.valueB)
    }

    get valueC() {
        return u32_state_unlock(this.actor, INSTRUCTION_VALUE_C, this.actor.valueC)
    }

    get addressA() {
        return u32_state_unlock(this.actor, INSTRUCTION_ADDRESS_A, this.actor.addressA)
    }

    get addressB() {
        return u32_state_unlock(this.actor, INSTRUCTION_ADDRESS_B, this.actor.addressB)
    }

    get addressC() {
        return u32_state_unlock(this.actor, INSTRUCTION_ADDRESS_C, this.actor.addressC)
    }

    get pcCurr() {
        return u32_state_unlock(this.actor, INSTRUCTION_PC_CURR, this.actor.pcCurr)
    }

    get pcNext() {
        return u32_state_unlock(this.actor, INSTRUCTION_PC_NEXT, this.actor.pcNext)
    }

    get instructionType() {
        return u8_state_unlock(this.actor, INSTRUCTION_TYPE, this.actor.instructionType)
    }

    traceResponse(roundIndex) {
        return u160_state_unlock(this.actor, TRACE_RESPONSE(roundIndex), this.actor.traceResponse(roundIndex)) 
    }

    merkleResponse(roundIndex) {
        return u160_state_unlock(this.actor, MERKLE_RESPONSE(roundIndex), this.actor.merkleResponse(roundIndex))
    }

    merkleResponseSibling(roundIndex){
		throw 'Not implemented!'
    }
}




export class VickyPlayer extends Player {

    constructor(secret, opponent, vm) {
        super(secret, opponent, vm, ...VICKY_WRAPPERS)
    }

    // Index of the last valid VM state
    get traceIndex() {
        let traceIndex = 0
        for (let i = 0; i < LOG_TRACE_LEN; i++) {
            const bit = this.traceChallenge(i)
            traceIndex += bit * 2 ** (LOG_TRACE_LEN - 1 - i)
        }
        return traceIndex
    }

    // Index of the first invalid VM state
    get traceSiblingIndex() {
        return this.traceIndex + 1
    }

    // Index of the current state
    nextTraceIndex(roundIndex) {
        let traceIndex = 0
        for (let i = 0; i < roundIndex; i++) {
            const bit = this.traceChallenge(i)
            traceIndex += bit * 2 ** (LOG_TRACE_LEN - 1 - i)
        }
        traceIndex += 2 ** (LOG_TRACE_LEN - 1 - roundIndex)
        return traceIndex
    }

    // Get the next trace challenge
    traceChallenge(roundIndex) {
        let traceIndex = this.nextTraceIndex(roundIndex)
        const snapshot = this.vm.run(traceIndex)
        const ourRoot = snapshot.root
        const theirRoot = this.opponent.traceResponse(roundIndex)
        const isCorrect = Number(ourRoot === theirRoot)
        return isCorrect
    }


    // Index of the last valid node in the Merkle path
    get merkleIndex() {
        let merkleIndex = 0
        for (let i = 0; i < LOG_PATH_LEN; i++) {
            const bit = this.merkleChallenge(i)
            merkleIndex += bit * 2 ** (LOG_PATH_LEN - 1 - i)
        }
        return merkleIndex
    }

    // Index of the first invalid node in the Merkle path
    get merkleSiblingIndex() {
        return this.merkleIndex + 1
    }

    // Index of the current node in the Merkle path
    nextMerkleIndex(roundIndex) {
        let merkleIndex = 0
        for (let i = 0; i < roundIndex; i++) {
            const bit = this.merkleChallenge(i)
            merkleIndex += bit * 2 ** (LOG_PATH_LEN - 1 - i)
        }
        merkleIndex += 2 ** (LOG_PATH_LEN - 1 - roundIndex)
        return merkleIndex
    }

    // Get the next Merkle challenge
    merkleChallenge(roundIndex) {
        let nodeIndex = this.nextMerkleIndex(roundIndex)

        const snapshot = this.vm.run(nodeIndex)
        // TODO: figure out if we're challenging valueA or valueB
        const ourNode = snapshot.path(this.opponent.addressA)[nodeIndex]
        const theirNode = this.opponent.merkleResponse(roundIndex)
        const isCorrect = Number(ourNode === theirNode)

        return isCorrect
    }
}


export class VickyOpponent extends Opponent {
    
    constructor(hashes) {
        super(hashes, ...VICKY_WRAPPERS)
    }

    // Get the next trace challenge
    traceChallenge(roundIndex) {
        return this.model.get_u1(TRACE_CHALLENGE(roundIndex))
    }

    // Index of the last valid VM state
    get traceIndex() {
        let traceIndex = 0
        for (let i = 0; i < LOG_TRACE_LEN; i++) {
            const bit = this.traceChallenge(i)
            traceIndex += bit * 2 ** (LOG_TRACE_LEN - 1 - i)
        }
        return traceIndex
    }

    // Index of the first invalid VM state
    get traceSiblingIndex() {
        return this.traceIndex + 1
    }

    // Index of the current state
    nextTraceIndex(roundIndex) {
        let traceIndex = 0
        for (let i = 0; i < roundIndex; i++) {
            const bit = this.traceChallenge(i)
            traceIndex += bit * 2 ** (LOG_TRACE_LEN - 1 - i)
        }
        traceIndex += 2 ** (LOG_TRACE_LEN - 1 - roundIndex)
        return traceIndex
    }


    // Index of the last valid node in the Merkle path
    get merkleIndex() {
        let merkleIndex = 0
        for (let i = 0; i < LOG_PATH_LEN; i++) {
            const bit = this.merkleChallenge(i)
            merkleIndex += bit * 2 ** (LOG_PATH_LEN - 1 - i)
        }
        return merkleIndex
    }

    // Index of the first invalid node in the Merkle path
    get merkleSiblingIndex() {
        return this.merkleIndex + 1
    }

    // Index of the current node in the Merkle path
    nextMerkleIndex(roundIndex) {
        let merkleIndex = 0
        for (let i = 0; i < roundIndex; i++) {
            const bit = this.merkleChallenge(i)
            merkleIndex += bit * 2 ** (LOG_PATH_LEN - 1 - i)
        }
        merkleIndex += 2 ** (LOG_PATH_LEN - 1 - roundIndex)
        return merkleIndex
    }

    // Get the next Merkle challenge
    merkleChallenge(roundIndex) {
        return this.model.get_u1(MERKLE_CHALLENGE(roundIndex))
    }
}






class VickyCommitWrapper extends Wrapper {

    traceChallenge(roundIndex) {
        return bit_state_commit(this.actor, TRACE_CHALLENGE(roundIndex))
    }

    merkleChallenge(roundIndex) {
        return bit_state_commit(this.actor, MERKLE_CHALLENGE(roundIndex))
    }
}




class VickyPushWrapper extends Wrapper {

    traceChallenge(roundIndex) {
        return bit_state(this.actor, TRACE_CHALLENGE(roundIndex))
    }

    merkleChallenge(roundIndex) {
        return bit_state(this.actor, MERKLE_CHALLENGE(roundIndex))
    }

    get merkleIndex() {
        return [
            0,
            loop(LOG_PATH_LEN, i => [
                OP_SWAP,
                this.merkleChallenge(LOG_PATH_LEN - 1 - i),
                OP_IF,
                	2 ** (LOG_PATH_LEN - 1 - i),
                	OP_ADD,
                OP_ENDIF
            ])
        ]
    }

    nextMerkleIndex(roundIndex) {
        return [
            0,
            loop(roundIndex, i => [
                OP_SWAP,
                this.merkleChallenge(LOG_PATH_LEN - 1 - i),
                OP_IF,
	                2 ** (LOG_PATH_LEN - 1 - i),
	                OP_ADD,
                OP_ENDIF
            ]),
            2 ** (LOG_PATH_LEN - 1 - roundIndex),
            OP_ADD
        ]
    }
}

class VickyUnlockWrapper extends Wrapper {

    traceChallenge(roundIndex) {
        return bit_state_unlock(this.actor, TRACE_CHALLENGE(roundIndex), this.actor.traceChallenge(roundIndex))
    }

    merkleChallenge(roundIndex) {
        return bit_state_unlock(this.actor, MERKLE_CHALLENGE(roundIndex), this.actor.merkleChallenge(roundIndex))
    }

    nextMerkleIndex(roundIndex) {
        return loop(roundIndex, i => this.merkleChallenge(LOG_PATH_LEN - 1 - i))
    }

}

const PAUL_WRAPPERS = [PaulUnlockWrapper, PaulCommitWrapper, PaulPushWrapper]
const VICKY_WRAPPERS = [VickyUnlockWrapper, VickyCommitWrapper, VickyPushWrapper]