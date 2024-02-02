import { LOG_TRACE_LEN, LOG_PATH_LEN, PATH_LEN } from './constants.js'
import { Player, Opponent } from '../scripts/player.js'
import { 
	bit_state,
	bit_state_commit,
	bit_state_unlock,
    bit_state_json,
    u32_state_bit,
    u32_state_bit_unlock,
    u2_state_unlock,
	u8_state_commit,
	u8_state,
    u8_state_json,
	u8_state_unlock,
	u32_state_unlock, 
	u32_state_commit,
	u32_state,
    u32_state_json,
 } from '../scripts/opcodes/u32_state.js'

import { 
	u160_state,
	u160_state_commit,
	u160_state_unlock,
    u160_push,
    u160_state_json,
    u160_toaltstack,
    u160_fromaltstack,
} from '../scripts/opcodes/u160_std.js'


const validateTraceIndex = index => {
    if (index < 0)
        throw Error(`index: ${index} < 0`)
    if (index >= LOG_TRACE_LEN)
        throw Error(`index: ${index} >= ${LOG_TRACE_LEN}`)
    return index
}

// Vicky's trace challenges
const TRACE_CHALLENGE = index => `TRACE_CHALLENGE_${validateTraceIndex(index)}`
// Paul's trace responses
const TRACE_RESPONSE = index => `TRACE_RESPONSE_${validateTraceIndex(index)}`
// Paul's trace response program counters
const TRACE_RESPONSE_PC = index => `TRACE_RESPONSE_PC_${validateTraceIndex(index)}`

// Vicky's Merkle Challenges for the operand A
const MERKLE_CHALLENGE_A = index => `MERKLE_CHALLENGE_A_${index}`
// Paul's Merkle Responses for the operand A
const MERKLE_RESPONSE_A = index => `MERKLE_RESPONSE_A_${index}`


// Vicky's Merkle Challenges for the operand B
const MERKLE_CHALLENGE_B = index => `MERKLE_CHALLENGE_B_${index}`
// Paul's Merkle Responses for the operand B
const MERKLE_RESPONSE_B = index => `MERKLE_RESPONSE_B_${index}`


// Vicky's Merkle Challenges for the result C
const MERKLE_CHALLENGE_C_PREV = index => `MERKLE_CHALLENGE_C_PREV_${index}`
// Paul's Merkle Responses for the result C
const MERKLE_RESPONSE_C_NEXT = index => `MERKLE_RESPONSE_C_NEXT_${index}`
// Paul's Merkle Responses for the result C
const MERKLE_RESPONSE_C_NEXT_SIBLING = index => `MERKLE_RESPONSE_C_NEXT_SIBLING_${index}`
// Paul's Merkle Responses for the result C
const MERKLE_RESPONSE_C_PREV = index => `MERKLE_RESPONSE_C_PREV_${index}`




// Paul's Instruction
const INSTRUCTION_TYPE = 'INSTRUCTION_TYPE'
const INSTRUCTION_VALUE_A = 'INSTRUCTION_VALUE_A'
const INSTRUCTION_ADDRESS_A = 'INSTRUCTION_ADDRESS_A'
const INSTRUCTION_VALUE_B = 'INSTRUCTION_VALUE_B'
const INSTRUCTION_ADDRESS_B = 'INSTRUCTION_ADDRESS_B'
const INSTRUCTION_VALUE_C = 'INSTRUCTION_VALUE_C'
const INSTRUCTION_ADDRESS_C = 'INSTRUCTION_ADDRESS_C'
const INSTRUCTION_PC_CURR = 'INSTRUCTION_PC_CURR'
const INSTRUCTION_PC_NEXT = 'INSTRUCTION_PC_NEXT'


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
        // Get the program counter of the previous instruction
        const traceIndex = this.opponent.traceIndex - 1
        const snapshot = this.vm.run(traceIndex)
        return snapshot.pc
    }

    get pcNext() {
        const traceIndex = this.opponent.traceIndex
        const snapshot = this.vm.run(traceIndex)
        return snapshot.pc
    }

    get instructionType() {
        const traceIndex = this.opponent.traceIndex
        const snapshot = this.vm.run(traceIndex)
        return snapshot.instruction.type
    }

    traceResponse(roundIndex) {
        const traceIndex = this.opponent.nextTraceIndex(roundIndex)
        const snapshot = this.vm.run(traceIndex)
        return snapshot.root
    }

    traceResponsePc(roundIndex) {
        const traceIndex = this.opponent.nextTraceIndex(roundIndex)
        const snapshot = this.vm.run(traceIndex)
        return snapshot.pc
    }

    merkleResponseA(roundIndex) {
        const traceIndex = this.opponent.traceIndex
        const snapshot = this.vm.run(traceIndex)
        const path = snapshot.path(snapshot.instruction.addressA)
        const merkleIndexA = this.opponent.nextMerkleIndexA(roundIndex)
        return path.verifyUpTo(merkleIndexA)
    }

    merkleResponseASibling(roundIndex){
        const traceIndex = this.opponent.traceIndex
        const snapshot = this.vm.run(traceIndex)
        const path = snapshot.path(snapshot.instruction.addressA)
        let merkleIndexA
        if (roundIndex < LOG_PATH_LEN)
            merkleIndexA = this.opponent.nextMerkleIndexA(roundIndex) - 1
        else
            merkleIndexA = this.opponent.merkleIndexA
        return path.getNode(merkleIndexA)
    }


    merkleResponseB(roundIndex) {
        const traceIndex = this.opponent.traceIndex
        const snapshot = this.vm.run(traceIndex)
        const path = snapshot.path(snapshot.instruction.addressB)
        const merkleIndexB = this.opponent.nextMerkleIndexB(roundIndex)
        return path.verifyUpTo(merkleIndexB)
    }

    merkleResponseBSibling(roundIndex){
        const traceIndex = this.opponent.traceIndex
        const snapshot = this.vm.run(traceIndex)
        const path = snapshot.path(snapshot.instruction.addressB)
        let merkleIndexB
        if (roundIndex < LOG_PATH_LEN)
            merkleIndexB = this.opponent.nextMerkleIndexB(roundIndex) - 1
        else
            merkleIndexB = this.opponent.merkleIndexB
        return path.getNode(merkleIndexB)
    }

    merkleResponseCPrev(roundIndex) {
        const traceIndex = this.opponent.traceIndex
        const merkleIndexC = this.opponent.nextMerkleIndexCPrev(roundIndex)
        const prevSnapshot = this.vm.run(traceIndex)
        const prevPath = prevSnapshot.path(prevSnapshot.instruction.addressC)
        return prevPath.verifyUpTo(merkleIndexC)
    }

    merkleResponseCPrevSibling(roundIndex){
        let merkleIndexC
        if (roundIndex < LOG_PATH_LEN)
            merkleIndexC = this.opponent.nextMerkleIndexCPrev(roundIndex) - 1
        else
            merkleIndexC = this.opponent.merkleIndexC

        const traceIndex = this.opponent.traceIndex
        const snapshot = this.vm.run(traceIndex)
        const path = snapshot.path(snapshot.instruction.addressC)
        return path.getNode(merkleIndexC)
    }

    merkleResponseCNext(merkleIndexC) {
        const traceIndex = this.opponent.traceIndex + 1
        const snapshot = this.vm.run(traceIndex)
        const path = snapshot.path(snapshot.instruction.addressC)
        return path.verifyUpTo(merkleIndexC)
    }

    merkleResponseCNextSibling(merkleIndexC){
        const traceIndex = this.opponent.traceIndex + 1
        const snapshot = this.vm.run(traceIndex)
        const path = snapshot.path(snapshot.instruction.addressC)
        return path.getNode(merkleIndexC)
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

    traceResponsePc(roundIndex) {
        return this.model.get_u32(TRACE_RESPONSE_PC(roundIndex))
    }

    merkleResponseA(roundIndex) {
        return this.model.get_u160(MERKLE_RESPONSE_A(roundIndex))
    }

    merkleResponseB(roundIndex) {
        return this.model.get_u160(MERKLE_RESPONSE_B(roundIndex))
    }

    merkleResponseCPrev(roundIndex) {
        return this.model.get_u160(MERKLE_RESPONSE_C_PREV(roundIndex))
    }

    merkleResponseCNext(roundIndex) {
        return this.model.get_u160(MERKLE_RESPONSE_C_NEXT(roundIndex))
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

    traceResponsePc(roundIndex) {
        return u32_state_commit(this.actor, TRACE_RESPONSE_PC(roundIndex))
    }

    merkleResponseA(roundIndex) {
        return u160_state_commit(this.actor, MERKLE_RESPONSE_A(roundIndex))
    }

    merkleResponseB(roundIndex) {
        return u160_state_commit(this.actor, MERKLE_RESPONSE_B(roundIndex))
    }

    merkleResponseCPrev(roundIndex) {
        return u160_state_commit(this.actor, MERKLE_RESPONSE_C_PREV(roundIndex))
    }

    merkleResponseCNext(roundIndex) {
        return u160_state_commit(this.actor, MERKLE_RESPONSE_C_NEXT(roundIndex))
    }

    merkleResponseCNextSibling(roundIndex) {
        return u160_state_commit(this.actor, MERKLE_RESPONSE_C_NEXT_SIBLING(roundIndex))
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

    traceResponsePc(roundIndex) {
        return u32_state(this.actor, TRACE_RESPONSE_PC(roundIndex))
    }

    merkleResponseA(roundIndex) {
        return u160_state(this.actor, MERKLE_RESPONSE_A(roundIndex))
    }

    merkleResponseB(roundIndex) {
        return u160_state(this.actor, MERKLE_RESPONSE_B(roundIndex))
    }

    merkleResponseCPrev(roundIndex) {
        return u160_state(this.actor, MERKLE_RESPONSE_C_PREV(roundIndex))
    }

    merkleResponseCNext(roundIndex) {
        return u160_state(this.actor, MERKLE_RESPONSE_C_NEXT(roundIndex))
    }

    merkleResponseCNextSibling(roundIndex) {
        return u160_state(this.actor, MERKLE_RESPONSE_C_NEXT_SIBLING(roundIndex))
    }

    addressABitAt(bitIndex){
        return u32_state_bit(this.actor, INSTRUCTION_ADDRESS_A, bitIndex)
    }

    addressBBitAt(bitIndex){
        return u32_state_bit(this.actor, INSTRUCTION_ADDRESS_B, bitIndex)
    }

    addressCBitAt(bitIndex){
        return u32_state_bit(this.actor, INSTRUCTION_ADDRESS_C, bitIndex)
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

    traceResponsePc(roundIndex) {
        return u32_state_unlock(this.actor, TRACE_RESPONSE_PC(roundIndex), this.actor.traceResponsePc(roundIndex)) 
    }

    merkleResponseA(roundIndex) {
        return u160_state_unlock(this.actor, MERKLE_RESPONSE_A(roundIndex), this.actor.merkleResponseA(roundIndex))
    }

    merkleResponseB(roundIndex) {
        return u160_state_unlock(this.actor, MERKLE_RESPONSE_B(roundIndex), this.actor.merkleResponseB(roundIndex))
    }

    merkleResponseCPrev(roundIndex) {
        const prevNode = this.actor.merkleResponseCPrev(roundIndex)
        return u160_state_unlock(this.actor, MERKLE_RESPONSE_C_PREV(roundIndex), prevNode)
    }

    merkleResponseCNext(roundIndex) {
        const nextNode = this.actor.merkleResponseCNext(roundIndex)
        return u160_state_unlock(this.actor, MERKLE_RESPONSE_C_NEXT(roundIndex), nextNode)
    }

    merkleResponseASibling(roundIndex){
        return u160_push(this.actor.merkleResponseASibling(roundIndex))
    }

    merkleResponseBSibling(roundIndex){
        return u160_push(this.actor.merkleResponseBSibling(roundIndex))
    }

    merkleResponseCPrevSibling(roundIndex){
        const prevNode = this.actor.merkleResponseCPrevSibling(roundIndex)
        return u160_push(prevNode)
    }

    merkleResponseCNextSibling(roundIndex){
        const nextNode = this.actor.merkleResponseCNextSibling(roundIndex)
        return u160_push(nextNode)
    }

    addressABitAt(bitIndex){
        return u32_state_bit_unlock(this.actor, INSTRUCTION_ADDRESS_A, this.actor.addressA, bitIndex)
    }

    addressBBitAt(bitIndex){
        return u32_state_bit_unlock(this.actor, INSTRUCTION_ADDRESS_B, this.actor.addressB, bitIndex)
    }

    addressCBitAt(bitIndex){
        return u32_state_bit_unlock(this.actor, INSTRUCTION_ADDRESS_C, this.actor.addressC, bitIndex)
    }
}





class PaulExportWrapper extends Wrapper {

    get valueA() {
        return u32_state_json(this.actor, INSTRUCTION_VALUE_A)
    }

    get valueB() {
        return u32_state_json(this.actor, INSTRUCTION_VALUE_B)
    }

    get valueC() {
        return u32_state_json(this.actor, INSTRUCTION_VALUE_C)
    }

    get addressA() {
        return u32_state_json(this.actor, INSTRUCTION_ADDRESS_A)
    }

    get addressB() {
        return u32_state_json(this.actor, INSTRUCTION_ADDRESS_B)
    }

    get addressC() {
        return u32_state_json(this.actor, INSTRUCTION_ADDRESS_C)
    }

    get pcCurr() {
        return u32_state_json(this.actor, INSTRUCTION_PC_CURR)
    }

    get pcNext() {
        return u32_state_json(this.actor, INSTRUCTION_PC_NEXT)
    }

    get instructionType() {
        return u8_state_json(this.actor, INSTRUCTION_TYPE)
    }

    traceResponse(roundIndex) {
        return u160_state_json(this.actor, TRACE_RESPONSE(roundIndex))
    }

    traceResponsePc(roundIndex) {
        return u32_state_json(this.actor, TRACE_RESPONSE_PC(roundIndex))
    }

    merkleResponseA(roundIndex) {
        return u160_state_json(this.actor, MERKLE_RESPONSE_A(roundIndex))
    }

    merkleResponseB(roundIndex) {
        return u160_state_json(this.actor, MERKLE_RESPONSE_B(roundIndex))
    }

    merkleResponseCPrev(roundIndex) {
        return u160_state_json(this.actor, MERKLE_RESPONSE_C_PREV(roundIndex))
    }

    merkleResponseCNext(roundIndex) {
        return u160_state_json(this.actor, MERKLE_RESPONSE_C_NEXT(roundIndex))
    }

    merkleResponseCNextSibling(roundIndex) {
        return u160_state_json(this.actor, MERKLE_RESPONSE_C_NEXT_SIBLING(roundIndex))
    }

    toJson(){
        const result = {}
        Object.assign(result, this.valueA)
        Object.assign(result, this.valueB)
        Object.assign(result, this.valueC)
        Object.assign(result, this.addressA)
        Object.assign(result, this.addressB)
        Object.assign(result, this.addressC)
        Object.assign(result, this.pcCurr)
        Object.assign(result, this.pcNext)
        Object.assign(result, this.instructionType)
        for(let i=0; i < LOG_TRACE_LEN; i++){
            Object.assign(result, this.traceResponse(i))
            Object.assign(result, this.traceResponsePc(i))
        }
        for(let i=0; i < LOG_PATH_LEN; i++){
            Object.assign(result, this.merkleResponseA(i))
            Object.assign(result, this.merkleResponseB(i))
            Object.assign(result, this.merkleResponseCPrev(i))
        }
        for(let i=0; i < PATH_LEN; i++){
            Object.assign(result, this.merkleResponseCNext(i))
            Object.assign(result, this.merkleResponseCNextSibling(i))
        }
        return result
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
        const traceIndex = this.nextTraceIndex(roundIndex)
        const snapshot = this.vm.run(traceIndex)
        const ourRoot = snapshot.root
        const ourPc = snapshot.pc
        const theirRoot = this.opponent.traceResponse(roundIndex)
        const theirPc = this.opponent.traceResponsePc(roundIndex)
        const isCorrect = Number(ourRoot === theirRoot && ourPc === theirPc)
        return isCorrect
    }


    // Index of the last valid node in the Merkle path
    get merkleIndexA() {
        let merkleIndexA = 0
        for (let i = 0; i < LOG_PATH_LEN; i++) {
            const bit = this.merkleChallengeA(i)
            merkleIndexA += bit * 2 ** (LOG_PATH_LEN - 1 - i)
        }
        return merkleIndexA
    }

    // Index of the last valid node in the Merkle path
    get merkleIndexB() {
        let merkleIndexB = 0
        for (let i = 0; i < LOG_PATH_LEN; i++) {
            const bit = this.merkleChallengeB(i)
            merkleIndexB += bit * 2 ** (LOG_PATH_LEN - 1 - i)
        }
        return merkleIndexB
    }

    // Index of the last valid node in the Merkle path
    get merkleIndexCPrev() {
        let merkleIndexC = 0
        for (let i = 0; i < LOG_PATH_LEN; i++) {
            const bit = this.merkleChallengeCPrev(i)
            merkleIndexC += bit * 2 ** (LOG_PATH_LEN - 1 - i)
        }
        return merkleIndexC
    }

    // Index of the current node in the Merkle path
    nextMerkleIndexA(roundIndex) {
        let merkleIndexA = 0
        for (let i = 0; i < roundIndex; i++) {
            const bit = this.merkleChallengeA(i)
            merkleIndexA += bit * 2 ** (LOG_PATH_LEN - 1 - i)
        }
        merkleIndexA += 2 ** (LOG_PATH_LEN - 1 - roundIndex)
        return merkleIndexA
    }

    // Index of the current node in the Merkle path
    nextMerkleIndexB(roundIndex) {
        let merkleIndexB = 0
        for (let i = 0; i < roundIndex; i++) {
            const bit = this.merkleChallengeB(i)
            merkleIndexB += bit * 2 ** (LOG_PATH_LEN - 1 - i)
        }
        merkleIndexB += 2 ** (LOG_PATH_LEN - 1 - roundIndex)
        return merkleIndexB
    }

    // Index of the current node in the Merkle path
    nextMerkleIndexCPrev(roundIndex) {
        let merkleIndexC = 0
        for (let i = 0; i < roundIndex; i++) {
            const bit = this.merkleChallengeCPrev(i)
            merkleIndexC += bit * 2 ** (LOG_PATH_LEN - 1 - i)
        }
        merkleIndexC += 2 ** (LOG_PATH_LEN - 1 - roundIndex)
        return merkleIndexC
    }

    // Get the next Merkle challenge
    merkleChallengeA(roundIndex) {
        const nodeIndex = this.nextMerkleIndexA(roundIndex)
        const snapshot = this.vm.run(this.traceIndex)
        const ourNode = snapshot.path(this.opponent.addressA)[nodeIndex]
        const theirNode = this.opponent.merkleResponseA(roundIndex)
        const isCorrect = Number(ourNode === theirNode)
        return isCorrect
    }

    // Get the next Merkle challenge
    merkleChallengeB(roundIndex) {
        const nodeIndex = this.nextMerkleIndexB(roundIndex)
        const snapshot = this.vm.run(this.traceIndex)
        const ourNode = snapshot.path(this.opponent.addressB)[nodeIndex]
        const theirNode = this.opponent.merkleResponseB(roundIndex)
        const isCorrect = Number(ourNode === theirNode)
        return isCorrect
    }

    // Get the next Merkle challenge
    merkleChallengeCPrev(roundIndex) {
        const nodeIndex = this.nextMerkleIndexCPrev(roundIndex)
        const snapshot = this.vm.run(this.traceIndex)
        const ourPrevNode = snapshot.path(this.opponent.addressC)[nodeIndex]

        const prevNode = this.opponent.merkleResponseCPrev(roundIndex)
        const isCorrect = Number(ourPrevNode === prevNode)
        return isCorrect
    }


    get isFaultyReadA(){
        const snapshot = this.vm.run(this.traceIndex)
        const valueA = snapshot.read(this.opponent.addressA)
        return valueA !== this.opponent.valueA
    }

    get isFaultyReadB(){
        const snapshot = this.vm.run(this.traceIndex)
        const valueB = snapshot.read(this.opponent.addressB)
        return valueB !== this.opponent.valueB
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
    get merkleIndexA() {
        let merkleIndexA = 0
        for (let i = 0; i < LOG_PATH_LEN; i++) {
            const bit = this.merkleChallengeA(i)
            merkleIndexA += bit * 2 ** (LOG_PATH_LEN - 1 - i)
        }
        return merkleIndexA
    }

    // Index of the last valid node in the Merkle path
    get merkleIndexB() {
        let merkleIndexB = 0
        for (let i = 0; i < LOG_PATH_LEN; i++) {
            const bit = this.merkleChallengeB(i)
            merkleIndexB += bit * 2 ** (LOG_PATH_LEN - 1 - i)
        }
        return merkleIndexB
    }

    // Index of the last valid node in the Merkle path
    get merkleIndexCPrev() {
        let merkleIndexC = 0
        for (let i = 0; i < LOG_PATH_LEN; i++) {
            const bit = this.merkleChallengeCPrev(i)
            merkleIndexC += bit * 2 ** (LOG_PATH_LEN - 1 - i)
        }
        return merkleIndexC
    }

    // Index of the current node in the Merkle path
    nextMerkleIndexA(roundIndex) {
        let merkleIndexA = 0
        for (let i = 0; i < roundIndex; i++) {
            const bit = this.merkleChallengeA(i)
            merkleIndexA += bit * 2 ** (LOG_PATH_LEN - 1 - i)
        }
        merkleIndexA += 2 ** (LOG_PATH_LEN - 1 - roundIndex)
        return merkleIndexA
    }

    // Index of the current node in the Merkle path
    nextMerkleIndexB(roundIndex) {
        let merkleIndexB = 0
        for (let i = 0; i < roundIndex; i++) {
            const bit = this.merkleChallengeB(i)
            merkleIndexB += bit * 2 ** (LOG_PATH_LEN - 1 - i)
        }
        merkleIndexB += 2 ** (LOG_PATH_LEN - 1 - roundIndex)
        return merkleIndexB
    }

    // Index of the current node in the Merkle path
    nextMerkleIndexCPrev(roundIndex) {
        let merkleIndexC = 0
        for (let i = 0; i < roundIndex; i++) {
            const bit = this.merkleChallengeCPrev(i)
            merkleIndexC += bit * 2 ** (LOG_PATH_LEN - 1 - i)
        }
        merkleIndexC += 2 ** (LOG_PATH_LEN - 1 - roundIndex)
        return merkleIndexC
    }

    // Get the next Merkle challenge
    merkleChallengeA(roundIndex) {
        return this.model.get_u1(MERKLE_CHALLENGE_A(roundIndex))
    }

    // Get the next Merkle challenge
    merkleChallengeB(roundIndex) {
        return this.model.get_u1(MERKLE_CHALLENGE_B(roundIndex))
    }

    // Get the next Merkle challenge
    merkleChallengeCPrev(roundIndex) {
        return this.model.get_u1(MERKLE_CHALLENGE_C_PREV(roundIndex))
    }
}



class VickyCommitWrapper extends Wrapper {

    traceChallenge(roundIndex) {
        return bit_state_commit(this.actor, TRACE_CHALLENGE(roundIndex))
    }

    merkleChallengeA(roundIndex) {
        return bit_state_commit(this.actor, MERKLE_CHALLENGE_A(roundIndex))
    }

    merkleChallengeB(roundIndex) {
        return bit_state_commit(this.actor, MERKLE_CHALLENGE_B(roundIndex))
    }

    merkleChallengeCPrev(roundIndex) {
        return bit_state_commit(this.actor, MERKLE_CHALLENGE_C_PREV(roundIndex))
    }
}


class VickyExportWrapper extends Wrapper {

    traceChallenge(roundIndex) {
        return bit_state_json(this.actor, TRACE_CHALLENGE(roundIndex))
    }

    merkleChallengeA(roundIndex) {
        return bit_state_json(this.actor, MERKLE_CHALLENGE_A(roundIndex))
    }

    merkleChallengeB(roundIndex) {
        return bit_state_json(this.actor, MERKLE_CHALLENGE_B(roundIndex))
    }

    merkleChallengeCPrev(roundIndex) {
        return bit_state_json(this.actor, MERKLE_CHALLENGE_C_PREV(roundIndex))
    }

    toJson(){
        const result = {}
        for(let i=0; i < LOG_TRACE_LEN; i++){
            Object.assign(result, this.traceChallenge(i))
        }
        for(let i=0; i < LOG_PATH_LEN; i++){
            Object.assign(result, this.merkleChallengeA(i))
            Object.assign(result, this.merkleChallengeB(i))
            Object.assign(result, this.merkleChallengeCPrev(i))
        }
        return result
    }
}




class VickyPushWrapper extends Wrapper {

    traceChallenge(roundIndex) {
        return bit_state(this.actor, TRACE_CHALLENGE(roundIndex))
    }

    merkleChallengeA(roundIndex) {
        return bit_state(this.actor, MERKLE_CHALLENGE_A(roundIndex))
    }

    merkleChallengeB(roundIndex) {
        return bit_state(this.actor, MERKLE_CHALLENGE_B(roundIndex))
    }

    merkleChallengeCPrev(roundIndex) {
        return bit_state(this.actor, MERKLE_CHALLENGE_C_PREV(roundIndex))
    }

    get traceIndex() {
        return [
            0,
            loop(LOG_TRACE_LEN, i => [
                OP_SWAP,
                this.traceChallenge(i),
                OP_IF,
                    2 ** (LOG_TRACE_LEN - 1 - i),
                    OP_ADD,
                OP_ENDIF
            ])
        ]
    }

    nextTraceIndex(roundIndex) {
        return [
            0,
            loop(roundIndex, i => [
                OP_SWAP,
                this.traceChallenge(i),
                OP_IF,
                    2 ** (LOG_TRACE_LEN - 1 - i),
                    OP_ADD,
                OP_ENDIF
            ]),
            2 ** (LOG_TRACE_LEN - 1 - roundIndex),
            OP_ADD
        ]
    }

    get merkleIndexA() {
        return [
            0,
            loop(LOG_PATH_LEN, i => [
                OP_SWAP,
                this.merkleChallengeA(i),
                OP_IF,
                	2 ** (LOG_PATH_LEN - 1 - i),
                	OP_ADD,
                OP_ENDIF
            ])
        ]
    }    

    get merkleIndexB() {
        return [
            0,
            loop(LOG_PATH_LEN, i => [
                OP_SWAP,
                this.merkleChallengeB(i),
                OP_IF,
                    2 ** (LOG_PATH_LEN - 1 - i),
                    OP_ADD,
                OP_ENDIF
            ])
        ]
    }

    get merkleIndexCPrev() {
        return [
            0,
            loop(LOG_PATH_LEN, i => [
                OP_SWAP,
                this.merkleChallengeCPrev(i),
                OP_IF,
                    2 ** (LOG_PATH_LEN - 1 - i),
                    OP_ADD,
                OP_ENDIF
            ])
        ]
    }

    nextMerkleIndexA(roundIndex) {
        return [
            0,
            loop(roundIndex, i => [
                OP_SWAP,
                this.merkleChallengeA(i),
                OP_IF,
	                2 ** (LOG_PATH_LEN - 1 - i),
	                OP_ADD,
                OP_ENDIF
            ]),
            2 ** (LOG_PATH_LEN - 1 - roundIndex),
            OP_ADD
        ]
    }    

    nextMerkleIndexB(roundIndex) {
        return [
            0,
            loop(roundIndex, i => [
                OP_SWAP,
                this.merkleChallengeB(i),
                OP_IF,
                    2 ** (LOG_PATH_LEN - 1 - i),
                    OP_ADD,
                OP_ENDIF
            ]),
            2 ** (LOG_PATH_LEN - 1 - roundIndex),
            OP_ADD
        ]
    }

    nextMerkleIndexCPrev(roundIndex) {
        return [
            0,
            loop(roundIndex, i => [
                OP_SWAP,
                this.merkleChallengeCPrev(i),
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

    get traceIndex() {
        return loop(LOG_TRACE_LEN, i => this.traceChallenge(LOG_TRACE_LEN - 1 - i))
    }

    nextTraceIndex(roundIndex) {
        return loop(roundIndex, i => this.traceChallenge(i)).reverse()
    }

    merkleChallengeA(roundIndex) {
        return bit_state_unlock(this.actor, MERKLE_CHALLENGE_A(roundIndex), this.actor.merkleChallengeA(roundIndex))
    }

    merkleChallengeB(roundIndex) {
        return bit_state_unlock(this.actor, MERKLE_CHALLENGE_B(roundIndex), this.actor.merkleChallengeB(roundIndex))
    }

    merkleChallengeCPrev(roundIndex) {
        return bit_state_unlock(this.actor, MERKLE_CHALLENGE_C_PREV(roundIndex), this.actor.merkleChallengeCPrev(roundIndex))
    }

    get merkleIndexA() {
        return loop(LOG_PATH_LEN, i => this.merkleChallengeA(LOG_PATH_LEN - 1 - i))
    }

    get merkleIndexB() {
        return loop(LOG_PATH_LEN, i => this.merkleChallengeB(LOG_PATH_LEN - 1 - i))
    }

    get merkleIndexCPrev() {
        return loop(LOG_PATH_LEN, i => this.merkleChallengeCPrev(LOG_PATH_LEN - 1 - i))
    }

    nextMerkleIndexA(roundIndex) {
        return loop(roundIndex, i => this.merkleChallengeA(i)).reverse()
    }

    nextMerkleIndexB(roundIndex) {
        return loop(roundIndex, i => this.merkleChallengeB(i)).reverse()
    }

    nextMerkleIndexCPrev(roundIndex) {
        return loop(roundIndex, i => this.merkleChallengeCPrev(i)).reverse()
    }
}


const PAUL_WRAPPERS = [PaulUnlockWrapper, PaulCommitWrapper, PaulPushWrapper, PaulExportWrapper]
const VICKY_WRAPPERS = [VickyUnlockWrapper, VickyCommitWrapper, VickyPushWrapper, VickyExportWrapper]