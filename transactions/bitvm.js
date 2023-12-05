import { merkleSequence } from './merkle-sequence.js'
import { u32_add_drop } from '../scripts/opcodes/u32_add.js'
import { u32_sub_drop } from '../scripts/opcodes/u32_sub.js'
import { Leaf } from './transaction.js'

import {
    binarySearchSequence,
    TRACE_CHALLENGE,
    TRACE_RESPONSE
} from './binary-search-sequence.js'

import {
    u32_state_commit,
    u32_state,
    u32_state_unlock,
    u8_state_unlock,
    u8_state,
    u8_state_commit
} from '../scripts/opcodes/u32_state.js'

import {
    u32_toaltstack,
    u32_fromaltstack,
    u32_equalverify,
    u32_equal,
    u32_push,
    u32_drop,
    u32_notequal
} from '../scripts/opcodes/u32_std.js'


// Logarithm of the length of the trace
export const LOG_TRACE_LEN = 4

// Variables
const INSTRUCTION_VALUE_A = 'INSTRUCTION_VALUE_A'
const INSTRUCTION_ADDRESS_A = 'INSTRUCTION_ADDRESS_A'
const INSTRUCTION_VALUE_B = 'INSTRUCTION_VALUE_B'
const INSTRUCTION_ADDRESS_B = 'INSTRUCTION_ADDRESS_B'
const INSTRUCTION_VALUE_C = 'INSTRUCTION_VALUE_C'
const INSTRUCTION_ADDRESS_C = 'INSTRUCTION_ADDRESS_C'
const INSTRUCTION_PC_CURR = 'INSTRUCTION_PC_CURR'
const INSTRUCTION_PC_NEXT = 'INSTRUCTION_PC_NEXT'
const INSTRUCTION_TYPE = 'INSTRUCTION_TYPE'

// Challenges
const CHALLENGE_EXECUTION = 'CHALLENGE_EXECUTION'
const CHALLENGE_INSTRUCTION = 'CHALLENGE_INSTRUCTION'
const CHALLENGE_VALUE_A = 'CHALLENGE_VALUE_A'
const CHALLENGE_VALUE_B = 'CHALLENGE_VALUE_B'
const CHALLENGE_VALUE_C = 'CHALLENGE_VALUE_C'
const CHALLENGE_PC_CURR = 'CHALLENGE_PC_CURR'

// Instructions
export const ASM_ADD = 42;
export const ASM_SUB = 43;
export const ASM_MUL = 44;
export const ASM_JMP = 45;
export const ASM_BEQ = 46;
export const ASM_BNE = 47;
// ...


// A program is a list of instructions
class Instruction {
    constructor(type, addressA, addressB, addressC){
        this.type = type
        this.addressA = addressA
        this.addressB = addressB
        this.addressC = addressC
    }
}

export const compileProgram = source => source.map( instruction => new Instruction(...instruction) )


class CommitInstructionLeaf extends Leaf {
    // TODO: use a register instead, so instructions become more compact and fit into 32 bits 

    lock(vicky, paul) {
        return [
            u32_state_commit(paul, INSTRUCTION_PC_CURR),
            u32_state_commit(paul, INSTRUCTION_PC_NEXT),

            u8_state_commit(paul, INSTRUCTION_TYPE),

            u32_state_commit(paul, INSTRUCTION_ADDRESS_A),
            u32_state_commit(paul, INSTRUCTION_VALUE_A),

            u32_state_commit(paul, INSTRUCTION_ADDRESS_B),
            u32_state_commit(paul, INSTRUCTION_VALUE_B),

            u32_state_commit(paul, INSTRUCTION_ADDRESS_C),
            u32_state_commit(paul, INSTRUCTION_VALUE_C),

            OP_TRUE,
        ]
    }

    unlock(vicky, paul, pcCurr, pcNext, instruction, addressA, valueA, addressB, valueB, addressC, valueC) {
        return [
            u32_state_unlock(paul, INSTRUCTION_VALUE_C, valueC),
            u32_state_unlock(paul, INSTRUCTION_ADDRESS_C, addressC),
            u32_state_unlock(paul, INSTRUCTION_VALUE_B, valueB),
            u32_state_unlock(paul, INSTRUCTION_ADDRESS_B, addressB),
            u32_state_unlock(paul, INSTRUCTION_VALUE_A, valueA),
            u32_state_unlock(paul, INSTRUCTION_ADDRESS_A, addressA),
            u8_state_unlock(paul, INSTRUCTION_TYPE, instruction),
            u32_state_unlock(paul, INSTRUCTION_PC_NEXT, pcNext),
            u32_state_unlock(paul, INSTRUCTION_PC_CURR, pcCurr),
        ]
    }
}

const commitInstructionRoot = (vicky, paul) => [
    [CommitInstructionLeaf, vicky, paul]
]



class ChallengeInstructionLeaf extends Leaf {

    lock(vicky, identifier) {
        return [
            OP_RIPEMD160,
            vicky.hashlock(identifier),
            OP_EQUAL,
        ]
    }

    unlock(vicky, identifier) {
        return [
            vicky.preimage(identifier)
        ]
    }
}




// Vicky disproves an execution of Paul 
class ExecuteAddLeaf extends Leaf {

    lock(vicky, paul) {
        return [
            // Vicky can execute only the instruction which Paul committed to
            u8_state(paul, INSTRUCTION_TYPE),
            ASM_ADD,
            OP_EQUALVERIFY,

            // Show that A + B does not equal C
            u32_state(paul, INSTRUCTION_VALUE_A),
            u32_toaltstack,

            u32_state(paul, INSTRUCTION_VALUE_B),
            u32_toaltstack,

            u32_state(paul, INSTRUCTION_VALUE_C),   // Disproving a single bit of C would suffice

            u32_fromaltstack,
            u32_fromaltstack,
            u32_add_drop(0, 1),
            u32_notequal,
        ]
    }

    unlock(vicky, paul, valueA, valueB, valueC) {
        return [
            u32_state_unlock(paul, INSTRUCTION_VALUE_C, valueC),
            u32_state_unlock(paul, INSTRUCTION_VALUE_B, valueB),
            u32_state_unlock(paul, INSTRUCTION_VALUE_A, valueA),
            u8_state_unlock(paul, INSTRUCTION_TYPE, ASM_ADD),
            // TODO: vicky signs
        ]
    }
}


class ExecuteSubLeaf extends Leaf {

    lock(vicky, paul) {
        return [
            // Vicky can execute only the instruction which Paul committed to
            u8_state(paul, INSTRUCTION_TYPE),
            ASM_SUB,
            OP_EQUALVERIFY,

            // Show that A - B does not equal C
            u32_state(paul, INSTRUCTION_VALUE_A),
            u32_toaltstack,

            u32_state(paul, INSTRUCTION_VALUE_B),
            u32_toaltstack,

            u32_state(paul, INSTRUCTION_VALUE_C),   // Disproving a single bit of C would suffice

            u32_fromaltstack,
            u32_fromaltstack,
            u32_sub_drop(0, 1),
            u32_notequal,
        ]
    }

    unlock(vicky, paul, valueA, valueB, valueC) {
        return [
            u32_state_unlock(paul, INSTRUCTION_VALUE_C, valueC),
            u32_state_unlock(paul, INSTRUCTION_VALUE_B, valueB),
            u32_state_unlock(paul, INSTRUCTION_VALUE_A, valueA),
            u8_state_unlock(paul, INSTRUCTION_TYPE, ASM_SUB),
            // TODO: vicky signs
        ]
    }
}




class ExecuteJmpLeaf extends Leaf {

    lock(vicky, paul) {
        return [
            // Vicky can execute only the instruction which Paul committed to
            u8_state(paul, INSTRUCTION_TYPE),
            ASM_JMP,
            OP_EQUALVERIFY,

            // Show that pcNext does not equal A
            u32_state(paul, INSTRUCTION_PC_NEXT),
            u32_toaltstack,

            u32_state(paul, INSTRUCTION_VALUE_A),

            u32_fromaltstack,
            u32_notequal,
        ]
    }

    unlock(vicky, paul, valueA, pcNext) {
        return [
            u32_state_unlock(paul, INSTRUCTION_VALUE_A, valueA),
            u32_state_unlock(paul, INSTRUCTION_PC_NEXT, pcNext),
            u8_state_unlock(paul, INSTRUCTION_TYPE, ASM_JMP),
        ]
    }
}


// Execute BEQ, "Branch if equal"
class ExecuteBEQLeaf extends Leaf {

    lock(vicky, paul) {
        return [
            u32_state(paul, INSTRUCTION_PC_NEXT),
            u32_toaltstack,

            // Read the current program counter, add 1, and store for later
            u32_state(paul, INSTRUCTION_PC_CURR),
            u32_push(1),
            u32_add_drop(0, 1),
            u32_toaltstack,

            u32_state(paul, INSTRUCTION_VALUE_C),
            u32_toaltstack,

            u32_state(paul, INSTRUCTION_VALUE_B),
            u32_toaltstack,

            u32_state(paul, INSTRUCTION_VALUE_A),
            u32_fromaltstack,

            u32_equal,
            u32_fromaltstack,

            4, OP_ROLL, // Result of u32_equal
            OP_IF,
            u32_fromaltstack,
            u32_drop,
            OP_ELSE,
            u32_drop,
            u32_fromaltstack,
            OP_ENDIF,

            u32_fromaltstack,
            u32_notequal,

        ]
    }

    unlock(vicky, paul, valueA, valueB, valueC, pcCurr, pcNext) {
        return [
            u32_state_unlock(paul, INSTRUCTION_VALUE_A, valueA),
            u32_state_unlock(paul, INSTRUCTION_VALUE_B, valueB),
            u32_state_unlock(paul, INSTRUCTION_VALUE_C, valueC),
            u32_state_unlock(paul, INSTRUCTION_PC_CURR, pcCurr),
            u32_state_unlock(paul, INSTRUCTION_PC_NEXT, pcNext),
            u8_state_unlock(paul, INSTRUCTION_TYPE, ASM_BEQ),
        ]
    }
}


const instructionExecutionRoot = (vicky, paul) => [
    [ExecuteAddLeaf, vicky, paul],
    [ExecuteSubLeaf, vicky, paul],
    [ExecuteJmpLeaf, vicky, paul],
    [ExecuteBEQLeaf, vicky, paul],
]




// For each instruction in the program we create an instruction leaf
class InstructionLeaf extends Leaf {

    // Todo add a leaf for unary instructions
    // TODO: make a separate leaf to disprove addressA, addressB, addressC, ...  
    // Actually, disproving a single bit suffices !!

    lock(vicky, paul, pcCurr, instruction) {
        return [
            // Ensure Vicky is executing the correct instruction here
            u32_state(paul, INSTRUCTION_PC_CURR),
            u32_push(pcCurr),
            u32_notequal,
            OP_TOALTSTACK,

            u8_state(paul, INSTRUCTION_TYPE),
            instruction.type,
            OP_NOTEQUAL,
            OP_TOALTSTACK,

            u32_state(paul, INSTRUCTION_ADDRESS_A),
            u32_push(instruction.addressA),
            u32_notequal,
            OP_TOALTSTACK,

            u32_state(paul, INSTRUCTION_ADDRESS_B),
            u32_push(instruction.addressB),
            u32_notequal,
            OP_TOALTSTACK,

            u32_state(paul, INSTRUCTION_ADDRESS_C),
            u32_push(instruction.addressC),
            u32_notequal,

            OP_FROMALTSTACK,
            OP_FROMALTSTACK,
            OP_FROMALTSTACK,
            OP_FROMALTSTACK,
            OP_BOOLOR,
            OP_BOOLOR,
            OP_BOOLOR,
            OP_BOOLOR,

            // TODO: vicky should sign!
        ]
    }

    unlock(vicky, paul, pcCurr, instruction) {
        return [
            u32_state_unlock(paul, INSTRUCTION_ADDRESS_C, instruction.addressC),
            u32_state_unlock(paul, INSTRUCTION_ADDRESS_B, instruction.addressB),
            u32_state_unlock(paul, INSTRUCTION_ADDRESS_A, instruction.addressA),
            u32_state_unlock(paul, INSTRUCTION_TYPE, instruction.type),
            u32_state_unlock(paul, INSTRUCTION_PC_CURR, pcCurr),
        ]
    }
}

// Create an InstructionLeaf for every instruction in the program
const programRoot = (vicky, paul, program) =>
    program.map((instruction, index) => [InstructionLeaf, vicky, paul, index, new Instruction(instruction)])



const challengeInstructionRoot = (vicky, paul, program) => [
    [ChallengeInstructionLeaf, vicky, CHALLENGE_VALUE_A],
    [ChallengeInstructionLeaf, vicky, CHALLENGE_VALUE_B],
    [ChallengeInstructionLeaf, vicky, CHALLENGE_VALUE_C],
    [ChallengeInstructionLeaf, vicky, CHALLENGE_PC_CURR],
    ...instructionExecutionRoot(vicky, paul),
    ...programRoot(vicky, paul, program),
]


const mergeSequences = (sequenceA, sequenceB) => {
    const length = Math.max(sequenceA.length, sequenceB.length)
    const result = []
    for (let i = 0; i < length; i++) {
        const a = sequenceA[i] || []
        const b = sequenceB[i] || []
        result[i] = [...a, ...b]
    }
    return result
}


class KickOffLeaf extends Leaf {

    lock(vicky){
        return [
            vicky.pubkey,
            OP_CHECKSIG
        ]
    }

    unlock(vicky){
        return [
            vicky.sign(this)
        ]
    }

}

const kickOffRoot = vicky => [
    [KickOffLeaf, vicky]
]

export const bitvmSequence = (vicky, paul, program) => [
    kickOffRoot(vicky),
    ...binarySearchSequence(vicky, paul, TRACE_CHALLENGE, TRACE_RESPONSE, LOG_TRACE_LEN),
    commitInstructionRoot(vicky, paul),
    challengeInstructionRoot(vicky, paul, program),
    ...merkleSequence(vicky, paul),
]

