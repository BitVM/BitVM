import { challengeResponseSequence } from './reveal-sequence.js'
import { merkleSequence } from './merkle-sequence.js'
import { u32_state_commit, u32_state, u32_state_unlock, u8_state_unlock, u8_state, u8_state_commit } from '../scripts/opcodes/u32_state.js';
import { u32_toaltstack, u32_fromaltstack, u32_equalverify } from '../scripts/opcodes/u32_std.js';
import { u32_add_drop } from '../scripts/opcodes/u32_add.js';
import { u32_sub_drop } from '../scripts/opcodes/u32_sub.js';
import { Leaf } from './transaction.js';

// Logarithm of the length of the trace
export const LOG_TRACE_LEN = 4

// Variables
const INSTRUCTION_VALUE_A = 'INSTRUCTION_VALUE_A'
const INSTRUCTION_ADDRESS_A = 'INSTRUCTION_ADDRESS_A'
const INSTRUCTION_VALUE_B = 'INSTRUCTION_VALUE_B'
const INSTRUCTION_ADDRESS_B = 'INSTRUCTION_ADDRESS_B'
const INSTRUCTION_VALUE_C = 'INSTRUCTION_VALUE_C'
const INSTRUCTION_ADDRESS_C = 'INSTRUCTION_ADDRESS_C'
const INSTRUCTION_PC = 'INSTRUCTION_PC'
const INSTRUCTION_TYPE = 'INSTRUCTION_TYPE'

// Challenges
const CHALLENGE_EXECUTION = 'challenge-execution'
const CHALLENGE_INSTRUCTION = 'challenge-instruction'
const CHALLENGE_VALUE_A = 'challenge-value_A'
const CHALLENGE_VALUE_B = 'challenge-value_B'
const CHALLENGE_VALUE_C = 'challenge-value_C'
const CHALLENGE_PC = 'challenge-program-counter'

// Instructions
const ASM_ADD = 42;
const ASM_SUB = 43;
const ASM_MUL = 44;
// ...



class InstructionCommitLeaf extends Leaf {

    lock(vicky, paul) {
        return [
            u32_state_commit(paul, INSTRUCTION_PC),
            u8_state_commit (paul, INSTRUCTION_TYPE),

            u32_state_commit(paul, INSTRUCTION_ADDRESS_A),
            u32_state_commit(paul, INSTRUCTION_VALUE_A),

            u32_state_commit(paul, INSTRUCTION_ADDRESS_B),
            u32_state_commit(paul, INSTRUCTION_VALUE_B),

            u32_state_commit(paul, INSTRUCTION_ADDRESS_C),
            u32_state_commit(paul, INSTRUCTION_VALUE_C),
            OP_TRUE,
        ]
    }

    unlock(vicky, paul, programCounter, instruction, addressA, valueA, addressB, valueB, addressC, valueC) {
        return [
            u32_state_unlock(paul, INSTRUCTION_VALUE_C, valueC),
            u32_state_unlock(paul, INSTRUCTION_ADDRESS_C, addressC),
            u32_state_unlock(paul, INSTRUCTION_VALUE_B, valueB),
            u32_state_unlock(paul, INSTRUCTION_ADDRESS_B, addressB),
            u32_state_unlock(paul, INSTRUCTION_VALUE_A, valueA),
            u32_state_unlock(paul, INSTRUCTION_ADDRESS_A, addressA),
            u8_state_unlock (paul, INSTRUCTION_TYPE, instruction),
            u32_state_unlock(paul, INSTRUCTION_PC, programCounter),
        ]
    }
}

const instructionCommitRoot = (vicky, paul) => [
    [InstructionCommitLeaf, vicky, paul]
]



class InstructionChallengeLeaf extends Leaf {

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




const instructionChallengeRoot = (vicky, paul) => [
    [InstructionChallengeLeaf, vicky, CHALLENGE_EXECUTION],
    [InstructionChallengeLeaf, vicky, CHALLENGE_INSTRUCTION],
    [InstructionChallengeLeaf, vicky, CHALLENGE_VALUE_A],
    [InstructionChallengeLeaf, vicky, CHALLENGE_VALUE_B],
    [InstructionChallengeLeaf, vicky, CHALLENGE_VALUE_C],
    [InstructionChallengeLeaf, vicky, CHALLENGE_PC],
]



class InstructionExecutionLeafAdd extends Leaf {
    
    lock(vicky, paul) {
        return [
            // Paul can execute this leaf only if Vicky challenged him to do so
            OP_RIPEMD160,
            OP_RIPEMD160,
            vicky.hashlock(CHALLENGE_EXECUTION),
            OP_EQUALVERIFY,

            // Ensure we're executing the correct instruction here
            u8_state(paul, INSTRUCTION_TYPE),
            ASM_ADD,
            OP_EQUALVERIFY,

            u32_state(paul, INSTRUCTION_VALUE_A),
            u32_toaltstack,

            u32_state(paul, INSTRUCTION_VALUE_B),
            u32_toaltstack,

            u32_state(paul, INSTRUCTION_VALUE_C),

            u32_fromaltstack,
            u32_fromaltstack,
            u32_add_drop(0, 1),
            u32_equalverify,
            OP_TRUE,
        ]
    }

    unlock(vicky, paul, valueA, valueB, valueC) {
        return [
            u32_state_unlock(paul, INSTRUCTION_VALUE_C, valueC),
            u32_state_unlock(paul, INSTRUCTION_VALUE_B, valueB),
            u32_state_unlock(paul, INSTRUCTION_VALUE_A, valueA),
            u8_state_unlock(paul, INSTRUCTION_TYPE, ASM_ADD),
            vicky.preimage(CHALLENGE_EXECUTION)
        ]
    }
}


class InstructionExecutionLeafSub extends Leaf {
    
    lock(vicky, paul) {
        return [
            // Paul can execute this leaf only if Vicky challenged him to do so
            OP_RIPEMD160,
            vicky.hashlock(CHALLENGE_EXECUTION),
            OP_EQUALVERIFY,

            // Ensure we're executing the correct instruction here
            u8_state(paul, INSTRUCTION_TYPE),
            ASM_SUB,
            OP_EQUALVERIFY,

            u32_state(paul, INSTRUCTION_VALUE_A),
            u32_toaltstack,

            u32_state(paul, INSTRUCTION_VALUE_B),
            u32_toaltstack,

            u32_state(paul, INSTRUCTION_VALUE_C),

            u32_fromaltstack,
            u32_fromaltstack,
            u32_sub_drop(0, 1),
            u32_equalverify,
            OP_TRUE,
        ]
    }

    unlock(vicky, paul, valueA, valueB, valueC) {
        return [
            u32_state_unlock(paul, INSTRUCTION_VALUE_C, valueC),
            u32_state_unlock(paul, INSTRUCTION_VALUE_B, valueB),
            u32_state_unlock(paul, INSTRUCTION_VALUE_A, valueA),
            u8_state_unlock(paul, INSTRUCTION_TYPE, ASM_SUB),
            vicky.preimage(CHALLENGE_EXECUTION)
        ]
    }
}


const instructionExecutionRoot = (vicky, paul) => [
    [InstructionExecutionLeafAdd, vicky, paul],
    [InstructionExecutionLeafSub, vicky, paul],
]

function mergeSequences(sequenceA, sequenceB) {
	const length = Math.max(sequenceA.length, sequenceB.length)
	const result = []
    for (let i = 0; i < length; i++) {
    	const a = sequenceA[i] || []
    	const b = sequenceB[i] || []
    	result[i] = [...a, ...b]
    }
    return result
}


export function bitvmSequence(vicky, paul) {
    return [
        ...challengeResponseSequence(vicky, paul, 'trace', LOG_TRACE_LEN),
        instructionCommitRoot(vicky, paul),
        instructionChallengeRoot(vicky, paul),
        ...mergeSequences(
    		merkleSequence(vicky, paul),
    		[ instructionExecutionRoot(vicky, paul) ],
        )
    ]
}