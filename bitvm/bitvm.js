import { u32_add_drop, u32_add } from '../scripts/opcodes/u32_add.js'
import { u32_sub_drop } from '../scripts/opcodes/u32_sub.js'
import { u32_or } from '../scripts/opcodes/u32_or.js'
import { u32_and } from '../scripts/opcodes/u32_and.js'
import { u32_xor, u32_drop_xor_table, u32_push_xor_table } from '../scripts/opcodes/u32_xor.js'
import { u32_lshift8, u32_rshift8 } from '../scripts/opcodes/u32_shift.js'
import { u32_lessthan } from '../scripts/opcodes/u32_cmp.js'
import { Leaf, Transaction, StartTransaction, EndTransaction } from '../scripts/transaction.js'
import { Instruction } from './vm.js'

import {
    u32_toaltstack,
    u32_fromaltstack,
    u32_equalverify,
    u32_equal,
    u32_push,
    u32_drop,
    u32_notequal,
    u32_dup,
    u32_roll,
} from '../scripts/opcodes/u32_std.js'

import {
    TIMEOUT,
    PAUL,
    VICKY,
    ASM_ADD,
    ASM_SUB,
    ASM_MUL,
    ASM_AND,
    ASM_OR,
    ASM_XOR,
    ASM_ADDI,
    ASM_SUBI,
    ASM_ANDI,
    ASM_ORI,
    ASM_XORI,
    ASM_JMP,
    ASM_BEQ,
    ASM_BNE,
    ASM_RSHIFT1,
    ASM_RSHIFT8,
    ASM_LSHIFT8,
    ASM_SLTU,
    ASM_SLT,
    ASM_LOAD,
    ASM_STORE,
    ASM_SYSCALL,
} from './constants.js'
import { OP_ENDIF, OP_EQUAL, OP_EQUALVERIFY, OP_FROMALTSTACK, OP_TOALTSTACK } from '../scripts/opcodes/opcodes.js'



class KickOffLeaf extends Leaf {

    lock(vicky) {
        return [
            vicky.pubkey,
            OP_CHECKSIG
        ]
    }

    unlock(vicky) {
        return [
            vicky.sign(this)
        ]
    }
}

export class KickOff extends StartTransaction {
    static ACTOR = VICKY

    static taproot(params) {
        return [
            [KickOffLeaf, params.vicky]
        ]
    }
}

export class CommitInstructionAddLeaf extends Leaf {

    lock(vicky, paul) {
        return [
            paul.push.instructionType,
            ASM_ADD,
            OP_EQUALVERIFY,

            paul.push.pcCurr,
            u32_toaltstack,
            paul.push.pcNext,
            u32_fromaltstack,
            u32_push(1),
            u32_add_drop(0, 1),
            u32_equalverify,

            paul.push.valueC,
            u32_toaltstack,

            paul.push.valueB,
            u32_toaltstack,
            paul.push.valueA,
            u32_fromaltstack,
            u32_add_drop(0, 1),
            u32_fromaltstack,
            u32_equalverify,


            paul.commit.addressA,
            paul.commit.addressB,
            paul.commit.addressC,

            OP_TRUE, // TODO: verify covenant here
        ]
    }

    unlock(vicky, paul) {
        return [
            paul.unlock.addressC,
            paul.unlock.addressB,
            paul.unlock.addressA,
            paul.unlock.valueA,
            paul.unlock.valueB,
            paul.unlock.valueC,
            paul.unlock.pcNext,
            paul.unlock.pcCurr,
            paul.unlock.instructionType,
        ]
    }
}

// Different to the CommitInstructionAddLeaf
// The second summand is addressB instead of valueB
export class CommitInstructionAddImmediateLeaf extends Leaf {

    lock(vicky, paul) {
        return [
            paul.push.instructionType,
            ASM_ADDI,
            OP_EQUALVERIFY,

            paul.push.pcCurr,
            u32_toaltstack,
            paul.push.pcNext,
            u32_fromaltstack,
            u32_push(1),
            u32_add_drop(0, 1),
            u32_equalverify,

            paul.push.valueC,
            u32_toaltstack,

            paul.push.addressB,
            u32_toaltstack,
            paul.push.valueA,
            u32_fromaltstack,
            u32_add_drop(0, 1),
            u32_fromaltstack,
            u32_equalverify,


            paul.commit.addressA,
            paul.commit.addressC,

            OP_TRUE, // TODO: verify covenant here
        ]
    }

    unlock(vicky, paul) {
        return [
            paul.unlock.addressC,
            paul.unlock.addressA,
            paul.unlock.valueA,
            paul.unlock.addressB,
            paul.unlock.valueC,
            paul.unlock.pcNext,
            paul.unlock.pcCurr,
            paul.unlock.instructionType,
        ]
    }
}


export class CommitInstructionSubLeaf extends Leaf {

    lock(vicky, paul) {
        return [
            paul.push.instructionType,
            ASM_SUB,
            OP_EQUALVERIFY,

            paul.push.pcCurr,
            u32_toaltstack,
            paul.push.pcNext,
            u32_fromaltstack,
            u32_push(1),
            u32_add_drop(0, 1),
            u32_equalverify,

            paul.push.valueC,
            u32_toaltstack,

            paul.push.valueA,
            u32_toaltstack,
            paul.push.valueB,
            u32_fromaltstack,
            u32_sub_drop(0, 1),
            u32_fromaltstack,
            u32_equalverify,


            paul.commit.addressA,
            paul.commit.addressB,
            paul.commit.addressC,

            OP_TRUE, // TODO: verify covenant here
        ]
    }

    unlock(vicky, paul) {
        return [
            paul.unlock.addressC,
            paul.unlock.addressB,
            paul.unlock.addressA,
            paul.unlock.valueB,
            paul.unlock.valueA,
            paul.unlock.valueC,
            paul.unlock.pcNext,
            paul.unlock.pcCurr,
            paul.unlock.instructionType,
        ]
    }
}


export class CommitInstructionSubImmediateLeaf extends Leaf {

    lock(vicky, paul) {
        return [
            paul.push.instructionType,
            ASM_SUBI,
            OP_EQUALVERIFY,

            paul.push.pcCurr,
            u32_toaltstack,
            paul.push.pcNext,
            u32_fromaltstack,
            u32_push(1),
            u32_add_drop(0, 1),
            u32_equalverify,

            paul.push.valueC,
            u32_toaltstack,

            paul.push.valueA,
            u32_toaltstack,
            paul.push.addressB,
            u32_fromaltstack,
            u32_sub_drop(0, 1),
            u32_fromaltstack,
            u32_equalverify,


            paul.commit.addressA,
            paul.commit.addressC,

            OP_TRUE, // TODO: verify covenant here
        ]
    }

    unlock(vicky, paul) {
        return [
            paul.unlock.addressC,
            paul.unlock.addressA,
            paul.unlock.addressB,
            paul.unlock.valueA,
            paul.unlock.valueC,
            paul.unlock.pcNext,
            paul.unlock.pcCurr,
            paul.unlock.instructionType,
        ]
    }
}


export class CommitInstructionLoadLeaf extends Leaf {

    lock(vicky, paul) {
        return [
            paul.push.instructionType,
            ASM_LOAD,
            OP_EQUALVERIFY,

            paul.push.pcCurr,
            u32_toaltstack,
            paul.push.pcNext,
            u32_fromaltstack,
            u32_push(1),
            u32_add_drop(0, 1),
            u32_equalverify,

            // Check if addressA == valueB
            paul.push.addressA,
            u32_toaltstack,
            paul.push.valueB,
            u32_fromaltstack,
            u32_equalverify,

            // Check if valueA == valueC
            paul.push.valueA,
            u32_toaltstack,
            paul.push.valueC,
            u32_fromaltstack,
            u32_equalverify,

            paul.commit.addressB,
            paul.commit.addressC,

            OP_TRUE, // TODO: verify covenant here
        ]
    }

    unlock(vicky, paul) {
        return [
            paul.unlock.addressC,
            paul.unlock.addressB,
            paul.unlock.valueC,
            paul.unlock.valueA,
            paul.unlock.valueB,
            paul.unlock.addressA,
            paul.unlock.pcNext,
            paul.unlock.pcCurr,
            paul.unlock.instructionType,
        ]
    }
}


export class CommitInstructionStoreLeaf extends Leaf {

    lock(vicky, paul) {
        return [
            paul.push.instructionType,
            ASM_STORE,
            OP_EQUALVERIFY,

            paul.push.pcCurr,
            u32_toaltstack,
            paul.push.pcNext,
            u32_fromaltstack,
            u32_push(1),
            u32_add_drop(0, 1),
            u32_equalverify,

            // Check if addressC == valueB
            paul.push.addressC,
            u32_toaltstack,
            paul.push.valueB,
            u32_fromaltstack,
            u32_equalverify,

            // Check if valueA == valueC
            paul.push.valueA,
            u32_toaltstack,
            paul.push.valueC,
            u32_fromaltstack,
            u32_equalverify,

            paul.commit.addressA,
            paul.commit.addressB,

            OP_TRUE, // TODO: verify covenant here
        ]
    }

    unlock(vicky, paul) {
        return [
            paul.unlock.addressB,
            paul.unlock.addressA,
            paul.unlock.valueC,
            paul.unlock.valueA,
            paul.unlock.valueB,
            paul.unlock.addressC,
            paul.unlock.pcNext,
            paul.unlock.pcCurr,
            paul.unlock.instructionType,
        ]
    }
}

export class CommitInstructionAndLeaf extends Leaf {

    lock(vicky, paul) {
        return [
            paul.push.instructionType,
            ASM_AND,
            OP_EQUALVERIFY,

            paul.push.pcCurr,
            u32_toaltstack,
            paul.push.pcNext,
            u32_fromaltstack,
            u32_push(1),
            u32_add_drop(0, 1),
            u32_equalverify,

            paul.push.valueC,
            u32_toaltstack,
            paul.push.valueB,
            u32_toaltstack,
            paul.push.valueA,
            u32_toaltstack,

            u32_push_xor_table,
            u32_fromaltstack,
            u32_fromaltstack,
            u32_and(0, 1, 3),
            u32_fromaltstack,
            u32_equalverify,
            u32_drop,
            u32_drop_xor_table,

            paul.commit.addressA,
            paul.commit.addressB,
            paul.commit.addressC,

            OP_TRUE, // TODO: verify covenant here
        ]
    }

    unlock(vicky, paul) {
        return [
            paul.unlock.addressC,
            paul.unlock.addressB,
            paul.unlock.addressA,
            paul.unlock.valueA,
            paul.unlock.valueB,
            paul.unlock.valueC,
            paul.unlock.pcNext,
            paul.unlock.pcCurr,
            paul.unlock.instructionType,
        ]
    }
}


export class CommitInstructionAndImmediateLeaf extends Leaf {

    lock(vicky, paul) {
        return [
            paul.push.instructionType,
            ASM_ANDI,
            OP_EQUALVERIFY,

            paul.push.pcCurr,
            u32_toaltstack,
            paul.push.pcNext,
            u32_fromaltstack,
            u32_push(1),
            u32_add_drop(0, 1),
            u32_equalverify,

            paul.push.valueC,
            u32_toaltstack,
            paul.push.addressB,
            u32_toaltstack,
            paul.push.valueA,
            u32_toaltstack,

            u32_push_xor_table,
            u32_fromaltstack,
            u32_fromaltstack,
            u32_and(0, 1, 3),
            u32_fromaltstack,
            u32_equalverify,
            u32_drop,
            u32_drop_xor_table,

            paul.commit.addressA,
            paul.commit.addressC,

            OP_TRUE, // TODO: verify covenant here
        ]
    }

    unlock(vicky, paul) {
        return [
            paul.unlock.addressC,
            paul.unlock.addressA,
            paul.unlock.valueA,
            paul.unlock.addressB,
            paul.unlock.valueC,
            paul.unlock.pcNext,
            paul.unlock.pcCurr,
            paul.unlock.instructionType,
        ]
    }
}
export class CommitInstructionOrLeaf extends Leaf {

    lock(vicky, paul) {
        return [
            paul.push.instructionType,
            ASM_OR,
            OP_EQUALVERIFY,

            paul.push.pcCurr,
            u32_toaltstack,
            paul.push.pcNext,
            u32_fromaltstack,
            u32_push(1),
            u32_add_drop(0, 1),
            u32_equalverify,

            paul.push.valueC,
            u32_toaltstack,
            paul.push.valueB,
            u32_toaltstack,
            paul.push.valueA,
            u32_toaltstack,

            u32_push_xor_table,
            u32_fromaltstack,
            u32_fromaltstack,
            u32_or(0, 1, 3),
            u32_fromaltstack,
            u32_equalverify,
            u32_drop,
            u32_drop_xor_table,

            paul.commit.addressA,
            paul.commit.addressB,
            paul.commit.addressC,

            OP_TRUE, // TODO: verify covenant here
        ]
    }

    unlock(vicky, paul) {
        return [
            paul.unlock.addressC,
            paul.unlock.addressB,
            paul.unlock.addressA,
            paul.unlock.valueA,
            paul.unlock.valueB,
            paul.unlock.valueC,
            paul.unlock.pcNext,
            paul.unlock.pcCurr,
            paul.unlock.instructionType,
        ]
    }
}


export class CommitInstructionOrImmediateLeaf extends Leaf {

    lock(vicky, paul) {
        return [
            paul.push.instructionType,
            ASM_ORI,
            OP_EQUALVERIFY,

            paul.push.pcCurr,
            u32_toaltstack,
            paul.push.pcNext,
            u32_fromaltstack,
            u32_push(1),
            u32_add_drop(0, 1),
            u32_equalverify,

            paul.push.valueC,
            u32_toaltstack,
            paul.push.addressB,
            u32_toaltstack,
            paul.push.valueA,
            u32_toaltstack,

            u32_push_xor_table,
            u32_fromaltstack,
            u32_fromaltstack,
            u32_or(0, 1, 3),
            u32_fromaltstack,
            u32_equalverify,
            u32_drop,
            u32_drop_xor_table,

            paul.commit.addressA,
            paul.commit.addressC,

            OP_TRUE, // TODO: verify covenant here
        ]
    }

    unlock(vicky, paul) {
        return [
            paul.unlock.addressC,
            paul.unlock.addressA,
            paul.unlock.valueA,
            paul.unlock.addressB,
            paul.unlock.valueC,
            paul.unlock.pcNext,
            paul.unlock.pcCurr,
            paul.unlock.instructionType,
        ]
    }
}

export class CommitInstructionXorLeaf extends Leaf {

    lock(vicky, paul) {
        return [
            paul.push.instructionType,
            ASM_XOR,
            OP_EQUALVERIFY,

            paul.push.pcCurr,
            u32_toaltstack,
            paul.push.pcNext,
            u32_fromaltstack,
            u32_push(1),
            u32_add_drop(0, 1),
            u32_equalverify,

            paul.push.valueC,
            u32_toaltstack,
            paul.push.valueB,
            u32_toaltstack,
            paul.push.valueA,
            u32_toaltstack,

            u32_push_xor_table,
            u32_fromaltstack,
            u32_fromaltstack,
            u32_xor(0, 1, 3),
            u32_fromaltstack,
            u32_equalverify,
            u32_drop,
            u32_drop_xor_table,

            paul.commit.addressA,
            paul.commit.addressB,
            paul.commit.addressC,

            OP_TRUE, // TODO: verify covenant here
        ]
    }

    unlock(vicky, paul) {
        return [
            paul.unlock.addressC,
            paul.unlock.addressB,
            paul.unlock.addressA,
            paul.unlock.valueA,
            paul.unlock.valueB,
            paul.unlock.valueC,
            paul.unlock.pcNext,
            paul.unlock.pcCurr,
            paul.unlock.instructionType,
        ]
    }
}


export class CommitInstructionXorImmediateLeaf extends Leaf {

    lock(vicky, paul) {
        return [
            paul.push.instructionType,
            ASM_XORI,
            OP_EQUALVERIFY,

            paul.push.pcCurr,
            u32_toaltstack,
            paul.push.pcNext,
            u32_fromaltstack,
            u32_push(1),
            u32_add_drop(0, 1),
            u32_equalverify,

            paul.push.valueC,
            u32_toaltstack,
            paul.push.addressB,
            u32_toaltstack,
            paul.push.valueA,
            u32_toaltstack,

            u32_push_xor_table,
            u32_fromaltstack,
            u32_fromaltstack,
            u32_xor(0, 1, 3),
            u32_fromaltstack,
            u32_equalverify,
            u32_drop,
            u32_drop_xor_table,

            paul.commit.addressA,
            paul.commit.addressC,

            OP_TRUE, // TODO: verify covenant here
        ]
    }

    unlock(vicky, paul) {
        return [
            paul.unlock.addressC,
            paul.unlock.addressA,
            paul.unlock.valueA,
            paul.unlock.addressB,
            paul.unlock.valueC,
            paul.unlock.pcNext,
            paul.unlock.pcCurr,
            paul.unlock.instructionType,
        ]
    }
}


export class CommitInstructionJMPLeaf extends Leaf {

    lock(vicky, paul) {
        return [
            paul.push.instructionType,
            ASM_JMP,
            OP_EQUALVERIFY,

            paul.push.pcNext,
            u32_toaltstack,
            paul.push.valueA,
            u32_fromaltstack,
            u32_equalverify,

            paul.commit.addressA,

            OP_TRUE, // TODO: verify covenant here
        ]
    }

    unlock(vicky, paul) {
        return [
            paul.unlock.addressA,
            paul.unlock.valueA,
            paul.unlock.pcNext,
            paul.unlock.instructionType,
        ]
    }
}


// Execute BEQ, "Branch if equal"
export class CommitInstructionBEQLeaf extends Leaf {

    lock(vicky, paul) {
        return [
            // Ensure the instructionType is ASM_BEQ
            paul.push.instructionType,
            ASM_BEQ,
            OP_EQUALVERIFY,

            // Read pcNext and put it on the altstack
            paul.push.pcNext,
            u32_toaltstack,

            // Check if valueA == valueB
            paul.push.valueA,
            u32_toaltstack,
            paul.push.valueB,
            u32_fromaltstack,
            u32_equal,

            OP_IF,
            // If valueA == valueB then pcNext = addressC
            paul.push.addressC,
            OP_ELSE,
            // Otherwise, pcNext = pcCurr + 1
            paul.push.pcCurr,
            u32_push(1),
            u32_add_drop(0, 1),
            OP_ENDIF,

            // Take pcNext from the altstack
            u32_fromaltstack,
            // Ensure its equal to the result from above
            u32_equalverify,

            // Commit to addressA and addressB
            paul.commit.addressA,
            paul.commit.addressB,

            // TODO: Check the covenant here
            OP_TRUE,
        ]
    }

    unlock(vicky, paul) {
        return [
            paul.unlock.addressB,
            paul.unlock.addressA,

            // IF valueA == valueB THEN addressC ELSE pcCurr
            paul.valueA == paul.valueB ? paul.unlock.addressC : paul.unlock.pcCurr,

            paul.unlock.valueB,
            paul.unlock.valueA,
            paul.unlock.pcNext,
            paul.unlock.instructionType,
        ]
    }
}


// Execute BEQ, "Branch if not equal"
export class CommitInstructionBNELeaf extends Leaf {

    lock(vicky, paul) {
        return [
            // Ensure the instructionType is ASM_BEQ
            paul.push.instructionType,
            ASM_BNE,
            OP_EQUALVERIFY,

            // Read pcNext and put it on the altstack
            paul.push.pcNext,
            u32_toaltstack,

            // Check if valueA !== valueB
            paul.push.valueA,
            u32_toaltstack,
            paul.push.valueB,
            u32_fromaltstack,
            u32_notequal,

            OP_IF,
            // If valueA !== valueB then pcNext = addressC
            paul.push.addressC,
            OP_ELSE,
            // Otherwise, pcNext = pcCurr + 1
            paul.push.pcCurr,
            u32_push(1),
            u32_add_drop(0, 1),
            OP_ENDIF,

            // Take pcNext from the altstack
            u32_fromaltstack,
            // Ensure its equal to the result from above
            u32_equalverify,

            // Commit to addressA and addressB
            paul.commit.addressA,
            paul.commit.addressB,

            // TODO: Check the covenant here
            OP_TRUE,
        ]
    }

    unlock(vicky, paul) {
        return [
            paul.unlock.addressB,
            paul.unlock.addressA,

            // IF valueA !== valueB THEN addressC ELSE pcCurr
            paul.valueA !== paul.valueB ? paul.unlock.addressC : paul.unlock.pcCurr,

            paul.unlock.valueB,
            paul.unlock.valueA,
            paul.unlock.pcNext,
            paul.unlock.instructionType,
        ]
    }
}


export class CommitInstructionRSHIFT1Leaf extends Leaf {

    lock(vicky, paul) {
        return [
            paul.push.instructionType,
            ASM_RSHIFT1,
            OP_EQUALVERIFY,

            paul.push.pcCurr,
            u32_toaltstack,
            paul.push.pcNext,
            u32_fromaltstack,
            u32_push(1),
            u32_add_drop(0, 1),
            u32_equalverify,

            paul.push.valueA,
            u32_toaltstack,
            u32_push(0x80000000),
            u32_toaltstack,
            paul.push.valueC,
            u32_dup,
            u32_fromaltstack,
            // valueC MSB is 0
            u32_lessthan,
            OP_VERIFY,
            // valueC << 1
            u32_dup,
            u32_add_drop(0, 1),
            // Either valueC == valueA or valueC + 1 == valueA
            u32_push(1),
            u32_add(1, 0),
            u32_fromaltstack,
            u32_dup,
            u32_roll(2),
            u32_equal,
            OP_TOALTSTACK,
            u32_equal,
            OP_FROMALTSTACK,
            OP_BOOLOR,
            OP_VERIFY,

            paul.commit.addressA,
            paul.commit.addressC,

            OP_TRUE, // TODO: verify covenant here
        ]
    }

    unlock(vicky, paul) {
        return [
            paul.unlock.addressC,
            paul.unlock.addressA,
            paul.unlock.valueC,
            paul.unlock.valueA,
            paul.unlock.pcNext,
            paul.unlock.pcCurr,
            paul.unlock.instructionType,
        ]
    }
}


export class CommitInstructionRSHIFT8Leaf extends Leaf {

    lock(vicky, paul) {
        return [
            paul.push.instructionType,
            ASM_RSHIFT8,
            OP_EQUALVERIFY,

            paul.push.pcCurr,
            u32_toaltstack,
            paul.push.pcNext,
            u32_fromaltstack,
            u32_push(1),
            u32_add_drop(0, 1),
            u32_equalverify,

            paul.push.valueA,
            u32_toaltstack,
            paul.push.valueC,
            u32_fromaltstack,
            u32_rshift8,
            u32_equalverify,

            paul.commit.addressA,
            paul.commit.addressC,

            OP_TRUE, // TODO: verify covenant here
        ]
    }

    unlock(vicky, paul) {
        return [
            paul.unlock.addressC,
            paul.unlock.addressA,
            paul.unlock.valueC,
            paul.unlock.valueA,
            paul.unlock.pcNext,
            paul.unlock.pcCurr,
            paul.unlock.instructionType,
        ]
    }
}

export class CommitInstructionLSHIFT8Leaf extends Leaf {

    lock(vicky, paul) {
        return [
            paul.push.instructionType,
            ASM_LSHIFT8,
            OP_EQUALVERIFY,

            paul.push.pcCurr,
            u32_toaltstack,
            paul.push.pcNext,
            u32_fromaltstack,
            u32_push(1),
            u32_add_drop(0, 1),
            u32_equalverify,

            paul.push.valueA,
            u32_toaltstack,
            paul.push.valueC,
            u32_fromaltstack,
            u32_lshift8,
            u32_equalverify,

            paul.commit.addressA,
            paul.commit.addressC,

            OP_TRUE, // TODO: verify covenant here
        ]
    }

    unlock(vicky, paul) {
        return [
            paul.unlock.addressC,
            paul.unlock.addressA,
            paul.unlock.valueC,
            paul.unlock.valueA,
            paul.unlock.pcNext,
            paul.unlock.pcCurr,
            paul.unlock.instructionType,
        ]
    }
}

export class CommitInstructionSLTULeaf extends Leaf {

    lock(vicky, paul) {
        return [
            paul.push.instructionType,
            ASM_SLTU,
            OP_EQUALVERIFY,

            paul.push.pcCurr,
            u32_toaltstack,
            paul.push.pcNext,
            u32_fromaltstack,
            u32_push(1),
            u32_add_drop(0, 1),
            u32_equalverify,

            paul.push.valueC,
            u32_toaltstack,

            paul.push.valueB,
            u32_toaltstack,
            paul.push.valueA,
            u32_fromaltstack,
            u32_lessthan,
            OP_IF,
            u32_push(1),
            OP_ELSE,
            u32_push(0),
            OP_ENDIF,
            u32_fromaltstack,
            u32_equalverify,


            paul.commit.addressA,
            paul.commit.addressB,
            paul.commit.addressC,

            OP_TRUE, // TODO: verify covenant here
        ]
    }

    unlock(vicky, paul) {
        return [
            paul.unlock.addressC,
            paul.unlock.addressB,
            paul.unlock.addressA,
            paul.unlock.valueA,
            paul.unlock.valueB,
            paul.unlock.valueC,
            paul.unlock.pcNext,
            paul.unlock.pcCurr,
            paul.unlock.instructionType,
        ]
    }
}


export class CommitInstructionSLTLeaf extends Leaf {

    lock(vicky, paul) {
        return [
            paul.push.instructionType,
            ASM_SLT,
            OP_EQUALVERIFY,

            paul.push.pcCurr,
            u32_toaltstack,
            paul.push.pcNext,
            u32_fromaltstack,
            u32_push(1),
            u32_add_drop(0, 1),
            u32_equalverify,

            paul.push.valueC,
            u32_toaltstack,

            paul.push.valueA,
            u32_dup,
            u32_push(0x8000_0000),
            u32_lessthan,
            // Put negated valueA sign on altstack
            OP_TOALTSTACK,
            u32_toaltstack,
            paul.push.valueB,
            u32_fromaltstack,
            u32_roll(1),
            u32_dup,
            u32_push(0x8000_0000),
            u32_lessthan,
            // Put negated valueB sign on altstack
            OP_TOALTSTACK,
            u32_lessthan,
            // If valueA and valueB have different signs the result has to be flipped
            OP_FROMALTSTACK,
            OP_FROMALTSTACK,
            OP_ADD,
            1,
            OP_EQUAL,
            OP_IF,
            OP_NOT,
            OP_ENDIF,

            // Check whether valueC is correctly set to the lessthan result
            OP_IF,
            u32_push(1),
            OP_ELSE,
            u32_push(0),
            OP_ENDIF,
            u32_fromaltstack,
            u32_equalverify,

            paul.commit.addressA,
            paul.commit.addressB,
            paul.commit.addressC,

            OP_TRUE, // TODO: verify covenant here
        ]
    }

    unlock(vicky, paul) {
        return [
            paul.unlock.addressC,
            paul.unlock.addressB,
            paul.unlock.addressA,
            paul.unlock.valueB,
            paul.unlock.valueA,
            paul.unlock.valueC,
            paul.unlock.pcNext,
            paul.unlock.pcCurr,
            paul.unlock.instructionType,
        ]
    }
}


export class CommitInstruction extends Transaction {

    static ACTOR = PAUL

    static taproot(params) {
        return [
            [CommitInstructionAddLeaf, params.vicky, params.paul],
            [CommitInstructionAddImmediateLeaf, params.vicky, params.paul],
            [CommitInstructionOrLeaf, params.vicky, params.paul],
            [CommitInstructionOrImmediateLeaf, params.vicky, params.paul],
            [CommitInstructionAndLeaf, params.vicky, params.paul],
            [CommitInstructionAndImmediateLeaf, params.vicky, params.paul],
            [CommitInstructionXorLeaf, params.vicky, params.paul],
            [CommitInstructionXorImmediateLeaf, params.vicky, params.paul],
            [CommitInstructionSubLeaf, params.vicky, params.paul],
            [CommitInstructionSubImmediateLeaf, params.vicky, params.paul],
            [CommitInstructionJMPLeaf, params.vicky, params.paul],
            [CommitInstructionBEQLeaf, params.vicky, params.paul],
            [CommitInstructionBNELeaf, params.vicky, params.paul],
            [CommitInstructionSLTLeaf, params.vicky, params.paul],
            [CommitInstructionSLTULeaf, params.vicky, params.paul],
            [CommitInstructionRSHIFT1Leaf, params.vicky, params.paul],
            [CommitInstructionStoreLeaf, params.vicky, params.paul],
            [CommitInstructionLoadLeaf, params.vicky, params.paul],
            [CommitInstructionRSHIFT8Leaf, params.vicky, params.paul],
            [CommitInstructionLSHIFT8Leaf, params.vicky, params.paul],
        ]
    }
}





export class CommitInstructionLeafTimeout extends Leaf {

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

export class CommitInstructionTimeout extends EndTransaction {
    static ACTOR = PAUL
    static taproot(params) {
        return [
            [CommitInstructionLeafTimeout, params.vicky, params.paul]
        ]
    }
}


class ChallengeValueALeaf extends Leaf {

    lock(vicky, paul) {
        return [
            1, OP_DROP,     // TODO: this is just a hack to have different TXIDs for valueA and valueB. We can do it with e.g. nSequence or so

            // TODO: Paul has to presign
            vicky.pubkey,
            OP_CHECKSIG,
        ]
    }

    unlock(vicky, paul) {
        if(!vicky.isFaultyReadA)
            throw Error(`Cannot unlock ${this.constructor.name}`)
        return [
            vicky.sign(this)
        ]
    }
}

class ChallengeValueBLeaf extends Leaf {

    lock(vicky, paul) {
        return [
            2, OP_DROP,     // TODO: this is just a hack to have different TXIDs for valueA and valueB. We can do it with e.g. nSequence or so

            // TODO: Paul has to presign
            vicky.pubkey,
            OP_CHECKSIG,
        ]
    }

    unlock(vicky, paul) {
        if(!vicky.isFaultyReadB)
            throw Error(`Cannot unlock ${this.constructor.name}`)
        return [
            vicky.sign(this)
        ]
    }
}

class ChallengeValueCLeaf extends Leaf {

    lock(vicky, paul) {
        return [
            3, OP_DROP,     // TODO: this is just a hack to have different TXIDs for valueA and valueB. We can do it with e.g. nSequence or so
            // TODO: Paul has to presign
            vicky.pubkey,
            OP_CHECKSIG,
        ]
    }

    unlock(vicky, paul) {
        if(!vicky.isFaultyWriteC)
            throw Error(`Cannot unlock ${this.constructor.name}`)
        return [
            vicky.sign(this)
        ]
    }
}



export class ChallengeValueA extends Transaction {
    static ACTOR = VICKY
    static taproot(params) {
        return [
            [ChallengeValueALeaf, params.vicky, params.paul]
        ]
    }
}

export class ChallengeValueB extends Transaction {
    static ACTOR = VICKY
    static taproot(params) {
        return [
            [ChallengeValueBLeaf, params.vicky, params.paul]
        ]
    }
}

export class ChallengeValueC extends Transaction {
    static ACTOR = VICKY
    static taproot(params) {
        return [
            [ChallengeValueCLeaf, params.vicky, params.paul]
        ]
    }
}


// For each instruction in the program we create an instruction leaf
// Actually, disproving a single bit suffices !!
export class DisproveAddressALeaf extends Leaf {

    lock(vicky, paul, pcCurr, instruction) {
        return [
            paul.push.pcCurr,
            u32_toaltstack,
            u32_push(pcCurr),
            u32_fromaltstack,
            u32_equalverify,

            u32_push(instruction.addressA),
            u32_toaltstack,
            paul.push.addressA,
            u32_fromaltstack,
            u32_notequal,
            OP_VERIFY,
            OP_1,

            // TODO: Signatures
        ]
    }

    unlock(vicky, paul) {
        return [
            paul.unlock.addressA,
            paul.unlock.pcCurr
        ]
    }
}


export class DisproveAddressBLeaf extends Leaf {

    lock(vicky, paul, pcCurr, instruction) {
        return [
            paul.push.pcCurr,
            u32_toaltstack,
            u32_push(pcCurr),
            u32_fromaltstack,
            u32_equalverify,

            u32_push(instruction.addressB),
            u32_toaltstack,
            paul.push.addressB,
            u32_fromaltstack,
            u32_notequal,
            OP_VERIFY,
            OP_1,

            // TODO: Signatures
        ]
    }

    unlock(vicky, paul) {
        return [
            paul.unlock.addressB,
            paul.unlock.pcCurr
        ]
    }
}


export class DisproveAddressCLeaf extends Leaf {

    lock(vicky, paul, pcCurr, instruction) {
        return [
            paul.push.pcCurr,
            u32_toaltstack,
            u32_push(pcCurr),
            u32_fromaltstack,
            u32_equalverify,

            u32_push(instruction.addressC),
            u32_toaltstack,
            paul.push.addressC,
            u32_fromaltstack,
            u32_notequal,
            OP_VERIFY,
            OP_1,

            // TODO: Signatures
        ]
    }

    unlock(vicky, paul) {
        return [
            paul.unlock.addressC,
            paul.unlock.pcCurr
        ]
    }
}


export class DisproveInstructionTypeLeaf extends Leaf {

    lock(vicky, paul, pcCurr, instruction) {
        return [
            paul.push.pcCurr,
            u32_toaltstack,
            u32_push(pcCurr),
            u32_fromaltstack,
            u32_equalverify,

            u32_push(instruction.type),
            u32_toaltstack,
            paul.push.type,
            u32_fromaltstack,
            u32_notequal,
            OP_VERIFY,
            OP_1,

            // TODO: Signatures
        ]
    }

    unlock(vicky, paul) {
        return [
            paul.unlock.instructionType,
            paul.unlock.pcCurr
        ]
    }
}


export class DisproveProgram extends EndTransaction {
    static ACTOR = VICKY
    static taproot(params) {
        const { vicky, paul, program } = params;
        // Create an InstructionLeaf for every instruction in the program
        return program.map((instruction, index) => {
            let disproveLeaves = [[DisproveInstructionTypeLeaf, vicky, paul, index, new Instruction(...instruction)]]
            if (!isNaN(instruction[1])) {
                disproveLeaves.push([DisproveAddressALeaf, vicky, paul, index, new Instruction(...instruction)])
            }
            if (!isNaN(instruction[2])) {
                disproveLeaves.push([DisproveAddressBLeaf, vicky, paul, index, new Instruction(...instruction)])
            }
            if (!isNaN(instruction[3])) {
                disproveLeaves.push([DisproveAddressCLeaf, vicky, paul, index, new Instruction(...instruction)])
            }
            return disproveLeaves
        }).flat(1)
    }
}


export class ChallengePcCurr extends Transaction {
    static ACTOR = VICKY

    static taproot(params) {
        console.warn(`${this.name} not implemented`)
        return [[class extends Leaf {
            lock() {
                return ['OP_0']
            }
            unlock() {
                if(!vicky.isFaultyPcCurr)
                    throw Error(`Cannot unlock ${this.constructor.name}`)
                return []
            }
        }]]
    }

    
}


export class ChallengePcNext extends Transaction {
    static ACTOR = VICKY
    
    static taproot(params) {
        console.warn(`${this.name} not implemented`)
        return [[class ChallengePcNextLeaf extends Leaf {
            lock() {
                return ['OP_1']
            }
            unlock() {
                if(!vicky.isFaultyPcNext)
                    throw Error(`Cannot unlock ${this.constructor.name}`)
                return []
            }
        }]]
    }
}

class ChallengeInstructionTimeoutLeaf extends Leaf {
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

export class ChallengeInstructionTimeout extends EndTransaction {
    static ACTOR = VICKY

    static taproot(params) {
        return [
            [ChallengeInstructionTimeoutLeaf, params.vicky, params.paul]
        ]
    }
}

export class EquivocatedPcNext extends EndTransaction {
    static ACTOR = PAUL

    static taproot(params) {
        console.warn(`${this.name} not implemented`)
        return [[class extends Leaf {
            lock() {
                return ['OP_2']
            }
            unlock() {
                return []
            }
        }]]
    }
}

export class EquivocatedPcNextTimeout extends EndTransaction {
    static ACTOR = VICKY

    static taproot(params) {
        console.warn(`${this.name} not implemented`)
        return [[class extends Leaf {
            lock() {
                return ['OP_0']
            }
            unlock() {
                return []
            }
        }]]
    }
}

export class EquivocatedPcCurr extends EndTransaction {
    static ACTOR = PAUL

    static taproot(params) {
        console.warn(`${this.name} not implemented`)
        return [[class extends Leaf {
            lock() {
                return ['OP_3']
            }
            unlock() {
                return []
            }
        }]]
    }
}

export class EquivocatedPcCurrTimeout extends EndTransaction {
    static ACTOR = VICKY

    static taproot(params) {
        console.warn(`${this.name} not implemented`)
        return [[class extends Leaf {
            lock() {
                return ['OP_4']
            }
            unlock() {
                return []
            }
        }]]
    }
}
