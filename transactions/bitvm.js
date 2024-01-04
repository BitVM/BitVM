import { u32_add_drop } from '../scripts/opcodes/u32_add.js'
import { u32_sub_drop } from '../scripts/opcodes/u32_sub.js'
import { Leaf, Transaction, StartTransaction, EndTransaction } from './transaction.js'
import { Instruction } from '../run/vm.js'
import { merkleSequence } from './merkle-sequence.js'
import { traceSequence } from './trace-sequence.js'

import {
    u32_toaltstack,
    u32_fromaltstack,
    u32_equalverify,
    u32_equal,
    u32_push,
    u32_drop,
    u32_notequal
} from '../scripts/opcodes/u32_std.js'

import {
    TIMEOUT,
    PAUL,
    VICKY,
} from './bitvm-player.js'

// Instructions
export const ASM_ADD = 42
export const ASM_SUB = 43
export const ASM_MUL = 44
export const ASM_JMP = 45
export const ASM_BEQ = 46
export const ASM_BNE = 47
// ...



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




class CommitInstructionLeaf extends Leaf {
    // TODO: use a register instead, so instructions become more compact and fit into 32 bits 

    lock(vicky, paul) {
        return [
            paul.commit.pcCurr,
            paul.commit.pcNext,
            paul.commit.instructionType,
            paul.commit.addressA,
            paul.commit.valueA,
            paul.commit.addressB,
            paul.commit.valueB,
            paul.commit.addressC,
            paul.commit.valueC,

            OP_TRUE, // TODO: verify covenant here
        ]
    }

    unlock(vicky, paul) {
        return [
            paul.unlock.valueC,
            paul.unlock.addressC,
            paul.unlock.valueB,
            paul.unlock.addressB,
            paul.unlock.valueA,
            paul.unlock.addressA,
            paul.unlock.instructionType,
            paul.unlock.pcNext,
            paul.unlock.pcCurr,
        ]
    }
}


class CommitInstructionAddLeaf extends Leaf {

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
            paul.unlock.instructionType,
            paul.unlock.pcCurr,
            paul.unlock.pcNext,
            paul.unlock.valueC,
            paul.unlock.valueB,
            paul.unlock.valueA,
            paul.unlock.addressA,
            paul.unlock.addressB,
            paul.unlock.addressC,
        ]
    }
}

class CommitInstructionSubLeaf extends Leaf {

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

            paul.push.valueB,
            u32_toaltstack,
            paul.push.valueA,
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
            paul.unlock.instructionType,
            paul.unlock.pcCurr,
            paul.unlock.pcNext,
            paul.unlock.valueC,
            paul.unlock.valueB,
            paul.unlock.valueA,
            paul.unlock.addressA,
            paul.unlock.addressB,
            paul.unlock.addressC,
        ]
    }
}


export class CommitInstruction extends Transaction {

    static ACTOR = PAUL

    static taproot(params) {
        return [
            [CommitInstructionAddLeaf, params.vicky, params.paul],
            [CommitInstructionSubLeaf, params.vicky, params.paul],
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


class ChallengeValueLeaf extends Leaf {

    lock(vicky, paul) {
        return [
            // TODO: Paul has to presign
            vicky.pubkey,
            OP_CHECKSIGVERIFY,
        ]
    }

    unlock(vicky, paul) {
        return [
            vicky.sign(this)
        ]
    }
}



export class ChallengeValueA extends Transaction {
    static ACTOR = VICKY
    static taproot(params) {
        return [
            [ChallengeValueLeaf, params.vicky, params.paul]
        ]
    }
}

export class ChallengeValueB extends Transaction {
    static ACTOR = VICKY
    static taproot(params) {
        // TODO: make some slight change here to distinguish ChallengeValueA from ChallengeValueB
        return [
            [ChallengeValueLeaf, params.vicky, params.paul]
        ]
    }
}




// Vicky disproves an execution of Paul 
class ExecuteAddLeaf extends Leaf {

    lock(vicky, paul) {
        return [
            // Vicky can execute only the instruction which Paul committed to
            paul.push.instructionType,
            ASM_ADD,
            OP_EQUALVERIFY,

            // Show that A + B does not equal C
            paul.push.valueA,
            u32_toaltstack,

            paul.push.valueB,
            u32_toaltstack,

            paul.push.valueC, // Disproving a single bit of C would suffice

            u32_fromaltstack,
            u32_fromaltstack,
            u32_add_drop(0, 1),
            u32_notequal,

            // TODO: Verify the covenant
        ]
    }

    unlock(vicky, paul) {
        return [
            paul.unlock.valueC,
            paul.unlock.valueB,
            paul.unlock.valueA,
            paul.unlock.instructionType
            // TODO: vicky signs
        ]
    }
}


class ExecuteSubLeaf extends Leaf {

    lock(vicky, paul) {
        return [
            // Vicky can execute only the instruction which Paul committed to
            paul.push.instructionType,
            ASM_SUB,
            OP_EQUALVERIFY,

            // Show that A - B does not equal C
            paul.push.valueA,
            u32_toaltstack,

            paul.push.valueB,
            u32_toaltstack,

            paul.push.valueC, // Disproving a single bit of C would suffice

            u32_fromaltstack,
            u32_fromaltstack,
            u32_sub_drop(0, 1),
            u32_notequal,
        ]
    }

    unlock(vicky, paul) {
        return [
            paul.unlock.valueC,
            paul.unlock.valueB,
            paul.unlock.valueA,
            paul.unlock.instructionType
            // TODO: vicky signs
        ]
    }
}




class ExecuteJmpLeaf extends Leaf {

    lock(vicky, paul) {
        return [
            // Vicky can execute only the instruction which Paul committed to
            paul.push.instructionType,
            ASM_JMP,
            OP_EQUALVERIFY,

            // Show that pcNext does not equal A
            paul.push.pcNext,
            u32_toaltstack,

            paul.push.valueA,

            u32_fromaltstack,
            u32_notequal,
        ]
    }

    unlock(vicky, paul) {
        return [
            paul.unlock.valueC,
            paul.unlock.pcNext,
            paul.unlock.instructionType
        ]
    }
}


// Execute BEQ, "Branch if equal"
class ExecuteBEQLeaf extends Leaf {

    lock(vicky, paul) {
        return [
            paul.push.instructionType,
            ASM_BEQ,
            OP_EQUALVERIFY,

            paul.push.pcNext,
            u32_toaltstack,

            // Read the current program counter, add 1, and store for later
            paul.push.pcCurr,
            u32_push(1),
            u32_add_drop(0, 1),
            u32_toaltstack,

            paul.push.valueC,
            u32_toaltstack,

            paul.push.valueB,
            u32_toaltstack,

            paul.push.valueA,
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

    unlock(vicky, paul) {
        return [
            paul.unlock.valueA,
            paul.unlock.valueB,
            paul.unlock.valueC,
            paul.unlock.pcCurr,
            paul.unlock.pcNext,
            paul.unlock.instructionType,
        ]
    }
}



export class ChallengeInstructionExecution extends Transaction {
    static taproot(params) {
        const { vicky, paul } = params;
        return [
            [ExecuteAddLeaf, vicky, paul],
            [ExecuteSubLeaf, vicky, paul],
            [ExecuteJmpLeaf, vicky, paul],
            [ExecuteBEQLeaf, vicky, paul],
        ]
    }
}


// For each instruction in the program we create an instruction leaf
class InstructionLeaf extends Leaf {

    // Todo add a leaf for unary instructions
    // TODO: make a separate leaf to disprove addressA, addressB, addressC, ...  
    // Actually, disproving a single bit suffices !!

    // TODO: Further refactor to paul.commit api?
    lock(vicky, paul, pcCurr, instruction) {
        return [
            // Ensure Vicky is executing the correct instruction here
            paul.push.pcCurr,
            u32_push(pcCurr),
            u32_equalverify,

            paul.push.instructionType,
            instruction.type,
            OP_NOTEQUAL,
            OP_TOALTSTACK,

            paul.push.addressA,
            u32_push(instruction.addressA),
            u32_notequal,
            OP_TOALTSTACK,

            paul.push.addressB,
            u32_push(instruction.addressB),
            u32_notequal,
            OP_TOALTSTACK,

            paul.push.addressC,
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

    unlock(vicky, paul) {
        return [
            paul.unlock.valueC,
            paul.unlock.valueB,
            paul.unlock.valueA,
            paul.unlock.instructionType,
            paul.unlock.pcCurr
        ]
    }
}



export class DisproveProgram extends EndTransaction {
    static ACTOR = PAUL

    static taproot(params) {
        const { vicky, paul, program } = params;
        // Create an InstructionLeaf for every instruction in the program
        return program.map((instruction, index) => [InstructionLeaf, vicky, paul, index, new Instruction(instruction)])
    }

}


export class ChallengePcCurr extends Transaction {
    static ACTOR = VICKY
    static taproot(params) {
        console.warn(`${this.name} not implemented`)
        return [[ class extends Leaf{
            lock(){
                return ['OP_0']
            }
            unlock(){
                return []
            }
        }]]
    }
}


export class ChallengePcNext extends Transaction {
    static ACTOR = VICKY
    static taproot(params) {
        console.warn(`${this.name} not implemented`)
        return [[ class extends Leaf{
            lock(){
                return ['OP_1']
            }
            unlock(){
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
        const { vicky, paul } = params;
        return [
            [ChallengeInstructionTimeoutLeaf, vicky, paul]
        ]
    }
}

export class EquivocatedPcNext extends EndTransaction {
    static ACTOR = PAUL

    static taproot(params) {
        console.warn(`${this.name} not implemented`)
        return [[ class extends Leaf{
            lock(){
                return ['OP_2']
            }
            unlock(){
                return []
            }
        }]]
    }
}

export class EquivocatedPcNextTimeout extends EndTransaction {
    static ACTOR = VICKY

    static taproot(params) {
        console.warn(`${this.name} not implemented`)
        return [[ class extends Leaf{
            lock(){
                return ['OP_0']
            }
            unlock(){
                return []
            }
        }]]
    }
}

export class EquivocatedPcCurr extends EndTransaction {
    static ACTOR = PAUL

    static taproot(params) {
        console.warn(`${this.name} not implemented`)
        return [[ class extends Leaf{
            lock(){
                return ['OP_3']
            }
            unlock(){
                return []
            }
        }]]
    }
}

export class EquivocatedPcCurrTimeout extends EndTransaction {
    static ACTOR = VICKY

    static taproot(params) {
        console.warn(`${this.name} not implemented`)
        return [[ class extends Leaf{
            lock(){
                return ['OP_4']
            }
            unlock(){
                return []
            }
        }]]
    }
}
