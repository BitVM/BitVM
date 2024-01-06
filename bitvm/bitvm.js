import { u32_add_drop } from '../scripts/opcodes/u32_add.js'
import { u32_sub_drop } from '../scripts/opcodes/u32_sub.js'
import { Leaf, Transaction, StartTransaction, EndTransaction } from '../scripts/transaction.js'
import { Instruction } from './vm.js'
import { merkleSequence } from './merkle-sequence.js'

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
    ASM_ADD,
    ASM_SUB,
    ASM_MUL,
    ASM_JMP,
    ASM_BEQ,
    ASM_BNE,
} from './constants.js'


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


export class CommitInstruction extends Transaction {

    static ACTOR = PAUL

    static taproot(params) {
        return [
            [CommitInstructionAddLeaf, params.vicky, params.paul],
            [CommitInstructionSubLeaf, params.vicky, params.paul],
            [CommitInstructionBEQLeaf, params.vicky, params.paul],
            [CommitInstructionBNELeaf, params.vicky, params.paul],
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




// For each instruction in the program we create an instruction leaf
class InstructionLeaf extends Leaf {

    // TODO: add a leaf for unary instructions. Vicky doesn't necessarily know all values
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
    static ACTOR = VICKY

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
        return [[ class extends Leaf {
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
        return [
            [ChallengeInstructionTimeoutLeaf, params.vicky, params.paul]
        ]
    }
}

export class EquivocatedPcNext extends EndTransaction {
    static ACTOR = PAUL

    static taproot(params) {
        console.warn(`${this.name} not implemented`)
        return [[ class extends Leaf {
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
        return [[ class extends Leaf {
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
        return [[ class extends Leaf {
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
