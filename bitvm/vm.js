import { blake3 } from '../libs/blake3.js'
import { toHex, fromHex, concat } from '../libs/bytes.js'
import { buildTree, buildPath, verifyPath } from '../libs/merkle.js'
import {
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
    ASM_SLTU,
    ASM_SLT,
    ASM_LOAD,
    ASM_STORE,
    ASM_SYSCALL,
    PATH_LEN,
    TRACE_LEN,
    MEMORY_LEN,
    U32_SIZE
} from './constants.js'


// Map positive and negative n to an unsigned u32
export const toU32 = n => (U32_SIZE + (n % U32_SIZE)) % U32_SIZE

// A program is a list of instructions
export class Instruction {

    constructor(type, addressA, addressB, addressC) {
        this.type = type
        this.addressA = addressA
        this.addressB = addressB
        this.addressC = addressC
    }

    toString() {
        return `${this.type} ${this.addressA} ${this.addressB} ${this.addressC}`
    }
}

export const compileProgram = source => source.map(instruction => new Instruction(...instruction))


class MerklePath {
    #path
    #snapshot
    #address

    constructor(snapshot, address) {
        const memory = snapshot.memory
        if (address < 0)
            throw `ERROR: address=${address} is negative`
        if (address >= MEMORY_LEN)
            throw `ERROR: address=${address} >= MEMORY_LEN=${MEMORY_LEN}`
        this.#snapshot = snapshot
        this.#address = address
        this.#path = buildPath(memory.map(value => new Uint32Array([value]).buffer), address)
    }

    verifyUpTo(height) {
        height = PATH_LEN - height
        const subPath = this.#path.slice(0, height)
        const value = new Uint32Array([this.#snapshot.read(this.#address)]).buffer
        const node = verifyPath(subPath, value, this.#address)
        return toHex(node)
    }

    getNode(index) {
        index = PATH_LEN - 1 - index
        return toHex(this.#path[index])
    }
}


class Snapshot {
    pc
    memory
    stepCount = 0
    instruction

    constructor(memory, instruction, pc = 0) {
        this.memory = memory
        this.instruction = instruction
        this.pc = pc
    }

    read(address) {
        if (address < 0)
            throw `ERROR: address=${address} is negative`
        if (address >= MEMORY_LEN)
            throw `ERROR: address=${address} >= MEMORY_LEN=${MEMORY_LEN}`
        if (address >= this.memory.length)
            return 0
        return this.memory[address]
    }

    write(address, value) {
        if (address < 0)
            throw `ERROR: address=${address} is negative`
        if (address >= MEMORY_LEN)
            throw `ERROR: address=${address} >= MEMORY_LEN=${MEMORY_LEN}`
        this.memory[address] = value
    }
    
    path(address) {
        return new MerklePath(this, address)
    }

    get root() {
        const root = buildTree(this.memory.map(x => new Uint32Array([x]).buffer))
        return toHex(root)
    }
}

const executeInstruction = (s) => {

    //console.log(`PC: ${s.pc},  Instruction: ${(s.instruction+'').padEnd(9,' ')}, valueA: ${s.read(s.instruction.addressA)}, valueB: ${s.read(s.instruction.addressB)}, valueC: ${s.read(s.instruction.addressC)}`)
    switch (s.instruction.type) {
        case ASM_ADD:
            s.write(
                s.instruction.addressC,
                toU32(s.read(s.instruction.addressA) + s.read(s.instruction.addressB))
            )
            s.pc += 1
            break
        case ASM_SUB:
            s.write(
                s.instruction.addressC,
                toU32(s.read(s.instruction.addressA) - s.read(s.instruction.addressB))
            )
            s.pc += 1
            break
        case ASM_MUL:
            s.write(
                s.instruction.addressC,
                toU32(s.read(s.instruction.addressA) * s.read(s.instruction.addressB))
            )
            s.pc += 1
            break
        case ASM_AND:
            s.write(
                s.instruction.addressC,
                toU32(s.read(s.instruction.addressA) & s.read(s.instruction.addressB))
            )
            s.pc += 1
            break
        case ASM_OR:
            s.write(
                s.instruction.addressC,
                toU32(s.read(s.instruction.addressA) | s.read(s.instruction.addressB))
            )
            s.pc += 1
            break
        case ASM_XOR:
            s.write(
                s.instruction.addressC,
                toU32(s.read(s.instruction.addressA) ^ s.read(s.instruction.addressB))
            )
            s.pc += 1
            break
        case ASM_ADDI:
            s.write(
                s.instruction.addressC,
                toU32(s.read(s.instruction.addressA) + s.instruction.addressB)
            )
            s.pc += 1
            break
        case ASM_SUBI:
            s.write(
                s.instruction.addressC,
                toU32(s.read(s.instruction.addressA) - s.instruction.addressB)
            )
            s.pc += 1
            break
        case ASM_ANDI:
            s.write(
                s.instruction.addressC,
                toU32(s.read(s.instruction.addressA) & s.instruction.addressB)
            )
            s.pc += 1
            break
        case ASM_ORI:
            s.write(
                s.instruction.addressC,
                toU32(s.read(s.instruction.addressA) | s.instruction.addressB)
            )
            s.pc += 1
            break
        case ASM_XORI:
            s.write(
                s.instruction.addressC,
                toU32(s.read(s.instruction.addressA) ^ s.instruction.addressB)
            )
            s.pc += 1
            break
        case ASM_BEQ:
            if (s.read(s.instruction.addressA) == s.read(s.instruction.addressB)) {
                s.pc = s.instruction.addressC
            } else {
                s.pc += 1
            }
            break
        case ASM_BNE:
            if (s.read(s.instruction.addressA) != s.read(s.instruction.addressB)) {
                s.pc = s.instruction.addressC
            } else {
                s.pc += 1
            }
            break
        case ASM_JMP:
            s.pc = s.read(s.instruction.addressA)
            break
        case ASM_RSHIFT1:
            s.write(
                s.instruction.addressC,
                toU32(s.read(s.instruction.addressA) >>> 1)
            )
            s.pc += 1
            break
        case ASM_SLTU:
            s.write(s.instruction.addressC, s.read(s.instruction.addressA) >>> 0 < s.read(s.instruction.addressB) >>> 0 ? 1 : 0);
            s.pc += 1
            break            
        case ASM_SLT:
            // Binary OR with each value to cast them to 32-bit integer and then back to a sign-extended number.
            s.write(s.instruction.addressC, (s.read(s.instruction.addressA) | 0 ) < ( s.read(s.instruction.addressB) | 0 ) ? 1 : 0);
            s.pc += 1
            break
        case ASM_LOAD:
            s.instruction.addressA = s.read(s.instruction.addressB)
            s.write(s.instruction.addressC, s.read(s.instruction.addressA))
            s.pc += 1
            break
        case ASM_STORE:
            s.instruction.addressC = s.read(s.instruction.addressB)
            s.write(s.instruction.addressC, s.read(s.instruction.addressA))
            s.pc += 1
            break;
        case ASM_SYSCALL:
            console.log("syscall called")
            s.pc += 1
            break
        default:
            throw `Unsupported instruction type ${s.instruction.type}`
            // s.pc += 1
            // break
    }
}

export class VM {
    program
    memoryEntries

    constructor(programSource, memoryEntries) {
        this.program = compileProgram(programSource)
        this.memoryEntries = memoryEntries
    }

    run(maxSteps = TRACE_LEN) {
        const snapshot = new Snapshot([...this.memoryEntries], this.program[0])
        while (snapshot.pc < this.program.length && snapshot.stepCount < maxSteps) {
            snapshot.instruction = this.program[snapshot.pc]
            executeInstruction(snapshot)
            snapshot.stepCount++
        }
        return snapshot
    }

}



