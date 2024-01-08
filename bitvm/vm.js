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
        if (address >= memory.length)
            throw `ERROR: address=${address} >= memory.length=${memory.length}`
        // TODO: new Uint32Array([this.pc]).buffer
        this.#snapshot = snapshot
        this.#address = address
        this.#path = buildPath(memory.map(value => new Uint32Array([value]).buffer), address)
    }

    verifyUpTo(height) {
        height = PATH_LEN - height
        const subPath = this.#path.slice(0, height)
        const value = this.#snapshot.read(this.#address)
        const node = verifyPath(subPath, value, this.#address)
        return toHex(node)
    }

    getNode(height) {
        height = PATH_LEN - height
        return toHex(this.#path[height])
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
        if (address >= this.memory.length)
            throw `ERROR: address=${address} >= memory.length=${this.memory.length}`
        return this.memory[address]
    }

    write(address, value) {
        if (address < 0)
            throw `ERROR: address=${address} is negative`
        if (address >= MEMORY_LEN)
            throw `ERROR: address=${address} >= memory.length=${MEMORY_LEN}`
        this.memory[address] = value
    }
    
    readByte(address, byteOffset){
        if (byteOffset < 0)
            throw `ERROR: byteOffset=${byteOffset} is negative`
        if (byteOffset >= Math.log2(U32_SIZE) / 8)
            throw `ERROR: byteOffset=${byteOffset} is too large. Should be below ${Math.log2(U32_SIZE) / 8}.`
        return (this.read(address) & 0xFF << (byteOffset * 8)) >>> (byteOffset * 8)
    }

    path(address) {
        return new MerklePath(this, address)
    }

    verify(path, value, address) {
        const root = verifyPath(path.map(x => fromHex(x).buffer), new Uint32Array([value]).buffer, address)
        // TODO: blake3(concat(root, pc)).slice(0, 20).buffer
        return toHex(root)
    }

    get root() {
        const root = buildTree(this.memory.map(x => new Uint32Array([x]).buffer))
        // TODO: toHex(blake3(concat(root, new Uint32Array([this.pc]).buffer)).slice(0, 20).buffer)
        return toHex(root)
    }
}

const executeInstruction = (snapshot) => {

    // console.log(`PC: ${snapshot.pc},  Instruction: ${(snapshot.instruction+'').padEnd(9,' ')} Memory: [${snapshot.memory}]`)
    switch (snapshot.instruction.type) {
        case ASM_ADD:
            snapshot.write(
                snapshot.instruction.addressC,
                toU32(snapshot.read(snapshot.instruction.addressA) + snapshot.read(snapshot.instruction.addressB))
            )
            snapshot.pc += 1
            break
        case ASM_SUB:
            snapshot.write(
                snapshot.instruction.addressC,
                toU32(snapshot.read(snapshot.instruction.addressA) - snapshot.read(snapshot.instruction.addressB))
            )
            snapshot.pc += 1
            break
        case ASM_MUL:
            snapshot.write(
                snapshot.instruction.addressC,
                toU32(snapshot.read(snapshot.instruction.addressA) * snapshot.read(snapshot.instruction.addressB))
            )
            snapshot.pc += 1
            break
        case ASM_AND:
            snapshot.write(
                snapshot.instruction.addressC,
                snapshot.read(snapshot.instruction.addressA) & snapshot.read(snapshot.instruction.addressB)
            )
            snapshot.pc += 1
            break
        case ASM_OR:
            snapshot.write(
                snapshot.instruction.addressC,
                snapshot.read(snapshot.instruction.addressA) | snapshot.read(snapshot.instruction.addressB)
            )
            snapshot.pc += 1
            break
        case ASM_XOR:
            snapshot.write(
                snapshot.instruction.addressC,
                snapshot.read(snapshot.instruction.addressA) ^ snapshot.read(snapshot.instruction.addressB)
            )
            snapshot.pc += 1
            break
        case ASM_ADDI:
            snapshot.write(
                snapshot.instruction.addressC,
                toU32(snapshot.read(snapshot.instruction.addressA) + snapshot.instruction.addressB)
            )
            snapshot.pc += 1
            break
        case ASM_SUBI:
            snapshot.write(
                snapshot.instruction.addressC,
                toU32(snapshot.read(snapshot.instruction.addressA) - snapshot.instruction.addressB)
            )
            snapshot.pc += 1
            break
        case ASM_ANDI:
            snapshot.write(
                snapshot.instruction.addressC,
                toU32(snapshot.read(snapshot.instruction.addressA) & snapshot.instruction.addressB)
            )
            snapshot.pc += 1
            break
        case ASM_ORI:
            snapshot.write(
                snapshot.instruction.addressC,
                snapshot.read(snapshot.instruction.addressA) | snapshot.instruction.addressB
            )
            snapshot.pc += 1
            break
        case ASM_XORI:
            snapshot.write(
                snapshot.instruction.addressC,
                snapshot.read(snapshot.instruction.addressA) ^ snapshot.instruction.addressB
            )
            snapshot.pc += 1
            break
        case ASM_BEQ:
            if (snapshot.read(snapshot.instruction.addressA) == snapshot.read(snapshot.instruction.addressB)) {
                snapshot.pc = snapshot.instruction.addressC
            } else {
                snapshot.pc += 1
            }
            break
        case ASM_BNE:
            if (snapshot.read(snapshot.instruction.addressA) != snapshot.read(snapshot.instruction.addressB)) {
                snapshot.pc = snapshot.instruction.addressC
            } else {
                snapshot.pc += 1
            }
            break
        case ASM_JMP:
            snapshot.pc = snapshot.read(snapshot.instruction.addressA)
            break
        case ASM_RSHIFT1:
            snapshot.write(
                snapshot.instruction.addressC,
                toU32(snapshot.read(snapshot.instruction.addressA) >>> 1)
            )
            snapshot.pc += 1
            break
        case ASM_SLTU:
            snapshot.write(snapshot.instruction.addressC, snapshot.read(snapshot.instruction.addressA) >>> 0 < snapshot.read(snapshot.instruction.addressB) >>> 0 ? 1 : 0);
            snapshot.pc += 1
            break            
        case ASM_SLT:
            // Binary OR with each value to cast them to 32-bit integer and then back to a sign-extended number.
            snapshot.write(snapshot.instruction.addressC, (snapshot.read(snapshot.instruction.addressA) | 0 ) < ( snapshot.read(snapshot.instruction.addressB) | 0 ) ? 1 : 0);
            snapshot.pc += 1
            break
        case ASM_LOAD:
            const byte = snapshot.readByte(snapshot.read(snapshot.instruction.addressA), snapshot.read(snapshot.instruction.addressB))
            snapshot.write(snapshot.instruction.addressC, byte); 
            snapshot.pc += 1
            break;
        case ASM_SYSCALL:
            console.log("syscall called")
            snapshot.pc += 1
            break
        default:
            snapshot.pc += 1
            break

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
        while (snapshot.pc < this.program.length && snapshot.stepCount < maxSteps - 1) {
            snapshot.instruction = this.program[snapshot.pc]
            executeInstruction(snapshot)
            snapshot.stepCount++
        }
        return snapshot
    }

}



