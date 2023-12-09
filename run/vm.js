import '../libs/blake3.js'
import { blake3 } from '../libs/blake3.js'
import { toHex, concat } from '../libs/bytes.js'
import { buildTree, buildPath } from '../libs/merkle.js'
import { ASM_ADD, ASM_SUB, ASM_MUL, ASM_JMP, ASM_BEQ, ASM_BNE } from '../transactions/bitvm.js'
import { TRACE_LEN } from '../transactions/bitvm.js'

// A program is a list of instructions
class Instruction {
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

class Snapshot {
    pc
    memory
    stepCount = 0

    constructor(memory, pc = 0) {
        this.memory = memory
        this.pc = pc
    }

    read(addr) {
        if(addr < 0) throw `ERROR: address=${addr} is negative`
        if(addr >= this.memory.length) throw `ERROR: address=${addr} >= memory.length=${this.memory.length}`
        return this.memory[addr]
    }

    write(addr, value) {
        if(addr < 0) throw `ERROR: address=${addr} is negative`
        if(addr >= this.memory.length) throw `ERROR: address=${addr} >= memory.length=${this.memory.length}`
        this.memory[addr] = value
    }

    path(addr) {
        if(addr < 0) throw `ERROR: address=${addr} is negative`
        if(addr >= this.memory.length) throw `ERROR: address=${addr} >= memory.length=${this.memory.length}`
        return [buildPath(this.memory.map(x => new Uint32Array([x]).buffer), addr), new Uint32Array([memory.pc]).buffer]
    }

    verify(path, pc, value, address) {
        const root = verifyPath(path, new Uint32Array([value]).buffer, address)
        return blake3(concat(root, pc)).slice(0, 20).buffer
    }

    get root() {
        const root = buildTree(this.memory.map(x => new Uint32Array([x]).buffer))
        return blake3(concat(root, new Uint32Array([memory.pc]).buffer)).slice(0, 20).buffer
    }
}

const executeInstruction = (snapshot) => {
    // traceExecution
    console.log(`PC: ${snapshot.pc},  Instruction: ${(snapshot.instruction+'').padEnd(9,' ')} Memory: [${snapshot.memory}]`)

    switch (snapshot.instruction.type) {
        case ASM_ADD:
            snapshot.write(
                snapshot.instruction.addressA,
                snapshot.read(snapshot.instruction.addressA) + snapshot.read(snapshot.instruction.addressB)
            )
            snapshot.pc += 1
            break
        case ASM_SUB:
            snapshot.write(
                snapshot.instruction.addressA,
                snapshot.read(snapshot.instruction.addressA) - snapshot.read(snapshot.instruction.addressB)
            )
            snapshot.pc += 1
            break
        case ASM_MUL:
            snapshot.write(
                snapshot.instruction.addressA,
                snapshot.read(snapshot.instruction.addressA) * snapshot.read(snapshot.instruction.addressB)
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
        default:
            snapshot.pc += 1
            break
    }
}

export class VM {
    program
    memory_entries

    constructor(program_source, memory_entries) {
        this.program = program_source.map(source => new Instruction(...source))
        this.memory_entries = memory_entries
    }

    run(maxSteps = TRACE_LEN) {
        const snapshot = new Snapshot([...this.memory_entries], 0)
        while (snapshot.pc >= 0 && snapshot.pc < this.program.length && snapshot.stepCount < maxSteps) {
            snapshot.instruction = this.program[snapshot.pc]
            executeInstruction(snapshot)
            snapshot.stepCount++
        }
        return snapshot
    }

}
