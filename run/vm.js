import '../libs/blake3.js'
import { blake3 } from '../libs/blake3.js'
import { toHex, concat } from '../libs/bytes.js'
import { buildTree, buildPath } from '../libs/merkle.js'
import { ASM_ADD, ASM_SUB, ASM_MUL, ASM_JMP, ASM_BEQ, ASM_BNE } from '../transactions/bitvm.js'
import { TRACE_LEN } from '../transactions/bitvm.js'

class Memory {
    pc
    mem
    stepCount = 0

    constructor(mem, pc = 0) {
        this.mem = mem
        this.pc = pc
    }

    read(addr) {
        if(addr < 0) throw `ERROR: address=${addr} is negative`
        if(addr >= this.mem.length) throw `ERROR: address=${addr} >= memory.length=${this.mem.length}`
        return this.mem[addr]
    }

    path(addr) {
        if(addr < 0) throw `ERROR: address=${addr} is negative`
        if(addr >= this.mem.length) throw `ERROR: address=${addr} >= memory.length=${this.mem.length}`
        return [buildPath(this.mem.map(x => new Uint32Array([x]).buffer), addr), new Uint32Array([memory.pc]).buffer]
    }

    verify(path, pc, value, address) {
        const root = verifyPath(path, new Uint32Array([value]).buffer, address)
        return blake3(concat(root, pc)).slice(0, 20).buffer
    }

    get root() {
        const root = buildTree(this.mem.map(x => new Uint32Array([x]).buffer))
        return blake3(concat(root, new Uint32Array([memory.pc]).buffer)).slice(0, 20).buffer
    }
}

const executeInstruction = (memory, instruction) => {
    // traceExecution
    console.log(`PC: ${memory.pc},  Instruction: ${(instruction+'').padEnd(9,' ')} Memory: [${memory.mem}]`)

    switch (instruction[0]) {
        case ASM_ADD:
            memory.mem[instruction[1]] = memory.mem[instruction[1]] + memory.mem[instruction[2]]
            memory.pc += 1
            break
        case ASM_SUB:
            memory.mem[instruction[1]] = memory.mem[instruction[1]] - memory.mem[instruction[2]]
            memory.pc += 1
            break
        case ASM_MUL:
            memory.mem[instruction[1]] = memory.mem[instruction[1]] * memory.mem[instruction[2]]
            memory.pc += 1
            break
        case ASM_BEQ:
            if (memory.mem[instruction[1]] == memory.mem[instruction[2]]) {
                memory.pc = instruction[3]
            } else {
                memory.pc += 1
            }
            break
        case ASM_BNE:
            if (memory.mem[instruction[1]] != memory.mem[instruction[2]]) {
                memory.pc = instruction[3]
            } else {
                memory.pc += 1
            }
            break
        case ASM_JMP:
            memory.pc = memory.mem[instruction[1]]
            break
        default:
            memory.pc += 1
            break
    }
}

export const runVM = (program, memory_entries, maxSteps=TRACE_LEN) => {
    let memory = new Memory([...memory_entries], 0)
    while (memory.pc >= 0 && memory.pc < program.length && memory.stepCount < maxSteps) {
        const currentInstruction = program[memory.pc];
        executeInstruction(memory, currentInstruction)
        memory.stepCount++
    }
    return memory
}
