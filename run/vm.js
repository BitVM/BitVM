import '../libs/blake3.js'
import { blake3 } from '../libs/blake3.js'
import { toHex, concat } from '../libs/bytes.js'
import { buildTree } from '../libs/merkle.js'
import { ASM_ADD, ASM_SUB, ASM_MUL, ASM_JMP, ASM_BEQ, ASM_BNE } from '../transactions/bitvm.js'
import { TRACE_LEN } from '../transactions/bitvm.js'

const traceExecution = (PC, instruction, memory) => {
    const root = blake3(concat(buildTree(memory.mem.map(x => new Uint32Array([x]).buffer)), new Uint32Array([memory.pc]).buffer))
    console.log(`PC: ${PC},  Instruction: ${(instruction+'').padEnd(9,' ')} Memory: [${memory.mem}]  State Root: ${toHex(root)}`)
    return root
}

const executeInstruction = (memory, instruction) => {
    const root = traceExecution(memory.pc, instruction, memory)

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
    return [memory, root] 
}

class Memory {
    pc
    mem

    constructor(mem, pc = 0) {
        this.mem = mem
        this.pc = pc
    }
}

class Trace {
    #roots

    constructor(roots){
        this.#roots = roots
    }

    getRoot(index){
        // if(index >= this.#roots.length)
        //     return '0000000000000000000000000000000000000000'
        index = Math.min(index, this.#roots.length - 1)
        return toHex(this.#roots[index])
    }

}

export const runVM = (program, data, maxSteps=TRACE_LEN) => {
    let memory = new Memory([...data], 0)
    let root
    let trace = []
    let stepCount = 0
    while (memory.pc >= 0 && memory.pc < program.length && stepCount < maxSteps) {
        const currentInstruction = program[memory.pc];
        [memory, root] = executeInstruction(memory, currentInstruction)
        trace.push(root)
        stepCount++
    }
    return new Trace(trace)
}

export const readFromMemory = (address) => {
    // TODO: return value + merkle proof here
    throw 'Not implemented!'
}
