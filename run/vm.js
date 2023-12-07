import '../libs/blake3.js'
import { toHex } from '../libs/bytes.js'
import { buildTree } from '../libs/merkle.js'
import { ASM_ADD, ASM_SUB, ASM_MUL, ASM_JMP, ASM_BEQ, ASM_BNE } from '../transactions/bitvm.js'
import { TRACE_LEN } from '../transactions/bitvm.js'

const traceExecution = (PC, instruction, memory) => {
    const root = buildTree(memory.map(x => new Uint32Array([x]).buffer))
    console.log(`PC: ${PC},  Instruction: ${(instruction+'').padEnd(9,' ')} Memory: [${memory}]  State Root: ${toHex(root)}`)
    return root
}

const executeInstruction = (memory, instruction) => {
    const PC = memory[memory.length - 1]
    const root = traceExecution(PC, instruction, memory)

    switch (instruction[0]) {
        case ASM_ADD:
            memory[instruction[1]] = memory[instruction[1]] + memory[instruction[2]]
            memory[memory.length - 1] += 1
            break
        case ASM_SUB:
            memory[instruction[1]] = memory[instruction[1]] - memory[instruction[2]]
            memory[memory.length - 1] += 1
            break
        case ASM_MUL:
            memory[instruction[1]] = memory[instruction[1]] * memory[instruction[2]]
            memory[memory.length - 1] += 1
            break
        case ASM_BEQ:
            if (memory[instruction[1]] == memory[instruction[2]]) {
                memory[memory.length - 1] = instruction[3]
            } else {
                memory[memory.length - 1] += 1
            }
            break
        case ASM_BNE:
            if (memory[instruction[1]] != memory[instruction[2]]) {
                memory[memory.length - 1] = instruction[3]
            } else {
                memory[memory.length - 1] += 1
            }
            break
        case ASM_JMP:
            memory[memory.length - 1] = memory[instruction[1]]
            break
        default:
            memory[memory.length - 1] += 1
            break
    }
    return [memory, root] 
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
    let memory = [...data]
    let root
    let trace = []
    let stepCount = 0
    while (memory[memory.length - 1] >= 0 && memory[memory.length - 1] < program.length && stepCount < maxSteps) {
        const currentInstruction = program[memory[memory.length - 1]];
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
