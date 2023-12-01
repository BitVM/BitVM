import '../libs/blake3.js'
import { toHex } from '../libs/bytes.js'
import { buildTree } from '../libs/merkle.js'
import { ASM_ADD, ASM_SUB, ASM_MUL, ASM_JMP, ASM_BEQ, ASM_BNE } from '../transactions/bitvm.js'

const traceExecution = async (PC, instruction, memory) => {
    const root = await buildTree(memory.map(x => new Uint32Array([x]).buffer))
    console.log(`PC: ${PC},  Instruction: ${(instruction+'').padEnd(9,' ')} Memory: [${memory}]  State Root: ${toHex(root)}`)
    return root
}

const executeInstruction = async (memory, instruction) => {
    const PC = memory[memory.length - 1]
    const root = await traceExecution(PC, instruction, memory)

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
                memory[memory.length - 1] += instruction[3]
            } else {
                memory[memory.length - 1] += 1
            }
            break
        case ASM_BNE:
            if (memory[instruction[1]] != memory[instruction[2]]) {
                memory[memory.length - 1] += instruction[3]
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

export const runVM = async (program, data) => {
    let memory = [...data]
    let root
    while (memory[memory.length - 1] >= 0 && memory[memory.length - 1] < program.length) {
        const currentInstruction = program[memory[memory.length - 1]];
        [memory, root] = await executeInstruction(memory, currentInstruction)
    }
    return root
}