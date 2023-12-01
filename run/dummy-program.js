import { ASM_ADD, ASM_SUB, ASM_MUL, ASM_JMP, ASM_BEQ, ASM_BNE, compileProgram } from '../transactions/bitvm.js'


// Count up to some given number
export const program = [
    [ASM_ADD, 0, 1, 0], // Increment value at address 0 by value at address 1
    [ASM_BNE, 0, 2, -1], // If value at address 0 and value at address 2 are not equal, jump 1 line backwards
]

// Export the compiled program too
export const compiledProgram = compileProgram(program)


// The input data
export const data = [
    0,      // initial value
    1,      // The step size is 1
    10,     // We count up to 10
    0, 
    0
]


