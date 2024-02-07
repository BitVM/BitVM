import { ASM_ADD, ASM_BNE } from '../bitvm/constants.js'


// The program: Count up to some given number
export const program = [
    [ASM_ADD, 1, 0, 0], // Increment value at address 0 by value at address 1
    [ASM_BNE, 2, 0, 0], // If value at address 0 and value at address 2 are not equal, jump 1 line backwards
]


// The input data
export const data = [
    0,      // The initial value is 0
    1,      // The step size is 1
    10,     // We count up to 10
    2,      // An extra value that Paul can use to try and execute some other code
]
