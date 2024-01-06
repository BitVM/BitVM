// The prover role
export const PAUL = 'paul'
// The verifier role
export const VICKY = 'vicky'

// Number of blocks for a player to respond until the other player wins
export const TIMEOUT = 1


// Logarithm of the VM's max trace length
export const LOG_TRACE_LEN = 4 // TODO: this should be 32
// Max trace length
export const TRACE_LEN = 2 ** LOG_TRACE_LEN


// Logarithm of the length of a Merkle path
export const LOG_PATH_LEN = 5
// Length of a Merkle path
export const PATH_LEN = 2 ** LOG_PATH_LEN
// Number of memory cells
export const MEMORY_LEN = 2 ** PATH_LEN


// VM instruction set
export const ASM_ADD  = 0
export const ASM_SUB  = 1
export const ASM_MUL  = 2
export const ASM_AND  = 3
export const ASM_OR   = 4
export const ASM_XOR  = 5
export const ASM_ADDI = 6
export const ASM_SUBI = 7
export const ASM_ANDI = 8
export const ASM_ORI  = 9
export const ASM_XORI = 10
export const ASM_JMP  = 11
export const ASM_BEQ  = 12
export const ASM_BNE  = 13

export const U32_SIZE = 2 ** 32
