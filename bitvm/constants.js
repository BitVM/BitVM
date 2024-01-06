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
export const ASM_ADD = 42
export const ASM_SUB = 43
export const ASM_MUL = 44
export const ASM_AND = 45
export const ASM_OR = 46
export const ASM_XOR = 47
export const ASM_ADDI = 48
export const ASM_SUBI = 49
export const ASM_ANDI = 50
export const ASM_ORI= 51
export const ASM_XORI = 52
export const ASM_JMP = 53
export const ASM_BEQ = 54
export const ASM_BNE = 55

export const U32_SIZE = 2 ** 32
