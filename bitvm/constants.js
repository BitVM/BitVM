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


// VM instruction set (emulating rv32i)
export const ASM_ADD	 = 1
export const ASM_SUB	 = 2
export const ASM_MUL	 = 3
export const ASM_AND	 = 4
export const ASM_OR 	 = 5
export const ASM_XOR	 = 6
export const ASM_ADDI	 = 7
export const ASM_SUBI	 = 8
export const ASM_ANDI	 = 9
export const ASM_ORI	 = 10
export const ASM_XORI	 = 11
export const ASM_JMP	 = 12
export const ASM_BEQ	 = 13
export const ASM_BNE	 = 14
export const ASM_RSHIFT1 = 15
export const ASM_SLTU	 = 16
export const ASM_SLT	 = 17
export const ASM_SYSCALL = 18
export const ASM_LOAD	 = 19
export const ASM_STORE	 = 20
export const ASM_RSHIFT8 = 21


export const U32_SIZE = 2 ** 32
