pub enum Role {
    Paul,
    Vicky,
}

// The prover role
pub const PAUL: Role = Role::Paul;
// The verifier role
pub const VICKY: Role = Role::Vicky;

// Number of blocks for a player to respond until the other player wins
pub const TIMEOUT: usize = 1;

// Logarithm of the VM's max trace length
pub const LOG_TRACE_LEN: usize = 32;
// Max trace length
pub const TRACE_LEN: usize = 1 << LOG_TRACE_LEN;

// Logarithm of the length of a Merkle path
pub const LOG_PATH_LEN: usize = 5;
// Length of a Merkle path
pub const PATH_LEN: usize = 1 << LOG_PATH_LEN;
// Number of memory cells
pub const MEMORY_LEN: usize = 1 << PATH_LEN;

// VM instruction set (emulating rv32i)
pub const ASM_ADD: u8 = 1;
pub const ASM_SUB: u8 = 2;
pub const ASM_MUL: u8 = 3;
pub const ASM_AND: u8 = 4;
pub const ASM_OR: u8 = 5;
pub const ASM_XOR: u8 = 6;
pub const ASM_ADDI: u8 = 7;
pub const ASM_SUBI: u8 = 8;
pub const ASM_ANDI: u8 = 9;
pub const ASM_ORI: u8 = 10;
pub const ASM_XORI: u8 = 11;
pub const ASM_JMP: u8 = 12;
pub const ASM_BEQ: u8 = 13;
pub const ASM_BNE: u8 = 14;
pub const ASM_RSHIFT1: u8 = 15;
pub const ASM_SLTU: u8 = 16;
pub const ASM_SLT: u8 = 17;
pub const ASM_SYSCALL: u8 = 18;
pub const ASM_LOAD: u8 = 19;
pub const ASM_STORE: u8 = 20;

pub const U32_SIZE: usize = 1 << 32;
