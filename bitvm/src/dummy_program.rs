use bitvm::{constants::*, vm::Instruction};

pub const DUMMY_PROGRAM: [Instruction; 2] = [
    Instruction {
        asm_type: ASM_ADD,
        address_a: 1,
        address_b: 0,
        address_c: 0,
    }, // Increment value at address 0 by value at address 1
    Instruction {
        asm_type: ASM_BNE,
        address_a: 2,
        address_b: 0,
        address_c: 0,
    }, // If value at address 0 and value at address 2 are not equal, jump 1 line backwards
];

// The input data
pub const DUMMY_DATA: [u32; 3] = [
    0,  // The initial value is 0
    1,  // The step size is 1
    10, // We count up to 10
];