import '../std/opcodes.js'
// 
// Subtraction of two u32 values represented as u8
//  
export const u32_sub = [
    // A0 - B0
    OP_SUB,
    OP_DUP,
    0,
    OP_LESSTHAN,
    OP_IF,
        256,
        OP_ADD,
        1,
    OP_ELSE,
        0,
    OP_ENDIF,
    OP_SWAP,
    OP_TOALTSTACK,

    // A1 - (B1 + carry_0)
    OP_ADD,
    OP_SUB,
    OP_DUP,
    0,
    OP_LESSTHAN,
    OP_IF,
        256,
        OP_ADD,
        1,
    OP_ELSE,
        0,
    OP_ENDIF,
    OP_SWAP,
    OP_TOALTSTACK,

    // A2 - (B2 + carry_1)
    OP_ADD,
    OP_SUB,
    OP_DUP,
    0,
    OP_LESSTHAN,
    OP_IF,
        256,
        OP_ADD,
        1,
    OP_ELSE,
        0,
    OP_ENDIF,
    OP_SWAP,
    OP_TOALTSTACK,

    // A3 - (B3 + carry_2)
    OP_ADD,
    OP_SUB,
    OP_DUP,
    0,
    OP_LESSTHAN,
    OP_IF,
        256,
        OP_ADD,
    OP_ENDIF,


    OP_FROMALTSTACK,
    OP_FROMALTSTACK,
    OP_FROMALTSTACK,

    // Now there's the result C_3 C_2 C_1 C_0 on the stack
]