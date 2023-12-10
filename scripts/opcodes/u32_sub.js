import './std.js'
import { u32_zip, u32_copy_zip } from './u32_zip.js'

const u8_sub_carrier = [
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
]

const u8_sub = [
    OP_SUB,
    OP_DUP,
    0,
    OP_LESSTHAN,
    OP_IF,
        256,
        OP_ADD,
    OP_ENDIF,
]

// 
// Subtraction of two u32 values represented as u8
// Copies the first summand `a` and drops `b`
//  
export const u32_sub = (a, b) => {
    if (a == b) 
        throw 'a == b'
    
    return [
        u32_copy_zip(a, b),

        // A0 - B0
        u8_sub_carrier,
        OP_SWAP,
        OP_TOALTSTACK,

        // A1 - (B1 + carry_0)
        OP_ADD,
        u8_sub_carrier,
        OP_SWAP,
        OP_TOALTSTACK,

        // A2 - (B2 + carry_1)
        OP_ADD,
        u8_sub_carrier,
        OP_SWAP,
        OP_TOALTSTACK,

        // A3 - (B3 + carry_2)
        OP_ADD,
        u8_sub,

        OP_FROMALTSTACK,
        OP_FROMALTSTACK,
        OP_FROMALTSTACK,

        // Now there's the result C_3 C_2 C_1 C_0 on the stack
    ]
}


// 
// Subtraction of two u32 values represented as u8
// Drops boths summands `a` and `b`
//  
export const u32_sub_drop = (a, b) => {
    if (a == b) 
        throw 'a == b'

    return [
        u32_zip(a, b),

        // A0 - B0
        u8_sub_carrier,
        OP_SWAP,
        OP_TOALTSTACK,

        // A1 - (B1 + carry_0)
        OP_ADD,
        u8_sub_carrier,
        OP_SWAP,
        OP_TOALTSTACK,

        // A2 - (B2 + carry_1)
        OP_ADD,
        u8_sub_carrier,
        OP_SWAP,
        OP_TOALTSTACK,

        // A3 - (B3 + carry_2)
        OP_ADD,
        u8_sub,

        OP_FROMALTSTACK,
        OP_FROMALTSTACK,
        OP_FROMALTSTACK,

        // Now there's the result C_3 C_2 C_1 C_0 on the stack
    ]
}