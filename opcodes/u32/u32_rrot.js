import '../std/opcodes.js'
import {loop} from '../std/std.js'

// Rotate by 16 bits to the right
export const u32_rrot16 = [OP_2SWAP]

export const u32_rrot8 = [
    3, OP_ROLL,
    3, OP_ROLL,
    3, OP_ROLL,
]

const u8_rrot12 = [
    0,
    OP_TOALTSTACK,

    loop(4, i => [
        OP_DUP,
        127,
        OP_GREATERTHAN,
        OP_IF,
            128,
            OP_SUB,
            OP_FROMALTSTACK,
            8 >>> i,
            OP_ADD,
            OP_TOALTSTACK,
        OP_ENDIF,

        OP_DUP,
        OP_ADD,
    ]),

    OP_FROMALTSTACK,
]

//
// Right Rotation by 12 bits
//
export const u32_rrot12 = [

                u8_rrot12,
       OP_ROT,  u8_rrot12,
    4, OP_ROLL, u8_rrot12,
    6, OP_ROLL, u8_rrot12,

    // 
    // Glue it all together
    //

    5, OP_ROLL,
    6, OP_ROLL,
       OP_ADD,
       OP_SWAP,

    6, OP_ROLL,
       OP_ADD,

       OP_ROT,
    3, OP_ROLL,
       OP_ADD,

    4, OP_ROLL,

    4, OP_ROLL,
       OP_ADD,
]


const u8_rrot7 = [
    OP_DUP,
    127,
    OP_GREATERTHAN,
    OP_IF,
        128,
        OP_SUB,
        1,
    OP_ELSE,
        0,
    OP_ENDIF,
]

//
// Right Rotation by 7 bits
//
export const u32_rrot7 = [

    // First Byte
    u8_rrot7,

    OP_ROT,

    // Second byte
    u8_rrot7,

    OP_SWAP,
    OP_DUP,
    OP_ADD,
    OP_ROT,
    OP_ADD,
    OP_SWAP,

    3, OP_ROLL,

    // Third byte
    u8_rrot7,

    OP_SWAP,
    OP_DUP,
    OP_ADD,
    OP_ROT,
    OP_ADD,
    OP_SWAP,

    4, OP_ROLL,

    // Fourth byte
    u8_rrot7,

    OP_SWAP,
    OP_DUP,
    OP_ADD,
    OP_ROT,
    OP_ADD,
    OP_SWAP,

    // Close the circle
    4, OP_ROLL,
       OP_DUP,
       OP_ADD,
       OP_ADD,

    OP_SWAP,
    OP_2SWAP,
    OP_SWAP,
]