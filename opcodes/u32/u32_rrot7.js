import '../std/opcodes.js'

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