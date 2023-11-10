import '../std/opcodes.js'

const u8_rrot12 = [
    0,
    OP_TOALTSTACK,

    OP_DUP,
    127,
    OP_GREATERTHAN,
    OP_IF,
        128,
        OP_SUB,
        OP_FROMALTSTACK,
        8,
        OP_ADD,
        OP_TOALTSTACK,
    OP_ENDIF,

    OP_DUP,
    OP_ADD,

    OP_DUP,
    127,
    OP_GREATERTHAN,
    OP_IF,
        128,
        OP_SUB,
        OP_FROMALTSTACK,
        4,
        OP_ADD,
        OP_TOALTSTACK,
    OP_ENDIF,

    OP_DUP,
    OP_ADD,

    OP_DUP,
    127,
    OP_GREATERTHAN,
    OP_IF,
        128,
        OP_SUB,
        OP_FROMALTSTACK,
        2,
        OP_ADD,
        OP_TOALTSTACK,
    OP_ENDIF,

    OP_DUP,
    OP_ADD,

    OP_DUP,
    127,
    OP_GREATERTHAN,
    OP_IF,
        128,
        OP_SUB,
        OP_FROMALTSTACK,
        OP_1ADD,
        OP_TOALTSTACK,
    OP_ENDIF,

    OP_DUP,
    OP_ADD,

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