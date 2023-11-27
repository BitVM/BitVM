import {u32_copy_zip} from './u32_zip.js'

const u8_xor = i => [
    // f_A = f(A)
    OP_DUP,
    i,
    OP_ADD,
    OP_PICK,

    // A_even = f_A << 1
    OP_DUP,
    OP_DUP,
    OP_ADD,

    // A_odd = A - A_even
    OP_ROT,
    OP_SWAP,
    OP_SUB,

    // f_B = f(B)
    OP_ROT,
    OP_DUP,
    i + 1,
    OP_ADD,
    OP_PICK,

    // B_even = f_B << 1
    OP_DUP,
    OP_DUP,
    OP_ADD,

    // B_odd = B - B_even
    OP_ROT,
    OP_SWAP,
    OP_SUB,

    // A_andxor_B_even = f_A + f_B
    OP_SWAP,
    3,
    OP_ROLL,
    OP_ADD,

    // A_xor_B_even = A_andxor_B_even - (f(A_andxor_B_even) << 1)
    OP_DUP,
    i + 1,
    OP_ADD,
    OP_PICK,
    OP_DUP,
    OP_ADD,
    OP_SUB,

    // A_andxor_B_odd = A_odd + B_odd
    OP_SWAP,
    OP_ROT,
    OP_ADD,

    // A_xor_B_odd = A_andxor_B_odd - (f(A_andxor_B_odd) << 1)
    OP_DUP,
    i,
    OP_ADD,
    OP_PICK,
    OP_DUP,
    OP_ADD,
    OP_SUB,

    // A_xor_B = A_xor_B_odd + (A_xor_B_even << 1)
    OP_SWAP,
    OP_DUP,
    OP_ADD,
    OP_ADD,
]

export const u32_xor = (a, b, stackSize) => {
    if (a == b) throw "a == b"
    const zipped = u32_copy_zip(a,b)
    a = (a + 1) * 4 - 1
    b = (b + 1) * 4 - 1
    return [
        zipped,

        // 
        // XOR
        // 

        u8_xor(8 + (stackSize - 2) * 4),

        OP_TOALTSTACK,

        u8_xor(6 + (stackSize - 2) * 4),

        OP_TOALTSTACK,

        u8_xor(4 + (stackSize - 2) * 4),

        OP_TOALTSTACK,

        u8_xor(2 + (stackSize - 2) * 4),


        OP_FROMALTSTACK,
        OP_FROMALTSTACK,
        OP_FROMALTSTACK,
    ]
}


//
// Push XOR Table
//
export const u32_push_xor_table = [
    85,
    OP_DUP,
    84,
    OP_DUP,
    OP_2OVER,
    OP_2OVER,
    81,
    OP_DUP,
    80,
    OP_DUP,
    OP_2OVER,
    OP_2OVER,

    85,
    OP_DUP,
    84,
    OP_DUP,
    OP_2OVER,
    OP_2OVER,
    81,
    OP_DUP,
    80,
    OP_DUP,
    OP_2OVER,
    OP_2OVER,

    69,
    OP_DUP,
    68,
    OP_DUP,
    OP_2OVER,
    OP_2OVER,
    65,
    OP_DUP,
    64,
    OP_DUP,
    OP_2OVER,
    OP_2OVER,

    69,
    OP_DUP,
    68,
    OP_DUP,
    OP_2OVER,
    OP_2OVER,
    65,
    OP_DUP,
    64,
    OP_DUP,
    OP_2OVER,
    OP_2OVER,

    85,
    OP_DUP,
    84,
    OP_DUP,
    OP_2OVER,
    OP_2OVER,
    81,
    OP_DUP,
    80,
    OP_DUP,
    OP_2OVER,
    OP_2OVER,

    85,
    OP_DUP,
    84,
    OP_DUP,
    OP_2OVER,
    OP_2OVER,
    81,
    OP_DUP,
    80,
    OP_DUP,
    OP_2OVER,
    OP_2OVER,

    69,
    OP_DUP,
    68,
    OP_DUP,
    OP_2OVER,
    OP_2OVER,
    65,
    OP_DUP,
    64,
    OP_DUP,
    OP_2OVER,
    OP_2OVER,

    69,
    OP_DUP,
    68,
    OP_DUP,
    OP_2OVER,
    OP_2OVER,
    65,
    OP_DUP,
    64,
    OP_DUP,
    OP_2OVER,
    OP_2OVER,

    21,
    OP_DUP,
    20,
    OP_DUP,
    OP_2OVER,
    OP_2OVER,
    17,
    OP_DUP,
    16,
    OP_DUP,
    OP_2OVER,
    OP_2OVER,

    21,
    OP_DUP,
    20,
    OP_DUP,
    OP_2OVER,
    OP_2OVER,
    17,
    OP_DUP,
    16,
    OP_DUP,
    OP_2OVER,
    OP_2OVER,

    5,
    OP_DUP,
    4,
    OP_DUP,
    OP_2OVER,
    OP_2OVER,
    1,
    OP_DUP,
    0,
    OP_DUP,
    OP_2OVER,
    OP_2OVER,

    5,
    OP_DUP,
    4,
    OP_DUP,
    OP_2OVER,
    OP_2OVER,
    1,
    OP_DUP,
    0,
    OP_DUP,
    OP_2OVER,
    OP_2OVER,

    21,
    OP_DUP,
    20,
    OP_DUP,
    OP_2OVER,
    OP_2OVER,
    17,
    OP_DUP,
    16,
    OP_DUP,
    OP_2OVER,
    OP_2OVER,

    21,
    OP_DUP,
    20,
    OP_DUP,
    OP_2OVER,
    OP_2OVER,
    17,
    OP_DUP,
    16,
    OP_DUP,
    OP_2OVER,
    OP_2OVER,

    5,
    OP_DUP,
    4,
    OP_DUP,
    OP_2OVER,
    OP_2OVER,
    1,
    OP_DUP,
    0,
    OP_DUP,
    OP_2OVER,
    OP_2OVER,

    5,
    OP_DUP,
    4,
    OP_DUP,
    OP_2OVER,
    OP_2OVER,
    1,
    OP_DUP,
    0,
    OP_DUP,
    OP_2OVER,
    OP_2OVER,
]

//
// Drop XOR Table
//
export const u32_drop_xor_table = loop(128, _ => OP_2DROP)
