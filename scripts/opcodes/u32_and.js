import { u32_copy_zip } from "./u32_zip.js"

const u8_and = i => [
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
    // A_and_B_even = f(A_andxor_B_even)
    i,
    OP_ADD,
    OP_PICK,

    // A_andxor_B_odd = A_odd + B_odd
    OP_SWAP,
    OP_ROT,
    OP_ADD,

    // A_and_B_odd = f(A_andxor_B_odd)
    i - 1,
    OP_ADD,
    OP_PICK,

    // A_and_B = A_and_B_odd + (A_and_B_even << 1)
    OP_SWAP,
    OP_DUP,
    OP_ADD,
    OP_ADD,
]

// Expects the u32_xor_table to be on the stack
export const u32_and = (a, b, stackSize) => {
    if (a == b) 
        throw 'a == b'
    return [
        u32_copy_zip(a,b),

        u8_and(8 + (stackSize - 2) * 4),

        OP_TOALTSTACK,

        u8_and(6 + (stackSize - 2) * 4),

        OP_TOALTSTACK,

        u8_and(4 + (stackSize - 2) * 4),

        OP_TOALTSTACK,

        u8_and(2 + (stackSize - 2) * 4),


        OP_FROMALTSTACK,
        OP_FROMALTSTACK,
        OP_FROMALTSTACK,
    ]
}

