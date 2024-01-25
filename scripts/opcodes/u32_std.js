import './std.js'

export const u32_push = value => [
    (value & 0xff000000) >>> 24,
    (value & 0x00ff0000) >>> 16,
    (value & 0x0000ff00) >>> 8,
    (value & 0x000000ff),
]

export const u32_equalverify = [
    4,
    OP_ROLL,
    OP_EQUALVERIFY,
    3,
    OP_ROLL,
    OP_EQUALVERIFY,
    OP_ROT,
    OP_EQUALVERIFY,
    OP_EQUALVERIFY,
]

export const u32_equal = [
    4,
    OP_ROLL,
    OP_EQUAL, OP_TOALTSTACK,
    3,
    OP_ROLL,
    OP_EQUAL, OP_TOALTSTACK,
    OP_ROT,
    OP_EQUAL, OP_TOALTSTACK,
    OP_EQUAL,
    OP_FROMALTSTACK, OP_BOOLAND,
    OP_FROMALTSTACK, OP_BOOLAND,
    OP_FROMALTSTACK, OP_BOOLAND,
]

export const u32_notequal = [
    4,
    OP_ROLL,
    OP_EQUAL, OP_NOT, OP_TOALTSTACK,
    3,
    OP_ROLL,
    OP_EQUAL, OP_NOT, OP_TOALTSTACK,
    OP_ROT,
    OP_EQUAL, OP_NOT, OP_TOALTSTACK,
    OP_EQUAL, OP_NOT,
    OP_FROMALTSTACK, OP_BOOLOR,
    OP_FROMALTSTACK, OP_BOOLOR,
    OP_FROMALTSTACK, OP_BOOLOR,
]

export const u32_toaltstack = [
    OP_TOALTSTACK,
    OP_TOALTSTACK,
    OP_TOALTSTACK,
    OP_TOALTSTACK,
]

export const u32_fromaltstack = [
    OP_FROMALTSTACK,
    OP_FROMALTSTACK,
    OP_FROMALTSTACK,
    OP_FROMALTSTACK,
]

export const u32_drop = [
    OP_2DROP,
    OP_2DROP,
]

export const u32_roll = a => {
    a = (a + 1) * 4 - 1
    return [
        a, OP_ROLL,
        a, OP_ROLL,
        a, OP_ROLL,
        a, OP_ROLL,
    ]
}

export const u32_pick = a => {
    a = (a + 1) * 4 - 1
    return [
        a, OP_PICK,
        a, OP_PICK,
        a, OP_PICK,
        a, OP_PICK,
    ]
}


export const u32_dup = [
    3,
    OP_PICK,
    OP_TOALTSTACK,
    OP_3DUP,
    OP_FROMALTSTACK,
    OP_ROT,
    OP_ROT,
    OP_2SWAP,
    OP_SWAP,
    OP_2SWAP,
]


const u32_compress = [
    OP_SWAP,
    OP_ROT,
    3,
    OP_ROLL,
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
    OP_TOALTSTACK,
    OP_256MUL,
    OP_ADD,
    OP_256MUL,
    OP_ADD,
    OP_256MUL,
    OP_ADD,
    OP_FROMALTSTACK,
    OP_IF,
        OP_NEGATE,
    OP_ENDIF,
]
