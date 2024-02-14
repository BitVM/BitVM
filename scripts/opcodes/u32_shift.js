import "./std.js"

export const u32_lshift8 = [3, OP_ROLL, OP_DROP, 0]

export const u32_lshift16 = [OP_2SWAP, OP_2DROP, 0, 0]

export const u32_lshift24 = [OP_2SWAP, OP_2DROP, OP_SWAP, OP_DROP, 0, 0, 0]

export const u32_rshift8 = [OP_DROP, 0, 3, OP_ROLL, 3, OP_ROLL, 3, OP_ROLL]

export const u32_rshift16 = [OP_2DROP, 0, 0, 3, OP_ROLL, 3, OP_ROLL]

export const u32_rshift24 = [OP_2DROP, OP_DROP, 0, 0, 0, 3, OP_ROLL]