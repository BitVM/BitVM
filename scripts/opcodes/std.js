import * as opcodes from './opcodes.js'
Object.assign(window, opcodes)

export const loop = (count, template) => {
    let res = [];
    for (var i = 0; i < count; i++) {
        res.push( template(i, count) );
    }
    return res
}

window.loop = loop

// 
// 
// Pseudo Instructions
// 
// 

//
// OP_4PICK
// The 4 items n back in the stack are copied to the top.
// 

// 1234_
// ^^^^^
// 1234_1
//  ^^^^^
// 1234_12
//   ^^^^^
// 1234_123
//    ^^^^^
// 1234_1234
export const OP_4PICK = [
    OP_4, OP_ADD, 
    OP_DUP,  OP_PICK, OP_SWAP,
    OP_DUP,  OP_PICK, OP_SWAP,
    OP_DUP,  OP_PICK, OP_SWAP,
    OP_1SUB, OP_PICK
]


//
// OP_4ROLL
// The 4 items n back in the stack are moved to the top.
//

// 1234_
// ^^^^^
// 234_1
// ^^^^^
// 3_412
// ^^^^^
// 4_123
// ^^^^^
// _1234
export const OP_4ROLL = [
    OP_4, OP_ADD, 
    OP_DUP,  OP_ROLL, OP_SWAP,
    OP_DUP,  OP_ROLL, OP_SWAP,
    OP_DUP,  OP_ROLL, OP_SWAP,
    OP_1SUB, OP_ROLL
]


// Duplicates the top four stack items
export const OP_4DUP  = [OP_2OVER, OP_2OVER]

// Removes the top four stack items.
export const OP_4DROP = [OP_2DROP, OP_2DROP]


export const OP_4SWAP = [
    7, OP_ROLL, 7, OP_ROLL,
    7, OP_ROLL, 7, OP_ROLL
]

// Puts the top 4 items onto the top of the alt stack. Removes them from the main stack.
export const OP_4TOALTSTACK   = [OP_TOALTSTACK, OP_TOALTSTACK, OP_TOALTSTACK, OP_TOALTSTACK]

// Puts the top 4 items from the altstack onto the top of the main stack. Removes them from the alt stack.
export const OP_4FROMALTSTACK = [OP_FROMALTSTACK, OP_FROMALTSTACK, OP_FROMALTSTACK, OP_FROMALTSTACK]



// 
// Multiplication by Powers of 2
// 

// The input is multiplied by 2
export const OP_2MUL = [OP_DUP, OP_ADD]

// The input is multiplied by 4
export const OP_4MUL = [
    OP_DUP, OP_ADD, OP_DUP, OP_ADD
]

// The input is multiplied by 2**k
export const op_2k_mul = k => loop(k, _ => OP_2MUL)

// The input is multiplied by 16
export const OP_16MUL = [
    OP_DUP, OP_ADD, OP_DUP, OP_ADD, 
    OP_DUP, OP_ADD, OP_DUP, OP_ADD
]

// The input is multiplied by 256
export const OP_256MUL = [
    OP_DUP, OP_ADD, OP_DUP, OP_ADD, 
    OP_DUP, OP_ADD, OP_DUP, OP_ADD,
    OP_DUP, OP_ADD, OP_DUP, OP_ADD, 
    OP_DUP, OP_ADD, OP_DUP, OP_ADD
]

// Boolean XOR
// WARNING: Doesn't error for non-bit values
export const OP_BOOLXOR = OP_NUMNOTEQUAL