import { u32_equalverify, u32_roll, u32_toaltstack, u32_fromaltstack, u32_push } from './u32_std.js'
import { u32_state, u32_state_unlock, u32_state_commit } from './u32_state.js'
import { pushHexEndian } from '../utils.js'

const U160_BYTE_SIZE = 20
const U160_U32_SIZE = 5
const U160_HEX_SIZE = U160_BYTE_SIZE * 2

export const u160_state = (secret, identifier) => [
    u32_state(secret, identifier + '_5'),
    u32_toaltstack,
    u32_state(secret, identifier + '_4'),
    u32_toaltstack,
    u32_state(secret, identifier + '_3'),
    u32_toaltstack,
    u32_state(secret, identifier + '_2'),
    u32_toaltstack,
    u32_state(secret, identifier + '_1'),
    u32_fromaltstack,
    u32_fromaltstack,
    u32_fromaltstack,
    u32_fromaltstack
]

export const u160_state_commit = (secret, identifier) =>
    loop (U160_U32_SIZE, i => u32_state_commit(secret, identifier + `_${U160_U32_SIZE-i}`))

function swapEndian(hexString) {
    return hexString.match(/../g).reverse().join('');
}

function hexToU32array(hexString) {
    if (hexString.length !== U160_HEX_SIZE)
        throw new Error(`Hex string must be 20 bytes (40 characters) long`)
    
    const numbers = []
    for (let i = hexString.length - 8; i >= 0 ; i -= 8) {
        // Extract 8 characters (4 bytes) at a time
        const substring = swapEndian(hexString.substring(i, i + 8))

        // Parse the substring as a hex number and add it to the result array
        const number = parseInt(substring, 16)
        numbers.push(number)
    }

    return numbers
}


export const u160_state_unlock = (actor, identifier, hexValue) =>
    hexToU32array(hexValue)
    .map((u32_value, i) => u32_state_unlock(actor, identifier + `_${i+1}`, u32_value))


export const u160_equalverify = loop(U160_U32_SIZE, i => [
    u32_roll(U160_U32_SIZE - i),
    u32_equalverify,
])

export const u160_equal = [
    loop(U160_BYTE_SIZE - 1, i => [
        U160_BYTE_SIZE - i,
        OP_ROLL,
        OP_EQUAL,
        OP_TOALTSTACK
    ]),
    OP_EQUAL,
    loop(U160_BYTE_SIZE - 1, i => [
        OP_FROMALTSTACK,
        OP_BOOLAND,
    ]),
]

export const u160_notequal = [
    loop(U160_BYTE_SIZE - 1, i => [
        U160_BYTE_SIZE - i,
        OP_ROLL,
        OP_EQUAL,
        OP_NOT,
        OP_TOALTSTACK
    ]),
    OP_EQUAL,
    OP_NOT,
    loop(U160_BYTE_SIZE - 1, i => [
        OP_FROMALTSTACK,
        OP_BOOLOR,
    ]),
]

export const u160_push = hexString => {
    if (hexString.length != U160_HEX_SIZE)
        throw `ERROR: hexString.length != ${U160_HEX_SIZE}`
    return pushHexEndian(hexString)
}


export const u160_swap_endian  = loop(U160_BYTE_SIZE, i => [ Math.floor(i/4) * 4 + 3, OP_ROLL ])

export const u160_toaltstack   = loop(U160_BYTE_SIZE, _ => OP_TOALTSTACK)

export const u160_fromaltstack = loop(U160_BYTE_SIZE, _ => OP_FROMALTSTACK)

