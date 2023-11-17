import { u32_equalverify, u32_roll, u32_toaltstack, u32_fromaltstack, u32_push } from '../u32/u32_std.js'
import { u32_state, u32_state_unlock, u32_state_commit } from '../u32/u32_state.js'

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
    loop (5, i => u32_state_commit(secret, identifier + `_${5-i}`))

function swapEndian(hexString) {
    return hexString.match(/../g).reverse().join('');
}

function hexStringTo32BitNumbers(hexString) {
    if (hexString.length !== 40)
        throw new Error('Hex string must be 20 bytes (40 characters) long')
    
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


export const u160_state_unlock = (secret, identifier, value) =>
    hexStringTo32BitNumbers(value)
    .map((v, i) => u32_state_unlock(secret, identifier + `_${i+1}`, v))

// export const u160_state_commit_unlock = (secret, identifier, value) =>
//     hexStringTo32BitNumbers(value)
//     .map((v, i) => u32_state_commit_unlock(secret, identifier + `_${i+1}`, v))    



export const u160_equalverify = loop(5, i => [
    u32_roll(5 - i),
    u32_equalverify,
])

export const u160_push = hexString => pushHexEndian(hexString)


export const u160_swap_endian = loop(20, i => [ Math.floor(i/4) * 4 + 3, OP_ROLL ])

export const u160_toaltstack = loop(20, _ => OP_TOALTSTACK)

export const u160_fromaltstack = loop(20, _ => OP_FROMALTSTACK)
