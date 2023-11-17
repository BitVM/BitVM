import '../opcodes/std/opcodes.js'
import '../opcodes/std/std.js'
import { pushText, pushHex, pushHexEndian, sanitizeBytes } from '../opcodes/utils.js'
import { u32_push, u32_equalverify, u32_toaltstack, u32_fromaltstack, u32_drop, u32_roll, u32_pick } from '../opcodes/u32/u32_std.js'
import { u32_rrot7, u32_rrot8, u32_rrot12, u32_rrot16 } from '../opcodes/u32/u32_rrot.js'
import { u32_zip, u32_copy_zip } from '../opcodes/u32/u32_zip.js'
import { u32_add, u32_add_drop } from '../opcodes/u32/u32_add.js'
import { u32_sub } from '../opcodes/u32/u32_sub.js'
import { u32_xor, u32_push_xor_table, u32_drop_xor_table } from '../opcodes/u32/u32_xor.js'
import { preimageHex, bit_state_unlock, u8_state, u8_state_unlock, u32_state, u32_state_unlock, u2_state_commit, u8_state_commit, u32_state_commit, u2_state, u2_state_unlock } from '../opcodes/u32/u32_state.js'
import { u160_state, u160_state_unlock, u160_state_commit, u160_equalverify, u160_push } from '../opcodes/u160/u160_std.js'
import { u256_equalverify } from '../opcodes/u256/u256_std.js'
import { blake3, blake3_160 } from '../opcodes/blake3/blake3.js'


function optimize(code) {
    for (let i = 1; i < code.length; ++ i) {
        if (code[i] === OP_ADD) {
            if (code[i-1] === 1 || code[i-1] === OP_1) {
                code.splice(i-1, 2, OP_1ADD)
            }
        }
        if (code[i] === OP_SUB) {
            if (code[i-1] === 1 || code[i-1] === OP_1) {
                code.splice(i-1, 2, OP_1SUB)
            }
        }
        if (code[i] === OP_DROP && code[i-1] === OP_DROP) {
            code.splice(i-1, 2, OP_2DROP)
        }
        if (code[i] == OP_ROLL) {
            if (code[i-1] === 0 || code[i-1] === OP_0) {
                code.splice(i-1, 2)
            }
            if (code[i-1] === 1 || code[i-1] === OP_1) {
                code.splice(i-1, 2, OP_SWAP)
            }
            if (code[i-1] === 2 || code[i-1] === OP_2) {
                code.splice(i-1, 2, OP_ROT)
            }
        }
        if (code[i] == OP_PICK) {
            if (code[i-1] === 0 || code[i-1] === OP_0) {
                code.splice(i-1, 2, OP_DUP)
            }
            if (code[i-1] === 1 || code[i-1] === OP_1) {
                code.splice(i-1, 2, OP_OVER)
            }
        }
    }
    return code
}

export function preprocessJS(text) {
    let code = eval(text)
    if (Array.isArray(code)) {
        code = optimize(code.flat(50)).join(' ')
    }
    code = code.split('debug;')[0]
    return code
}