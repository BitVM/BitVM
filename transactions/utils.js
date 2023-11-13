import { toHex } from '../libs/bytes.js'
import { Script, Tap, Address } from '../libs/tapscript.js'
import { keys } from '../libs/crypto_tools.js'
import init, { run_script, script_asm_to_hex } from '../libs/bitcoin_scriptexec.js'
import { preprocessJS } from '../opcodes/compile.js'
await init()  

// TODO set to smallest sendable amount
export const DUST_LIMIT = 500

export function compile(program) {
    return Script.decode(script_asm_to_hex(preprocessJS(program)))
}

export function replace_unlock_opcodes(script) {
    return script.map(opcode => {
        switch (opcode) {
            case 'OP_1':
                return '01'
            case 'OP_2':
                return '02'
            case 'OP_3':
                return '03'
            default:
                return opcode
        }
    })
}

export function compileUnlock(program) {
    return replace_unlock_opcodes(compile(program))
}

export function toPublicKey(secret){
    // Drop the first byte of the pubkey
    return toHex(keys.get_pubkey(secret)).slice(2)
}

export function generateP2trAddressInfo(script, pubkey) {
    const tapleaf = Tap.encodeScript(script)
    // We could use a random pubkey for the tweaking to disable the key-spending path
    // See https://github.com/cmdruid/tapscript#about-key-tweaking
    // In the current setting we allow paul to skip the challenge tx for vicky (e.g. in case he knows the preimage already)
    const [tweaked_pubkey, control_block] = Tap.getPubKey(pubkey, {target: tapleaf})
    const address = Address.p2tr.fromPubKey(tweaked_pubkey, 'signet')
    return [address, tapleaf, control_block]
}