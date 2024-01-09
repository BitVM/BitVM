import init, { run_script, script_asm_to_hex } from '../libs/bitcoin_scriptexec.js'
import { preprocessJS } from '../scripts/compile.js'
await init()
import { Player } from '../scripts/player.js'

import { u32_state_bit, u32_state_bit_unlock, u8_state_bit, u8_state_bit_unlock, u2_state_bit, u2_state_unlock } from '../scripts/opcodes/u32_state.js'

const PAUL_SECRET = 'd898098e09898a0980989b980809809809f09809884324874302975287524398'
const actor = new Player(PAUL_SECRET, null, null)

describe('u32_state_bit lib', function () {

    it('can run u32_state_bit script', function(){
        const identifier = 'DUMMY_IDENTIFIER'
        const bitIndex = 15
        const value = 0b01000000000000000

        const program = [
            u32_state_bit_unlock(actor, identifier, value, bitIndex),
            u32_state_bit(actor, identifier, bitIndex),
        ]
        const script = preprocessJS(program)
        const compiledScript = script_asm_to_hex(script)
        const result = run_script(compiledScript, '')
        const finalStack = result.get('final_stack')
        expect(finalStack[0]).toBe('01')
        expect(finalStack.length).toBe(1)
    })


    it('can run u8_state_bit script', function(){
        const identifier = 'DUMMY_IDENTIFIER'
        const bitIndex = 6
        const value = 0b01000000

        const program = [
            u8_state_bit_unlock(actor, identifier, value, bitIndex),
            u8_state_bit(actor, identifier, bitIndex),
        ]
        const script = preprocessJS(program)
        const compiledScript = script_asm_to_hex(script)
        const result = run_script(compiledScript, '')
        expect(result.get('final_stack')[0]).toBe('01')
    })

    it('can run u2_state_bit script', function(){
        const identifier = 'DUMMY_IDENTIFIER'
        const bitIndex = 1
        const value = 0b11
        const index = 1

        const program = [
            u2_state_unlock(actor, identifier, value, index),
            u2_state_bit(actor, identifier, index, bitIndex),
        ]
        const script = preprocessJS(program)
        const compiledScript = script_asm_to_hex(script)
        const result = run_script(compiledScript, '')
        expect(result.get('final_stack')[0]).toBe('01')
    })

})
