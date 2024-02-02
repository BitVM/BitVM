import { DisproveProgram } from '../bitvm/bitvm.js'
import { ASM_ADD, ASM_ADDI, ASM_AND, ASM_ANDI, ASM_BEQ, ASM_BNE, ASM_JMP, ASM_LOAD, ASM_MUL, ASM_OR, ASM_ORI, ASM_RSHIFT1, ASM_SLT, ASM_SLTU, ASM_STORE, ASM_XOR, ASM_XORI } from '../bitvm/constants.js'


const program = [
    [ASM_ADDI, 0, 1, 2],
    [ASM_ADD, 0, 1, 2],
    [ASM_OR, 0, 1, 2],
    [ASM_ORI, 0, 1, 2],
    [ASM_AND, 0, 1, 2],
    [ASM_ANDI, 0, 1, 2],
    [ASM_XOR, 0, 1, 2],
    [ASM_XORI, 0, 1, 2],
    [ASM_SLT, 0, 1, 2],
    [ASM_SLTU, 0, 1, 2],
    [ASM_BEQ, 0, 1, 2],
    [ASM_BNE, 0, 1, 2],
    [ASM_RSHIFT1, 0, 1, 2],
    [ASM_JMP, 0, NaN, NaN],
    [ASM_STORE, 0, 1, NaN],
    [ASM_LOAD, NaN, 1, 2],
    [ASM_MUL, 0, 1, 2],
]


describe('DisproveInstructionLeaf', function() {

    it('can be generated', function() {
        const disproveProgramTaproot = DisproveProgram.taproot({ vicky: null, paul: null, program })
        expect(disproveProgramTaproot.length).toEqual(13 * 4 + 2 + 2 * 3 + 4)
    })
})
