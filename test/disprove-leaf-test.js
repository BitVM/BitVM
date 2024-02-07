import { DisproveProgram, DisproveAddressALeaf, DisproveAddressBLeaf, DisproveAddressCLeaf, DisproveInstructionTypeLeaf} from '../bitvm/bitvm.js'
import { ASM_ADD, ASM_ADDI, ASM_AND, ASM_ANDI, ASM_BEQ, ASM_BNE, ASM_JMP, ASM_LOAD, ASM_MUL, ASM_OR, ASM_ORI, ASM_RSHIFT1, ASM_SLT, ASM_SLTU, ASM_STORE, ASM_XOR, ASM_XORI } from '../bitvm/constants.js'
import { PaulPlayer } from '../bitvm/model.js'
import { Instruction } from '../bitvm/vm.js'

const PAUL_SECRET = 'd898098e09898a0980989b980809809809f09809884324874302975287524398'

class DummyPaul extends PaulPlayer {
    constructor(){ super(PAUL_SECRET, null, null) }
}


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

    it ('can disprove addressA', function() {
        
        class DummyPaulAddressA extends DummyPaul {
            get addressA() { return 4 }
            get addressB() { return 0 }
            get addressC() { return 0 }
            get pcCurr()   { return 31 }
        }
        const dummyLeaf = new DisproveAddressALeaf({}, null, new DummyPaulAddressA, 31, new Instruction(...[ASM_ADD, 3, 0, 0]))
        const result = dummyLeaf.canExecute()
        
        expect(result).toBeTrue()
    })

    it ('can disprove addressB', function() {
        
        class DummyPaulAddressB extends DummyPaul {
            get addressA() { return 3 }
            get addressB() { return 1 }
            get addressC() { return 0 }
            get pcCurr()   { return 31 }
        }
        const dummyLeaf = new DisproveAddressBLeaf({}, null, new DummyPaulAddressB, 31, new Instruction(...[ASM_ADD, 3, 0, 0]))
        const result = dummyLeaf.canExecute()
        
        expect(result).toBeTrue()
    })

    it ('can disprove addressC', function() {
        
        class DummyPaulAddressC extends DummyPaul {
            get addressA() { return 3 }
            get addressB() { return 0 }
            get addressC() { return 1 }
            get pcCurr()   { return 31 }
        }
        const dummyLeaf = new DisproveAddressCLeaf({}, null, new DummyPaulAddressC, 31, new Instruction(...[ASM_ADD, 3, 0, 0]))
        const result = dummyLeaf.canExecute()
        
        expect(result).toBeTrue()
    })

    it ('can disprove instructionType', function() {
        
        class DummyPaulType extends DummyPaul {
            get addressA() { return 3 }
            get addressB() { return 0 }
            get addressC() { return 0 }
            get pcCurr()   { return 31 }
            get instructionType() { return ASM_ADD }
        }
        const dummyLeaf = new DisproveInstructionTypeLeaf({}, null, new DummyPaulType, 31, new Instruction(...[ASM_ADDI, 3, 0, 0]))
        const result = dummyLeaf.canExecute()
        
        expect(result).toBeTrue()
    })
})
