import { Leaf } from '../transactions/transaction.js'
import { CommitInstructionAddLeaf, CommitInstructionSubLeaf } from '../transactions/bitvm.js'
import { PaulPlayer } from '../transactions/bitvm-player.js'
import { ASM_ADD, ASM_SUB, ASM_MUL, ASM_JMP, ASM_BEQ, ASM_BNE } from '../transactions/bitvm.js'

const PAUL_SECRET = 'd898098e09898a0980989b980809809809f09809884324874302975287524398'

class DummyPaul extends PaulPlayer {
    constructor(){ super(PAUL_SECRET, null, null) }
}

describe('InstructionCommitLeafs', function () {

    it('can run an ASM_ADD script', function(){
        class DummyPaulAdd extends DummyPaul {
            get valueA()   { return 42 }
            get valueB()   { return 43 }
            get valueC()   { return 85 }
            get addressA() { return 2 }
            get addressB() { return 3 }
            get addressC() { return 4 }
            get pcCurr()   { return 31 }
            get pcNext()   { return 32 }
            get instructionType() { return ASM_ADD }
        }

        const dummyLeaf = new CommitInstructionAddLeaf({}, null, new DummyPaulAdd())
        const result = dummyLeaf.canExecute()
        
        expect(result).toBeTrue()
    })


    it('can run an ASM_SUB script', function(){

        class DummyPaulSub extends DummyPaul {
            get valueA()   { return 13 }
            get valueB()   { return 7 }
            get valueC()   { return 6 }
            get addressA() { return 2 }
            get addressB() { return 3 }
            get addressC() { return 4 }
            get pcCurr()   { return 31 }
            get pcNext()   { return 32 }
            get instructionType() { return ASM_SUB }
        }

        const dummyLeaf = new CommitInstructionSubLeaf({}, null, new DummyPaulSub())
        const result = dummyLeaf.canExecute()
        
        expect(result).toBeTrue()
    })

})
