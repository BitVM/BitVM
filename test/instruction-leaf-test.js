import { Leaf } from '../scripts/transaction.js'
import { CommitInstructionAddLeaf, CommitInstructionSubLeaf, CommitInstructionBNELeaf } from '../bitvm/bitvm.js'
import { PaulPlayer } from '../bitvm/bitvm-player.js'
import { ASM_ADD, ASM_SUB, ASM_MUL, ASM_JMP, ASM_BEQ, ASM_BNE } from '../bitvm/constants.js'

const PAUL_SECRET = 'd898098e09898a0980989b980809809809f09809884324874302975287524398'

class DummyPaul extends PaulPlayer {
    constructor(){ super(PAUL_SECRET, null, null) }
}

describe('InstructionCommitLeaf', function() {

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

    it('can run an ASM_BNE script (case: True)', function(){

        class DummyPaulBNE extends DummyPaul {
            get valueA()   { return 7 }
            get valueB()   { return 10 }
            get addressA() { return 2 }
            get addressB() { return 3 }
            get addressC() { return 7 }
            get pcCurr()   { return 31 }
            get pcNext()   { return 7 }
            get instructionType() { return ASM_BNE }
        }

        const dummyLeaf = new CommitInstructionBNELeaf({}, null, new DummyPaulBNE())
        const result = dummyLeaf.canExecute()
        
        expect(result).toBeTrue()
    })

    it('can run an ASM_BNE script (case: False)', function(){

        class DummyPaulBNE extends DummyPaul {
            get valueA()   { return 7 }
            get valueB()   { return 7 }
            get addressA() { return 2 }
            get addressB() { return 3 }
            get addressC() { return 7 }
            get pcCurr()   { return 31 }
            get pcNext()   { return 32 }
            get instructionType() { return ASM_BNE }
        }

        const dummyLeaf = new CommitInstructionBNELeaf({}, null, new DummyPaulBNE())
        const result = dummyLeaf.canExecute()
        
        expect(result).toBeTrue()
    })

})
