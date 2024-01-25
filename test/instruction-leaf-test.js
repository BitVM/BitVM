import { Leaf } from '../scripts/transaction.js'
import { CommitInstructionAddLeaf, CommitInstructionSubLeaf, CommitInstructionBNELeaf, CommitInstructionLoadLeaf, CommitInstructionOrLeaf, CommitInstructionStoreLeaf, CommitInstructionOrImmediateLeaf, CommitInstructionXorImmediateLeaf, CommitInstructionXorLeaf, CommitInstructionAndLeaf, CommitInstructionAndImmediateLeaf, CommitInstructionJMPLeaf, CommitInstructionRSHIFT1Leaf, CommitInstructionSLTULeaf, CommitInstructionSLTLeaf } from '../bitvm/bitvm.js'
import { PaulPlayer } from '../bitvm/bitvm-player.js'
import { ASM_ADD, ASM_SUB, ASM_MUL, ASM_JMP, ASM_BEQ, ASM_BNE, ASM_LOAD, ASM_STORE, ASM_AND, ASM_ANDI, ASM_OR, ASM_ORI, ASM_XOR, ASM_XORI, ASM_RSHIFT1, ASM_SLTU, ASM_SLT } from '../bitvm/constants.js'

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

    it('can run an ASM_JMP script', function(){

        class DummyPaulJMP extends DummyPaul {
            get valueA()   { return 7 }
            get valueB()   { return NaN }
            get addressA() { return 2 }
            get addressB() { return NaN }
            get addressC() { return NaN }
            get pcCurr()   { return NaN }
            get pcNext()   { return 7 }
            get instructionType() { return ASM_JMP }
        }

        const dummyLeaf = new CommitInstructionJMPLeaf({}, null, new DummyPaulJMP())
        const result = dummyLeaf.canExecute()
        
        expect(result).toBeTrue()
    })

    it('can run an ASM_LOAD script', function(){

        class DummyPaulLOAD extends DummyPaul {
            get valueA()   { return 0xDEADBEEF }
            get valueB()   { return 187 }
            get valueC()   { return 0xDEADBEEF }
            get addressA() { return 187 }
            get addressB() { return 0 }
            get addressC() { return 1 }
            get pcCurr()   { return 31 }
            get pcNext()   { return 32 }
            get instructionType() { return ASM_LOAD }
        }

        const dummyLeaf = new CommitInstructionLoadLeaf({}, null, new DummyPaulLOAD())
        const result = dummyLeaf.canExecute()
        
        expect(result).toBeTrue()
    })


    it('can run an ASM_STORE script', function(){
        class DummyPaulSTORE extends DummyPaul {
            get valueA()   { return 0xDEADBEEF }
            get valueB()   { return 187 }
            get valueC()   { return 0xDEADBEEF }
            get addressA() { return 2 }
            get addressB() { return 3 }
            get addressC() { return 187 }
            get pcCurr()   { return 31 }
            get pcNext()   { return 32 }
            get instructionType() { return ASM_STORE }
        }

        const dummyLeaf = new CommitInstructionStoreLeaf({}, null, new DummyPaulSTORE())
        const result = dummyLeaf.canExecute()
        
        expect(result).toBeTrue()
    })

    it('can run an ASM_AND script', function(){
        class DummyPaulAND extends DummyPaul {
            get valueA()   { return 0b11000110_11000110_11000110_10001101 }
            get valueB()   { return 0b10100101_10100101_10100101_01001011 }
            get valueC()   { return 0b10000100_10000100_10000100_00001001 }
            get addressA() { return 2 }
            get addressB() { return 3 }
            get addressC() { return 4 }
            get pcCurr()   { return 31 }
            get pcNext()   { return 32 }
            get instructionType() { return ASM_AND }
        }

        const dummyLeaf = new CommitInstructionAndLeaf({}, null, new DummyPaulAND())
        const result = dummyLeaf.canExecute()
        
        expect(result).toBeTrue()
    })


    it('can run an ASM_ANDI script', function(){
        class DummyPaulANDI extends DummyPaul {
            get valueA()   { return 0b11000110_11000110_11000110_10001101 }
            get valueB()   { return NaN }                                
            get valueC()   { return 0b10000100_10000100_10000100_00001001 }
            get addressA() { return 2 }                                  
            get addressB() { return 0b10100101_10100101_10100101_01001011 }
            get addressC() { return 4 }
            get pcCurr()   { return 31 }
            get pcNext()   { return 32 }
            get instructionType() { return ASM_ANDI }
        }

        const dummyLeaf = new CommitInstructionAndImmediateLeaf({}, null, new DummyPaulANDI())
        const result = dummyLeaf.canExecute()
        
        expect(result).toBeTrue()
    })

    it('can run an ASM_OR script', function(){
        class DummyPaulOR extends DummyPaul {
            get valueA()   { return 0b11000110_11000110_11000110_01100011 }
            get valueB()   { return 0b10100101_10100101_10100101_11010010 }
            get valueC()   { return 0b11100111_11100111_11100111_11110011 }
            get addressA() { return 2 }
            get addressB() { return 3 }
            get addressC() { return 4 }
            get pcCurr()   { return 31 }
            get pcNext()   { return 32 }
            get instructionType() { return ASM_OR }
        }

        const dummyLeaf = new CommitInstructionOrLeaf({}, null, new DummyPaulOR())
        const result = dummyLeaf.canExecute()
        
        expect(result).toBeTrue()
    })


    it('can run an ASM_ORI script', function(){
        class DummyPaulORI extends DummyPaul {
            get valueA()   { return 0b11000110_11000110_11000110_01100011 }
            get valueB()   { return NaN }                         
            get valueC()   { return 0b11100111_11100111_11100111_11110011 }
            get addressA() { return 2 }                           
            get addressB() { return 0b10100101_10100101_10100101_11010010 }
            get addressC() { return 4 }
            get pcCurr()   { return 31 }
            get pcNext()   { return 32 }
            get instructionType() { return ASM_ORI }
        }

        const dummyLeaf = new CommitInstructionOrImmediateLeaf({}, null, new DummyPaulORI())
        const result = dummyLeaf.canExecute()
        
        expect(result).toBeTrue()
    })


    it('can run an ASM_XOR script', function(){
        class DummyPaulXOR extends DummyPaul {
            get valueA()   { return 0b11000110_11000110_11000110_01100011 }
            get valueB()   { return 0b10100101_10100101_10100101_11010010 }
            get valueC()   { return 0b01100011_01100011_01100011_10110001 }
            get addressA() { return 2 }
            get addressB() { return 3 }
            get addressC() { return 4 }
            get pcCurr()   { return 31 }
            get pcNext()   { return 32 }
            get instructionType() { return ASM_XOR }
        }

        const dummyLeaf = new CommitInstructionXorLeaf({}, null, new DummyPaulXOR())
        const result = dummyLeaf.canExecute()
        
        expect(result).toBeTrue()
    })


    it('can run an ASM_XORI script', function(){
        class DummyPaulXORI extends DummyPaul {
            get valueA()   { return 0b110001100_110001100_110001100_100011001 }
            get valueB()   { return NaN }                                    
            get valueC()   { return 0b011000110_011000110_011000110_110001100 }
            get addressA() { return 2 }                                      
            get addressB() { return 0b101001010_101001010_101001010_010010101 }
            get addressC() { return 4 }
            get pcCurr()   { return 31 }
            get pcNext()   { return 32 }
            get instructionType() { return ASM_XORI }
        }

        const dummyLeaf = new CommitInstructionXorImmediateLeaf({}, null, new DummyPaulXORI())
        const result = dummyLeaf.canExecute()
        
        expect(result).toBeTrue()
    })

    it('can run an ASM_RSHIFT1 script', function(){
        class DummyPaulRSHIFT1 extends DummyPaul {
            get valueA()   { return 0xFEED4321 }
            get valueB()   { return NaN }                                    
            get valueC()   { return 0x7F76A190 }
            get addressA() { return 2 }                                      
            get addressB() { return NaN }
            get addressC() { return 4 }
            get pcCurr()   { return 31 }
            get pcNext()   { return 32 }
            get instructionType() { return ASM_RSHIFT1 }
        }

        const dummyLeaf = new CommitInstructionRSHIFT1Leaf({}, null, new DummyPaulRSHIFT1())
        const result = dummyLeaf.canExecute()
        
        expect(result).toBeTrue()
    })

    it('can run an ASM_RSHIFT1 script (wrong shift)', function(){
        class DummyPaulRSHIFT1False extends DummyPaul {
            get valueA()   { return 0b101010101 }
            get valueB()   { return NaN }                                    
            get valueC()   { return 0b001010101 }
            get addressA() { return 2 }                                      
            get addressB() { return NaN }
            get addressC() { return 4 }
            get pcCurr()   { return 31 }
            get pcNext()   { return 32 }
            get instructionType() { return ASM_RSHIFT1 }
        }

        const dummyLeaf = new CommitInstructionRSHIFT1Leaf({}, null, new DummyPaulRSHIFT1False())
        const result = dummyLeaf.canExecute()
        
        expect(result).toBeFalse()
    })

    it('can run an ASM_SLTU script (pass)', function(){
        class DummyPaulSLTU extends DummyPaul {
            get valueA()   { return 25 }
            get valueB()   { return 26 }                                    
            get valueC()   { return 1 }
            get addressA() { return 2 }                                      
            get addressB() { return 3 }
            get addressC() { return 4 }
            get pcCurr()   { return 31 }
            get pcNext()   { return 32 }
            get instructionType() { return ASM_SLTU }
        }

        const dummyLeaf = new CommitInstructionSLTULeaf({}, null, new DummyPaulSLTU())
        const result = dummyLeaf.canExecute()
        
        expect(result).toBeTrue()
    })

    it('can run an ASM_SLTU script (fail)', function(){
        class DummyPaulSLTU extends DummyPaul {
            get valueA()   { return 0xFFFFFFFF }
            get valueB()   { return 4 }                                    
            get valueC()   { return 1 }
            get addressA() { return 2 }                                      
            get addressB() { return 3 }
            get addressC() { return 4 }
            get pcCurr()   { return 31 }
            get pcNext()   { return 32 }
            get instructionType() { return ASM_SLTU }
        }

        const dummyLeaf = new CommitInstructionSLTULeaf({}, null, new DummyPaulSLTU())
        const result = dummyLeaf.canExecute()
        
        expect(result).toBeFalse()
    })

    it('can run an ASM_SLT script (can execute - different signs)', function(){
        class DummyPaulSLT extends DummyPaul {
            get valueA()   { return 0xF000_000A }
            get valueB()   { return 0x0B }                                    
            get valueC()   { return 1 }
            get addressA() { return 2 }                                      
            get addressB() { return 3 }
            get addressC() { return 4 }
            get pcCurr()   { return 31 }
            get pcNext()   { return 32 }
            get instructionType() { return ASM_SLT }
        }

        const dummyLeaf = new CommitInstructionSLTLeaf({}, null, new DummyPaulSLT())
        const result = dummyLeaf.canExecute()
        
        expect(result).toBeTrue()
    })
    
    it('can run an ASM_SLT script (can execute - same sign positive )', function(){
        class DummyPaulSLT extends DummyPaul {
            get valueA()   { return 0x0A }
            get valueB()   { return 0x0B }                                    
            get valueC()   { return 1 }
            get addressA() { return 2 }                                      
            get addressB() { return 3 }
            get addressC() { return 4 }
            get pcCurr()   { return 31 }
            get pcNext()   { return 32 }
            get instructionType() { return ASM_SLT }
        }

        const dummyLeaf = new CommitInstructionSLTLeaf({}, null, new DummyPaulSLT())
        const result = dummyLeaf.canExecute()
        
        expect(result).toBeTrue()
    })

    it('can run an ASM_SLT script (can execute - same sign negative )', function(){
        class DummyPaulSLT extends DummyPaul {
            get valueA()   { return 0xF000_00A0 }
            get valueB()   { return 0xF000_000B }                                    
            get valueC()   { return 0 }
            get addressA() { return 2 }                                      
            get addressB() { return 3 }
            get addressC() { return 4 }
            get pcCurr()   { return 31 }
            get pcNext()   { return 32 }
            get instructionType() { return ASM_SLT }
        }

        const dummyLeaf = new CommitInstructionSLTLeaf({}, null, new DummyPaulSLT())
        const result = dummyLeaf.canExecute()
        
        expect(result).toBeTrue()
    })

    it('can run an ASM_SLT script (tx fails for wrong valueC - different signs)', function(){
        class DummyPaulSLT extends DummyPaul {
            get valueA()   { return 0xF000_000A }
            get valueB()   { return 0x0B }                                    
            get valueC()   { return 0 }
            get addressA() { return 2 }                                      
            get addressB() { return 3 }
            get addressC() { return 4 }
            get pcCurr()   { return 31 }
            get pcNext()   { return 32 }
            get instructionType() { return ASM_SLT }
        }

        const dummyLeaf = new CommitInstructionSLTLeaf({}, null, new DummyPaulSLT())
        const result = dummyLeaf.canExecute()
        
        expect(result).toBeFalse()
    })

    it('can run an ASM_SLT script (tx fails for wrong valueC - same signs)', function(){
        class DummyPaulSLT extends DummyPaul {
            get valueA()   { return 0xF000_00A0 }
            get valueB()   { return 0xF000_000B }                                    
            get valueC()   { return 1 }
            get addressA() { return 2 }                                      
            get addressB() { return 3 }
            get addressC() { return 4 }
            get pcCurr()   { return 31 }
            get pcNext()   { return 32 }
            get instructionType() { return ASM_SLT }
        }

        const dummyLeaf = new CommitInstructionSLTLeaf({}, null, new DummyPaulSLT())
        const result = dummyLeaf.canExecute()
        
        expect(result).toBeFalse()
    })
})
