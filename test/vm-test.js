import { VM, toU32 } from '../bitvm/vm.js'
import {
    ASM_ADD,
    ASM_SUB,
    ASM_MUL,
    ASM_AND,
    ASM_OR,
    ASM_XOR,
    ASM_ADDI,
    ASM_SUBI,
    ASM_ANDI,
    ASM_ORI,
    ASM_XORI,
    ASM_JMP,
    ASM_RSHIFT1,
    ASM_SLTU,
    ASM_SLT,
    ASM_LOAD,
    ASM_WRITE,
    ASM_SYSCALL,
    ASM_BEQ,
    ASM_BNE,
    U32_SIZE } from '../bitvm/constants.js'
import { program, data } from '../run/dummy-program.js'


describe('The VM', function () {

    it('can execute ADD instructions', function(){
        const addressA = 0
        const valueA = U32_SIZE - 5
        const addressB = 1
        const valueB = U32_SIZE - 7
        const addressC = 2
        const program = [[ ASM_ADD, addressA, addressB, addressC ]]
        const data = [ valueA, valueB ]

        const vm = new VM(program, data)
        const snapshot = vm.run()
        
        // Verify result
        const valueC = snapshot.read(addressC)
        expect(valueC).toBe( toU32(valueA + valueB) ) 

        // Verify program counter
        const currPc = vm.run(0).pc
        const nextPc = snapshot.pc
        expect(nextPc).toBe(currPc + 1)
    })

    it('can execute SUB instructions', function(){
        const addressA = 0
        const valueA = 42
        const addressB = 1
        const valueB = 120
        const addressC = 2
        const program = [[ ASM_SUB, addressA, addressB, addressC ]]
        const data = [ valueA, valueB ]

        const vm = new VM(program, data)
        const snapshot = vm.run()
        
        // Verify result
        const valueC = snapshot.read(addressC)
        expect(valueC).toBe( toU32(valueA - valueB) )

        // Verify program counter
        const currPc = vm.run(0).pc
        const nextPc = snapshot.pc
        expect(nextPc).toBe(currPc + 1)
    })

    it('can execute MUL instructions', function(){
        const addressA = 0
        const valueA = U32_SIZE - 5
        const addressB = 1
        const valueB = U32_SIZE - 7
        const addressC = 2
        const program = [[ ASM_MUL, addressA, addressB, addressC ]]
        const data = [ valueA, valueB ]

        const vm = new VM(program, data)
        const snapshot = vm.run()
        
        // Verify result
        const valueC = snapshot.read(addressC)
        expect(valueC).toBe( toU32(valueA * valueB) ) 

        // Verify program counter
        const currPc = vm.run(0).pc
        const nextPc = snapshot.pc
        expect(nextPc).toBe(currPc + 1)
    })

    it('can execute AND instructions', function(){
        const addressA = 0
        const valueA = 0x1100
        const addressB = 1
        const valueB = 0x0101
        const addressC = 2
        const program = [[ ASM_AND, addressA, addressB, addressC ]]
        const data = [ valueA, valueB ]

        const vm = new VM(program, data)
        const snapshot = vm.run()

        // Verify result
        const valueC = snapshot.read(addressC)
        expect(valueC).toBe( toU32(valueA & valueB) ) 

        // Verify program counter
        const currPc = vm.run(0).pc
        const nextPc = snapshot.pc
        expect(nextPc).toBe(currPc + 1)
    })

    it('can execute OR instructions', function(){
        const addressA = 0
        const valueA = 0x1100
        const addressB = 1
        const valueB = 0x0101
        const addressC = 2
        const program = [[ ASM_OR, addressA, addressB, addressC ]]
        const data = [ valueA, valueB ]

        const vm = new VM(program, data)
        const snapshot = vm.run()

        // Verify result
        const valueC = snapshot.read(addressC)
        expect(valueC).toBe( toU32(valueA | valueB) ) 

        // Verify program counter
        const currPc = vm.run(0).pc
        const nextPc = snapshot.pc
        expect(nextPc).toBe(currPc + 1)
    })

    it('can execute XOR instructions', function(){
        const addressA = 0
        const valueA = 0x1100
        const addressB = 1
        const valueB = 0x0101
        const addressC = 2
        const program = [[ ASM_XOR, addressA, addressB, addressC ]]
        const data = [ valueA, valueB ]

        const vm = new VM(program, data)
        const snapshot = vm.run()

        // Verify result
        const valueC = snapshot.read(addressC)
        expect(valueC).toBe( toU32(valueA ^ valueB) ) 

        // Verify program counter
        const currPc = vm.run(0).pc
        const nextPc = snapshot.pc
        expect(nextPc).toBe(currPc + 1)
    })

    it('can execute ADDI instructions', function(){
        const addressA = 0
        const valueA = U32_SIZE - 5
        const addressB = U32_SIZE - 7
        const addressC = 1
        const program = [[ ASM_ADDI, addressA, addressB, addressC ]]
        const data = [ valueA ]

        const vm = new VM(program, data)
        const snapshot = vm.run()
        
        // Verify result
        const valueC = snapshot.read(addressC)
        expect(valueC).toBe( toU32(valueA + addressB) ) 

        // Verify program counter
        const currPc = vm.run(0).pc
        const nextPc = snapshot.pc
        expect(nextPc).toBe(currPc + 1)
    })

    it('can execute SUBI instructions', function(){
        const addressA = 0
        const valueA = 42
        const addressB = 43
        const addressC = 2
        const program = [[ ASM_SUBI, addressA, addressB, addressC ]]
        const data = [ valueA ]

        const vm = new VM(program, data)
        const snapshot = vm.run()
        
        // Verify result
        const valueC = snapshot.read(addressC)
        expect(valueC).toBe( toU32(valueA - addressB) )

        // Verify program counter
        const currPc = vm.run(0).pc
        const nextPc = snapshot.pc
        expect(nextPc).toBe(currPc + 1)
    })

    it('can execute ANDI instructions', function(){
        const addressA = 0
        const valueA = 0x11000000
        const addressB = 0x01010000
        const addressC = 2
        const program = [[ ASM_ANDI, addressA, addressB, addressC ]]
        const data = [ valueA ]

        const vm = new VM(program, data)
        const snapshot = vm.run()

        // Verify result
        const valueC = snapshot.read(addressC)
        expect(valueC).toBe( toU32(valueA & addressB) ) 

        // Verify program counter
        const currPc = vm.run(0).pc
        const nextPc = snapshot.pc
        expect(nextPc).toBe(currPc + 1)
    })

    it('can execute ORI instructions', function(){
        const addressA = 0
        const valueA = 0x1100
        const addressB = 0x0101
        const addressC = 2
        const program = [[ ASM_ORI, addressA, addressB, addressC ]]
        const data = [ valueA ]

        const vm = new VM(program, data)
        const snapshot = vm.run()

        // Verify result
        const valueC = snapshot.read(addressC)
        expect(valueC).toBe( toU32(valueA | addressB) ) 

        // Verify program counter
        const currPc = vm.run(0).pc
        const nextPc = snapshot.pc
        expect(nextPc).toBe(currPc + 1)
    })

    it('can execute XORI instructions', function(){
        const addressA = 0
        const valueA = 0x1100
        const addressB = 0x0101
        const addressC = 2
        const program = [[ ASM_XORI, addressA, addressB, addressC ]]
        const data = [ valueA ]

        const vm = new VM(program, data)
        const snapshot = vm.run()

        // Verify result
        const valueC = snapshot.read(addressC)
        expect(valueC).toBe( toU32(valueA ^ addressB) ) 

        // Verify program counter
        const currPc = vm.run(0).pc
        const nextPc = snapshot.pc
        expect(nextPc).toBe(currPc + 1)
    })
    it('can execute BEQ instructions (Case: True)', function(){
        const addressA = 0
        const valueA = 42
        const addressB = 1
        const valueB = 42
        const addressC = 210
        const program = [[ ASM_BEQ, addressA, addressB, addressC ]]
        const data = [ valueA, valueB ]

        const vm = new VM(program, data)
        const snapshot = vm.run()
        
        // Verify next program counter is addressC
        const currPc = vm.run(0).pc
        const nextPc = snapshot.pc
        expect(nextPc).toBe(addressC)
    })

    it('can execute BEQ instructions (Case: False)', function(){
        const addressA = 0
        const valueA = 42
        const addressB = 1
        const valueB = 43
        const addressC = 210
        const program = [[ ASM_BEQ, addressA, addressB, addressC ]]
        const data = [ valueA, valueB ]

        const vm = new VM(program, data)
        const snapshot = vm.run()
        
        // Verify next program counter is currPc + 1
        const currPc = vm.run(0).pc
        const nextPc = snapshot.pc
        expect(nextPc).toBe(currPc + 1)
    })


    it('can execute BNE instructions (Case: True)', function(){
        const addressA = 0
        const valueA = 42
        const addressB = 1
        const valueB = 43
        const addressC = 210
        const program = [[ ASM_BNE, addressA, addressB, addressC ]]
        const data = [ valueA, valueB ]

        const vm = new VM(program, data)
        const snapshot = vm.run()
        
        // Verify next program counter is addressC
        const currPc = vm.run(0).pc
        const nextPc = snapshot.pc
        expect(nextPc).toBe(addressC)
    })


    it('can execute BNE instructions (Case: False)', function(){
        const addressA = 0
        const valueA = 42
        const addressB = 1
        const valueB = 42
        const addressC = 210
        const program = [[ ASM_BNE, addressA, addressB, addressC ]]
        const data = [ valueA, valueB ]

        const vm = new VM(program, data)
        const snapshot = vm.run()
        
        // Verify next program counter is currPc + 1
        const currPc = vm.run(0).pc
        const nextPc = snapshot.pc
        expect(nextPc).toBe(currPc + 1)
    })

    it('can execute RSHIFT1 instructions', function(){
        const addressA = 0
        const valueA = 0x1100
        const addressC = 1
        const program = [[ ASM_RSHIFT1, addressA, 0, addressC ]]
        const data = [ valueA ]

        const vm = new VM(program, data)
        const snapshot = vm.run()
        
        // Verify result
        const valueC = snapshot.read(addressC)
        expect(valueC).toBe( toU32(valueA >>> 1) ) 

        // Verify program counter
        const currPc = vm.run(0).pc
        const nextPc = snapshot.pc
        expect(nextPc).toBe(currPc + 1)
    })

    it('can execute SLTU instructions (Result: 1)', function(){
        const addressA = 0
        const valueA = U32_SIZE - 2
        const addressB = 1
        const valueB = U32_SIZE - 1
        const addressC = 2
        const program = [[ ASM_SLTU, addressA, addressB, addressC ]]
        const data = [ valueA, valueB ]

        const vm = new VM(program, data)
        const snapshot = vm.run()
        
        // Verify result
        const valueC = snapshot.read(addressC)
        expect(valueC).toBe( 1 ) 

        // Verify program counter
        const currPc = vm.run(0).pc
        const nextPc = snapshot.pc
        expect(nextPc).toBe(currPc + 1)
    })

    it('can execute SLTU instructions (Result: 0)', function(){
        const addressA = 0
        const valueA = U32_SIZE - 1
        const addressB = 1
        const valueB = U32_SIZE - 2
        const addressC = 2
        const program = [[ ASM_SLTU, addressA, addressB, addressC ]]
        const data = [ valueA, valueB ]

        const vm = new VM(program, data)
        const snapshot = vm.run()
        
        // Verify result
        const valueC = snapshot.read(addressC)
        expect(valueC).toBe( 0 ) 

        // Verify program counter
        const currPc = vm.run(0).pc
        const nextPc = snapshot.pc
        expect(nextPc).toBe(currPc + 1)
    })

    it('can execute SLT instructions (Result: 1)', function(){
        const addressA = 0
        const valueA = 0xFFFFFFF9
        const addressB = 1
        const valueB = 0x00000001
        const addressC = 2
        const program = [[ ASM_SLT, addressA, addressB, addressC ]]
        const data = [ valueA, valueB ]

        const vm = new VM(program, data)
        const snapshot = vm.run()
        
        // Verify result
        const valueC = snapshot.read(addressC)
        expect(valueC).toBe( 1 ) 

        // Verify program counter
        const currPc = vm.run(0).pc
        const nextPc = snapshot.pc
        expect(nextPc).toBe(currPc + 1)
    })

    it('can execute SLT instructions (Result: 0)', function(){
        const addressA = 0
        const valueA = -5
        const addressB = 1
        const valueB = -7
        const addressC = 2
        const program = [[ ASM_SLT, addressA, addressB, addressC ]]
        const data = [ valueA, valueB ]

        const vm = new VM(program, data)
        const snapshot = vm.run()
        
        // Verify result
        const valueC = snapshot.read(addressC)
        expect(valueC).toBe( 0 ) 

        // Verify program counter
        const currPc = vm.run(0).pc
        const nextPc = snapshot.pc
        expect(nextPc).toBe(currPc + 1)
    })
})
