import { VM, toU32 } from '../bitvm/vm.js'
import { ASM_ADD, ASM_SUB, ASM_MUL, ASM_JMP, ASM_BEQ, ASM_BNE, U32_SIZE } from '../bitvm/constants.js'
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
})
