import { Instruction, VM, toU32 } from '../bitvm/vm.js'
import {
    ASM_ADD, ASM_SUB, ASM_MUL, ASM_AND, ASM_OR,
    ASM_XOR,
    ASM_ADDI,
    ASM_SUBI,
    ASM_ANDI,
    ASM_ORI,
    ASM_XORI,
    ASM_JMP,
    ASM_RSHIFT1,
    ASM_RSHIFT8,
    ASM_SLTU,
    ASM_SLT,
    ASM_LOAD,
    ASM_STORE,
    ASM_SYSCALL,
    ASM_BEQ,
    ASM_BNE,
    U32_SIZE,
    MEMORY_LEN
} from '../bitvm/constants.js'


describe('The VM', function() {

    it('can execute ADD instructions', function() {
        const addressA = 0
        const valueA = U32_SIZE - 5
        const addressB = 1
        const valueB = 7
        const addressC = 2
        const program = [[ASM_ADD, addressA, addressB, addressC]]
        const data = [valueA, valueB]

        const vm = new VM(program, data)
        const snapshot = vm.run()

        // Verify result
        const valueC = snapshot.read(addressC)
        expect(valueC).toBe(2)

        // Verify program counter
        const currPc = vm.run(0).pc
        const nextPc = snapshot.pc
        expect(nextPc).toBe(currPc + 1)
    })

    it('can execute SUB instructions', function() {
        const addressA = 0
        const valueA = U32_SIZE - 3
        const addressB = 1
        const valueB = U32_SIZE - 5
        const addressC = 2
        const program = [[ASM_SUB, addressA, addressB, addressC]]
        const data = [valueA, valueB]

        const vm = new VM(program, data)
        const snapshot = vm.run()

        // Verify result
        const valueC = snapshot.read(addressC)
        expect(valueC).toBe(2)

        // Verify program counter
        const currPc = vm.run(0).pc
        const nextPc = snapshot.pc
        expect(nextPc).toBe(currPc + 1)
    })

    it('can execute SUB instructions ("negative" result)', function() {
        const addressA = 0
        const valueA = 3
        const addressB = 1
        const valueB = 5
        const addressC = 2
        const program = [[ASM_SUB, addressA, addressB, addressC]]
        const data = [valueA, valueB]

        const vm = new VM(program, data)
        const snapshot = vm.run()

        // Verify result
        const valueC = snapshot.read(addressC)
        expect(valueC).toBe(U32_SIZE - 2)

        // Verify program counter
        const currPc = vm.run(0).pc
        const nextPc = snapshot.pc
        expect(nextPc).toBe(currPc + 1)
    })

    it('can execute MUL instructions', function() {
        const addressA = 0
        const valueA = U32_SIZE - 5
        const addressB = 1
        const valueB = 32
        const addressC = 2
        const program = [[ASM_MUL, addressA, addressB, addressC]]
        const data = [valueA, valueB]

        const vm = new VM(program, data)
        const snapshot = vm.run()

        // Verify result
        const valueC = snapshot.read(addressC)
        expect(valueC).toBe(U32_SIZE - 160)

        // Verify program counter
        const currPc = vm.run(0).pc
        const nextPc = snapshot.pc
        expect(nextPc).toBe(currPc + 1)
    })

    it('can execute AND instructions', function() {
        const addressA = 0
        const valueA = 0b1100
        const addressB = 1
        const valueB = 0b0101
        const addressC = 2
        const program = [[ASM_AND, addressA, addressB, addressC]]
        const data = [valueA, valueB]

        const vm = new VM(program, data)
        const snapshot = vm.run()

        // Verify result
        const valueC = snapshot.read(addressC)
        expect(valueC).toBe(0b0100)

        // Verify program counter
        const currPc = vm.run(0).pc
        const nextPc = snapshot.pc
        expect(nextPc).toBe(currPc + 1)
    })

    it('can execute OR instructions', function() {
        const addressA = 0
        const valueA = 0b1100
        const addressB = 1
        const valueB = 0b0101
        const addressC = 2
        const program = [[ASM_OR, addressA, addressB, addressC]]
        const data = [valueA, valueB]

        const vm = new VM(program, data)
        const snapshot = vm.run()

        // Verify result
        const valueC = snapshot.read(addressC)
        expect(valueC).toBe(0b1101)

        // Verify program counter
        const currPc = vm.run(0).pc
        const nextPc = snapshot.pc
        expect(nextPc).toBe(currPc + 1)
    })

    it('can execute XOR instructions', function() {
        const addressA = 0
        const valueA = 0b1100
        const addressB = 1
        const valueB = 0b0101
        const addressC = 2
        const program = [[ASM_XOR, addressA, addressB, addressC]]
        const data = [valueA, valueB]

        const vm = new VM(program, data)
        const snapshot = vm.run()

        // Verify result
        const valueC = snapshot.read(addressC)
        expect(valueC).toBe(0b1001)

        // Verify program counter
        const currPc = vm.run(0).pc
        const nextPc = snapshot.pc
        expect(nextPc).toBe(currPc + 1)
    })

    it('can execute ADDI instructions', function() {
        const addressA = 0
        const valueA = U32_SIZE - 5
        const addressB = 7
        const addressC = 1
        const program = [[ASM_ADDI, addressA, addressB, addressC]]
        const data = [valueA]

        const vm = new VM(program, data)
        const snapshot = vm.run()

        // Verify result
        const valueC = snapshot.read(addressC)
        expect(valueC).toBe(2)

        // Verify program counter
        const currPc = vm.run(0).pc
        const nextPc = snapshot.pc
        expect(nextPc).toBe(currPc + 1)
    })

    it('can execute SUBI instructions', function() {
        const addressA = 0
        const valueA = 42
        const addressB = 43
        const addressC = 2
        const program = [[ASM_SUBI, addressA, addressB, addressC]]
        const data = [valueA]

        const vm = new VM(program, data)
        const snapshot = vm.run()

        // Verify result
        const valueC = snapshot.read(addressC)
        expect(valueC).toBe(U32_SIZE - 1)

        // Verify program counter
        const currPc = vm.run(0).pc
        const nextPc = snapshot.pc
        expect(nextPc).toBe(currPc + 1)
    })

    it('can execute ANDI instructions', function() {
        const addressA = 0
        const valueA = 0b1100
        const addressB = 0b0101
        const addressC = 2
        const program = [[ASM_ANDI, addressA, addressB, addressC]]
        const data = [valueA]

        const vm = new VM(program, data)
        const snapshot = vm.run()

        // Verify result
        const valueC = snapshot.read(addressC)
        expect(valueC).toBe(0b0100)

        // Verify program counter
        const currPc = vm.run(0).pc
        const nextPc = snapshot.pc
        expect(nextPc).toBe(currPc + 1)
    })

    it('can execute ORI instructions', function() {
        const addressA = 0
        const valueA = 0b1100
        const addressB = 0b0101
        const addressC = 2
        const program = [[ASM_ORI, addressA, addressB, addressC]]
        const data = [valueA]

        const vm = new VM(program, data)
        const snapshot = vm.run()

        // Verify result
        const valueC = snapshot.read(addressC)
        expect(valueC).toBe(0b1101)

        // Verify program counter
        const currPc = vm.run(0).pc
        const nextPc = snapshot.pc
        expect(nextPc).toBe(currPc + 1)
    })

    it('can execute XORI instructions', function() {
        const addressA = 0
        const valueA = 0b1100
        const addressB = 0b0101
        const addressC = 2
        const program = [[ASM_XORI, addressA, addressB, addressC]]
        const data = [valueA]

        const vm = new VM(program, data)
        const snapshot = vm.run()

        // Verify result
        const valueC = snapshot.read(addressC)
        expect(valueC).toBe(0b1001)

        // Verify program counter
        const currPc = vm.run(0).pc
        const nextPc = snapshot.pc
        expect(nextPc).toBe(currPc + 1)
    })
    it('can execute BEQ instructions (Case: True)', function() {
        const addressA = 0
        const valueA = 42
        const addressB = 1
        const valueB = 42
        const addressC = 210
        const program = [[ASM_BEQ, addressA, addressB, addressC]]
        const data = [valueA, valueB]

        const vm = new VM(program, data)
        const snapshot = vm.run()

        // Verify next program counter is addressC
        const currPc = vm.run(0).pc
        const nextPc = snapshot.pc
        expect(nextPc).toBe(addressC)
    })

    it('can execute BEQ instructions (Case: False)', function() {
        const addressA = 0
        const valueA = 42
        const addressB = 1
        const valueB = 43
        const addressC = 210
        const program = [[ASM_BEQ, addressA, addressB, addressC]]
        const data = [valueA, valueB]

        const vm = new VM(program, data)
        const snapshot = vm.run()

        // Verify next program counter is currPc + 1
        const currPc = vm.run(0).pc
        const nextPc = snapshot.pc
        expect(nextPc).toBe(currPc + 1)
    })

    it('can execute BNE instructions (Case: True)', function() {
        const addressA = 0
        const valueA = 42
        const addressB = 1
        const valueB = 43
        const addressC = 210
        const program = [[ASM_BNE, addressA, addressB, addressC]]
        const data = [valueA, valueB]

        const vm = new VM(program, data)
        const snapshot = vm.run()

        // Verify next program counter is addressC
        const currPc = vm.run(0).pc
        const nextPc = snapshot.pc
        expect(nextPc).toBe(addressC)
    })

    it('can execute BNE instructions (Case: False)', function() {
        const addressA = 0
        const valueA = 42
        const addressB = 1
        const valueB = 42
        const addressC = 210
        const program = [[ASM_BNE, addressA, addressB, addressC]]
        const data = [valueA, valueB]

        const vm = new VM(program, data)
        const snapshot = vm.run()

        // Verify next program counter is currPc + 1
        const currPc = vm.run(0).pc
        const nextPc = snapshot.pc
        expect(nextPc).toBe(currPc + 1)
    })

    it('can execute JMP instructions', function() {
        const addressA = 0
        const valueA = 42
        const program = [[ASM_JMP, addressA, NaN, NaN]]
        const data = [valueA]

        const vm = new VM(program, data)
        const snapshot = vm.run()

        // Verify next program counter is valueA
        const nextPc = snapshot.pc
        expect(nextPc).toBe(valueA)
    })

    it('can execute RSHIFT1 instructions', function() {
        const addressA = 0
        const valueA = 0b1100
        const addressC = 1
        const program = [[ASM_RSHIFT1, addressA, 0, addressC]]
        const data = [valueA]

        const vm = new VM(program, data)
        const snapshot = vm.run()

        // Verify result
        const valueC = snapshot.read(addressC)
        expect(valueC).toBe(0b0110)

        // Verify program counter
        const currPc = vm.run(0).pc
        const nextPc = snapshot.pc
        expect(nextPc).toBe(currPc + 1)
    })

    it('can execute RSHIFT8 instructions', function() {
        const addressA = 0
        const valueA = 0xFEED4321
        const addressC = 1
        const program = [[ASM_RSHIFT8, addressA, 0, addressC]]
        const data = [valueA]

        const vm = new VM(program, data)
        const snapshot = vm.run()

        // Verify result
        const valueC = snapshot.read(addressC)
        expect(valueC).toBe(0x00FEED43)

        // Verify program counter
        const currPc = vm.run(0).pc
        const nextPc = snapshot.pc
        expect(nextPc).toBe(currPc + 1)
    })

    it('can execute SLTU instructions (Result: 1)', function() {
        const addressA = 0
        const valueA = U32_SIZE - 2
        const addressB = 1
        const valueB = U32_SIZE - 1
        const addressC = 2
        const program = [[ASM_SLTU, addressA, addressB, addressC]]
        const data = [valueA, valueB]

        const vm = new VM(program, data)
        const snapshot = vm.run()

        // Verify result
        const valueC = snapshot.read(addressC)
        expect(valueC).toBe(1)

        // Verify program counter
        const currPc = vm.run(0).pc
        const nextPc = snapshot.pc
        expect(nextPc).toBe(currPc + 1)
    })

    it('can execute SLTU instructions (Result: 0)', function() {
        const addressA = 0
        const valueA = U32_SIZE - 1
        const addressB = 1
        const valueB = U32_SIZE - 2
        const addressC = 2
        const program = [[ASM_SLTU, addressA, addressB, addressC]]
        const data = [valueA, valueB]

        const vm = new VM(program, data)
        const snapshot = vm.run()

        // Verify result
        const valueC = snapshot.read(addressC)
        expect(valueC).toBe(0)

        // Verify program counter
        const currPc = vm.run(0).pc
        const nextPc = snapshot.pc
        expect(nextPc).toBe(currPc + 1)
    })

    it('can execute SLT instructions (Result: 1)', function() {
        const addressA = 0
        const valueA = 0xFFFFFFF9
        const addressB = 1
        const valueB = 0x00000001
        const addressC = 2
        const program = [[ASM_SLT, addressA, addressB, addressC]]
        const data = [valueA, valueB]

        const vm = new VM(program, data)
        const snapshot = vm.run()

        // Verify result
        const valueC = snapshot.read(addressC)
        expect(valueC).toBe(1)

        // Verify program counter
        const currPc = vm.run(0).pc
        const nextPc = snapshot.pc
        expect(nextPc).toBe(currPc + 1)
    })

    it('can execute SLT instructions (Result: 0)', function() {
        const addressA = 0
        const valueA = -5
        const addressB = 1
        const valueB = -7
        const addressC = 2
        const program = [[ASM_SLT, addressA, addressB, addressC]]
        const data = [valueA, valueB]

        const vm = new VM(program, data)
        const snapshot = vm.run()

        // Verify result
        const valueC = snapshot.read(addressC)
        expect(valueC).toBe(0)

        // Verify program counter
        const currPc = vm.run(0).pc
        const nextPc = snapshot.pc
        expect(nextPc).toBe(currPc + 1)
    })

    it('can execute LOAD instructions', function() {
        // addressA is figured out at runtime from valueB -> addressA == valueB
        // valueA is loaded
        const valueA = 0x89ABCDEF
        const addressB = 0
        // Specifies where the address is stored
        const valueB = 17
        const addressC = 1
        const program = [[ASM_LOAD, NaN, addressB, addressC]]
        const data = [valueB, ...Array(valueB - 1).fill(0), valueA]

        const vm = new VM(program, data)
        const snapshot = vm.run()

        // Verify result
        const valueC = snapshot.read(addressC)
        expect(valueC).toBe(0x89ABCDEF)

        // Verify that the instruction correctly sets addressA
        const addressA = snapshot.instruction.addressA
        expect(addressA).toBe(valueB)

        // Verify program counter
        const currPc = vm.run(0).pc
        const nextPc = snapshot.pc
        expect(nextPc).toBe(currPc + 1)
    })

    it('can execute STORE instructions', function() {
        // addressC is figured out at runtime from valueB -> addressC == valueB
        // valueA is stored
        const addressA = 0
        const valueA = 0x89ABCDEF
        const addressB = 1
        // Specifies where the address is stored
        const valueB = 17
        const program = [[ASM_STORE, addressA, addressB, NaN]]
        const data = [valueA, valueB, ...Array(valueB - 2).fill(0), NaN]

        const vm = new VM(program, data)
        const snapshot = vm.run()

        // Verify that the instruction correctly sets addressC
        const addressC = snapshot.instruction.addressC
        expect(addressC).toBe(17)

        // Verify result
        const valueC = snapshot.read(addressC)
        expect(valueC).toBe(0x89ABCDEF)

        // Verify program counter
        const currPc = vm.run(0).pc
        const nextPc = snapshot.pc
        expect(nextPc).toBe(currPc + 1)
    })

    it('can merklize its memory', function() {
        const addressA = 1  // TODO: set this to some random address, e.g., 42
        const valueA = 42
        const addressB = 0
        const valueB = 43
        const addressC = 2
        const program = [[ASM_ADD, addressA, addressB, addressC]]
        const data = [valueA, valueB]

        const vm = new VM(program, data)
        const snapshot = vm.run()

        const pathRoot = snapshot.path(addressA).verifyUpTo(0)

        expect(pathRoot).toBe(snapshot.root)
    })

    it('can execute a rv32i program (testcase simple)', async function() {
        await fetch("../run/rv32i_programs/rv32ui-bitvm-simple.json")
            .then((res) => {
                if (!res.ok) {
                    throw new Error
                        (`HTTP error! Status: ${res.status}`);
                }
                return res.json();
            })
            .then(data => {
                let { program, memory } = data
                program = eval(program)

                const vm = new VM(program, memory)
                const snapshot = vm.run(25)

                expect(snapshot.read(132)).toBe(1)
                expect(snapshot.read(112)).toBe(0)
            })
            .catch((error) =>
                console.error("Unable to fetch data:", error));
    })
})

// TODO: Theses tests will fail because the program data is not checked into git
//       Have to host them somewhere
describe('rv32ui emulation', function() {
    function rv32ui_test(name, expected_passes, programFile) {
        it(`${name} opcode`, async function() {
            await fetch(programFile)
                .then((res) => {
                    if (!res.ok) {
                        throw new Error
                            (`HTTP error! Status: ${res.status}`);
                    }
                    return res.json();
                })
                .then(data => {
                    let { program, memory } = data
                    program = eval(program)

                    const vm = new VM(program, memory)
                    const snapshot = vm.run(2 ** 14)

                    expect(snapshot.read(132)).toBe(1)
                    expect(snapshot.read(112)).toBe(expected_passes)
                    expect(snapshot.pc).toBe(program.length)
                })
                .catch((error) =>
                    console.error("Unable to fetch data:", error));
        })
    }

    rv32ui_test("ADD", 38, "../run/rv32i_programs/rv32ui-bitvm-add.json")
    rv32ui_test("ADDI", 25, "../run/rv32i_programs/rv32ui-bitvm-addi.json")
    rv32ui_test("AND", 27, "../run/rv32i_programs/rv32ui-bitvm-and.json")
    rv32ui_test("ANDI", 14, "../run/rv32i_programs/rv32ui-bitvm-andi.json")
    rv32ui_test("AUIPC", 3, "../run/rv32i_programs/rv32ui-bitvm-auipc.json")
    rv32ui_test("BEQ", 21, "../run/rv32i_programs/rv32ui-bitvm-beq.json")
    rv32ui_test("BGE", 24, "../run/rv32i_programs/rv32ui-bitvm-bge.json")
    rv32ui_test("BGEU", 24, "../run/rv32i_programs/rv32ui-bitvm-bgeu.json")
    rv32ui_test("JALR", 7, "../run/rv32i_programs/rv32ui-bitvm-jalr.json")
    rv32ui_test("LB", 19, "../run/rv32i_programs/rv32ui-bitvm-lb.json")
    rv32ui_test("LBU", 19, "../run/rv32i_programs/rv32ui-bitvm-lbu.json")
    rv32ui_test("LH", 19, "../run/rv32i_programs/rv32ui-bitvm-lh.json")
    rv32ui_test("LHU", 19, "../run/rv32i_programs/rv32ui-bitvm-lhu.json")
    rv32ui_test("LUI", 6, "../run/rv32i_programs/rv32ui-bitvm-lui.json")
    rv32ui_test("OR", 27, "../run/rv32i_programs/rv32ui-bitvm-or.json")
    rv32ui_test("SB", 23, "../run/rv32i_programs/rv32ui-bitvm-sb.json")
    rv32ui_test("SH", 23, "../run/rv32i_programs/rv32ui-bitvm-sh.json")
    rv32ui_test("SLL", 43, "../run/rv32i_programs/rv32ui-bitvm-sll.json")
    rv32ui_test("SLLI", 25, "../run/rv32i_programs/rv32ui-bitvm-slli.json")
    rv32ui_test("SLTI", 25, "../run/rv32i_programs/rv32ui-bitvm-slti.json")
    rv32ui_test("SLTIU", 25, "../run/rv32i_programs/rv32ui-bitvm-sltiu.json")
    rv32ui_test("SRA", 43, "../run/rv32i_programs/rv32ui-bitvm-sra.json")
    rv32ui_test("SRAI", 25, "../run/rv32i_programs/rv32ui-bitvm-srai.json")
    rv32ui_test("SRLI", 25, "../run/rv32i_programs/rv32ui-bitvm-srli.json")
    rv32ui_test("SUB", 37, "../run/rv32i_programs/rv32ui-bitvm-sub.json")
    rv32ui_test("SW", 23, "../run/rv32i_programs/rv32ui-bitvm-sw.json")
    rv32ui_test("XOR", 27, "../run/rv32i_programs/rv32ui-bitvm-xor.json")
    rv32ui_test("XORI", 14, "../run/rv32i_programs/rv32ui-bitvm-xori.json")
})


