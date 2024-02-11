import {
    MerkleHashALeftLeaf,
    MerkleHashBLeftLeaf,
    MerkleHashARightLeaf,
    MerkleHashBRightLeaf,
    MerkleHashARootLeftLeaf,
    MerkleHashBRootLeftLeaf,
    MerkleHashARootRightLeaf,
    MerkleHashBRootRightLeaf,
    MerkleALeafHashLeftLeaf,
    MerkleBLeafHashLeftLeaf,
    MerkleALeafHashRightLeaf,
    MerkleBLeafHashRightLeaf,
} from '../bitvm/merkle/read.js'
import { PaulPlayer, VickyPlayer } from '../bitvm/model.js'
import { LOG_PATH_LEN, PATH_LEN, ASM_ADD } from '../bitvm/constants.js'
import { VM } from '../bitvm/vm.js'


const LOG_TRACE_LEN = 4
const program = [
    [ASM_ADD, 1, 0, 0], // Increment value at address 0 by value at address 1
    [ASM_BNE, 2, 0, 0], // If value at address 0 and value at address 2 are not equal, jump 1 line backwards
]
const data = [
    0,      // The initial value is 0
    1,      // The step size is 1
    10,     // We count up to 10
]


const PAUL_SECRET = 'd898098e09898a0980989b980809809809f09809884324874302975287524398'
const VICKY_SECRET = 'a9bd8b8ade888ed12301b21318a3a73429232343587049870132987481723497'

class DummyPaul extends PaulPlayer {
    constructor(vicky) {
        const vm = new VM(program, data)
        super(PAUL_SECRET, vicky, vm)
    }
}

class DummyVickyBase extends VickyPlayer {
    constructor() {
        super(VICKY_SECRET, null, null)
    }

    merkleChallengeA(roundIndex) {
        return Number(this.merkleIndexA.toString(2).replace('0b', '').padStart(LOG_PATH_LEN, '0')[roundIndex])
    }  

    merkleChallengeB(roundIndex) {
        return Number(this.merkleIndexB.toString(2).replace('0b', '').padStart(LOG_PATH_LEN, '0')[roundIndex])
    }  

    traceChallenge(roundIndex) {
        return Number(this.traceIndex.toString(2).replace('0b', '').padStart(LOG_TRACE_LEN, '0')[roundIndex])
    }
}

describe('MerkleHashLeaf', function() {

    it('can hash a left-hand side Merkle round (Operand: A)', function() {

        class DummyVicky extends DummyVickyBase {
            nextTraceIndex(roundIndex) {
                return [16, 8, 4, 2, 3][roundIndex]
            }

            nextMerkleIndexA(roundIndex) {
                return [16, 8, 4, 2, 3][roundIndex]
            }

            get traceIndex() {
                return 3
            }

            get merkleIndexA() {
                return 0b00011
            }
        }

        const dummyVicky = new DummyVicky()
        const dummyPaul = new DummyPaul(dummyVicky)
        const dummyLeaf = new MerkleHashALeftLeaf({}, dummyVicky, dummyPaul, dummyVicky.merkleIndexA)

        const result = dummyLeaf.runScript()
        const finalStack = result.get('final_stack')
        expect(result.get('error')).toBe('')
        expect(finalStack[0]).toBe('01')
        expect(finalStack.length).toBe(1)
    })

    it('can hash a left-hand side Merkle round (Operand: B)', function() {

        class DummyVicky extends DummyVickyBase {
            nextTraceIndex(roundIndex) {
                return [16, 8, 4, 2, 3][roundIndex]
            }

            nextMerkleIndexB(roundIndex) {
                return [16, 8, 4, 2, 3][roundIndex]
            }

            get traceIndex() {
                return 3
            }

            get merkleIndexB() {
                return 0b00011
            }
        }

        const dummyVicky = new DummyVicky()
        const dummyPaul = new DummyPaul(dummyVicky)
        const dummyLeaf = new MerkleHashBLeftLeaf({}, dummyVicky, dummyPaul, dummyVicky.merkleIndexB)

        const result = dummyLeaf.runScript()
        const finalStack = result.get('final_stack')
        expect(result.get('error')).toBe('')
        expect(finalStack[0]).toBe('01')
        expect(finalStack.length).toBe(1)
    })



    it('can hash a right-hand side Merkle round (Operand: A)', function() {
        
        class DummyVicky extends DummyVickyBase {

            nextTraceIndex(roundIndex) {
                return [0b10000, 0b01000, 0b00100, 0b00010, 0b00011][roundIndex]
            }

            nextMerkleIndexA(roundIndex) {
                return [0b10000, 0b11000, 0b11100, 0b11110, 0b11111][roundIndex]
            }

            get traceIndex() {
                return 0b00011
            }

            get merkleIndexA() {
                return 0b11110
            }
        }

        const dummyVicky = new DummyVicky()
        const dummyPaul = new DummyPaul(dummyVicky)
        const dummyLeaf = new MerkleHashARightLeaf({}, dummyVicky, dummyPaul, dummyVicky.merkleIndexA)

        const result = dummyLeaf.runScript()
        const finalStack = result.get('final_stack')
        expect(finalStack[0]).toBe('01')
        expect(finalStack.length).toBe(1)
    })



    it('can hash a right-hand side Merkle round (Operand: B)', function() {
        
        class DummyVicky extends DummyVickyBase {

            nextTraceIndex(roundIndex) {
                return [0b10000, 0b01000, 0b00100, 0b00010, 0b00011][roundIndex]
            }

            nextMerkleIndexB(roundIndex) {
                return [0b10000, 0b11000, 0b11100, 0b11110, 0b11111][roundIndex]
            }

            get traceIndex() {
                return 0b00011
            }

            get merkleIndexB() {
                return 0b11110
            }
        }

        class DummyPaul extends PaulPlayer {
            constructor(vicky) {
                const addressB = 3
                const program = [[ASM_ADD, 0, addressB, 0]]
                const data = []
                const vm = new VM(program, data)
                super(PAUL_SECRET, vicky, vm)
            }
        }

        const dummyVicky = new DummyVicky()
        const dummyPaul = new DummyPaul(dummyVicky)
        const dummyLeaf = new MerkleHashBRightLeaf({}, dummyVicky, dummyPaul, dummyVicky.merkleIndexB)

        const result = dummyLeaf.runScript()
        const finalStack = result.get('final_stack')
        expect(finalStack[0]).toBe('01')
        expect(finalStack.length).toBe(1)
    })



    it('can hash a left-hand side Merkle root (Operand: A)', function() {

        class DummyVicky extends DummyVickyBase {

            get traceIndex() {
                return 3
            }

            nextTraceIndex(roundIndex) {
                return [0b01000, 0b00100, 0b00010, 0b00011][roundIndex]
            }


            get merkleIndexA() {
                return 0b00000
            }

            nextMerkleIndexA(roundIndex) {
                return [0b10000, 0b01000, 0b00100, 0b00010, 0b00001][roundIndex]
            }

        }

        const dummyVicky = new DummyVicky()
        const dummyPaul = new DummyPaul(dummyVicky)
        const dummyLeaf = new MerkleHashARootLeftLeaf({}, dummyVicky, dummyPaul, 3)

        const result = dummyLeaf.runScript()
        const finalStack = result.get('final_stack')
        expect(result.get('error')).toBe('')
        expect(finalStack[0]).toBe('01')
        expect(finalStack.length).toBe(1)
    })



    it('can hash a left-hand side Merkle root (Operand: B)', function() {

        class DummyVicky extends DummyVickyBase {

            get traceIndex() {
                return 3
            }

            nextTraceIndex(roundIndex) {
                return [0b01000, 0b00100, 0b00010, 0b00011][roundIndex]
            }


            get merkleIndexB() {
                return 0b00000
            }

            nextMerkleIndexB(roundIndex) {
                return [0b10000, 0b01000, 0b00100, 0b00010, 0b00001][roundIndex]
            }

        }

        const dummyVicky = new DummyVicky()
        const dummyPaul = new DummyPaul(dummyVicky)
        const dummyLeaf = new MerkleHashBRootLeftLeaf({}, dummyVicky, dummyPaul, dummyVicky.traceIndex)

        const result = dummyLeaf.runScript()
        const finalStack = result.get('final_stack')
        expect(result.get('error')).toBe('')
        expect(finalStack[0]).toBe('01')
        expect(finalStack.length).toBe(1)
    })



    it('can hash a right-hand side Merkle root (Operand: A)', function() {

        class DummyVicky extends DummyVickyBase {

            get traceIndex() {
                return 3
            }

            nextTraceIndex(roundIndex) {
                return [0b10000, 0b01000, 0b00100, 0b00010, 0b00011][roundIndex]
            }

            get merkleIndexA() {
                return 0b00000
            }

            nextMerkleIndexA(roundIndex) {
                return [0b10000, 0b01000, 0b00100, 0b00010, 0b00001][roundIndex]
            }
        }

        class DummyPaul extends PaulPlayer {
            constructor(vicky) {
                const addressA = 2**(PATH_LEN-1)
                const program = [[ASM_ADD, addressA, 0, 0]]
                const data = []
                const vm = new VM(program, data)
                super(PAUL_SECRET, vicky, vm)
            }
        }

        const dummyVicky = new DummyVicky()
        const dummyPaul = new DummyPaul(dummyVicky)
        const dummyLeaf = new MerkleHashARootRightLeaf({}, dummyVicky, dummyPaul, dummyVicky.traceIndex)

        const result = dummyLeaf.runScript()
        console.log(result)
        const finalStack = result.get('final_stack')
        expect(result.get('error')).toBe('')
        expect(finalStack[0]).toBe('01')
        expect(finalStack.length).toBe(1)
    })


    it('can hash a right-hand side Merkle root (Operand: B)', function() {

        class DummyVicky extends DummyVickyBase {

            get traceIndex() {
                return 3
            }

            nextTraceIndex(roundIndex) {
                return [0b10000, 0b01000, 0b00100, 0b00010, 0b00011][roundIndex]
            }

            get merkleIndexB() {
                return 0b00000
            }

            nextMerkleIndexB(roundIndex) {
                return [0b10000, 0b01000, 0b00100, 0b00010, 0b00001][roundIndex]
            }
        }

        class DummyPaul extends PaulPlayer {
            constructor(vicky) {
                const addressB = 2**(PATH_LEN-1)
                const program = [[ASM_ADD, 0, addressB, 0]]
                const data = []
                const vm = new VM(program, data)
                super(PAUL_SECRET, vicky, vm)
            }
        }

        const dummyVicky = new DummyVicky()
        const dummyPaul = new DummyPaul(dummyVicky)
        const dummyLeaf = new MerkleHashBRootRightLeaf({}, dummyVicky, dummyPaul, dummyVicky.traceIndex)

        const result = dummyLeaf.runScript()
        console.log(result)
        const finalStack = result.get('final_stack')
        expect(result.get('error')).toBe('')
        expect(finalStack[0]).toBe('01')
        expect(finalStack.length).toBe(1)
    })



    it('can hash a left-hand side Merkle leaf (Operand: A)', function() {

        class DummyVicky extends DummyVickyBase {

            get traceIndex() {
                return 3
            }

            nextTraceIndex(roundIndex) {
                return [16, 8, 4, 2, 3][roundIndex]
            }

            get merkleIndexA() {
                return 0b11111
            }

            nextMerkleIndexA(roundIndex) {
                return [0b10000, 0b11000, 0b11100, 0b11110, 0b11111][roundIndex]
            }
        }

        const dummyVicky = new DummyVicky()
        const dummyPaul = new DummyPaul(dummyVicky)
        const dummyLeaf = new MerkleALeafHashLeftLeaf({}, dummyVicky, dummyPaul)

        const result = dummyLeaf.runScript()
        const finalStack = result.get('final_stack')
        expect(result.get('error')).toBe('')
        expect(finalStack[0]).toBe('01')
        expect(finalStack.length).toBe(1)
    })


    it('can hash a left-hand side Merkle leaf (Operand: B)', function() {

        class DummyVicky extends DummyVickyBase {

            get traceIndex() {
                return 3
            }

            nextTraceIndex(roundIndex) {
                return [16, 8, 4, 2, 3][roundIndex]
            }

            get merkleIndexB() {
                return 0b11111
            }

            nextMerkleIndexB(roundIndex) {
                return [0b10000, 0b11000, 0b11100, 0b11110, 0b11111][roundIndex]
            }
        }

        const dummyVicky = new DummyVicky()
        const dummyPaul = new DummyPaul(dummyVicky)
        const dummyLeaf = new MerkleBLeafHashLeftLeaf({}, dummyVicky, dummyPaul)

        const result = dummyLeaf.runScript()
        const finalStack = result.get('final_stack')
        expect(result.get('error')).toBe('')
        expect(finalStack[0]).toBe('01')
        expect(finalStack.length).toBe(1)
    })


    it('can hash a right-hand side Merkle leaf (Operand: A)', function() {

        class DummyVicky extends DummyVickyBase {

            get traceIndex() {
                return 3
            }

            nextTraceIndex(roundIndex) {
                return [16, 8, 4, 2, 3][roundIndex]
            }

            get merkleIndexA() {
                return 0b11111
            }

            nextMerkleIndexA(roundIndex) {
                return [0b10000, 0b11000, 0b11100, 0b11110, 0b11111][roundIndex]
            }
        }

        class DummyPaul extends PaulPlayer {
            constructor(vicky) {
                const addressA = 1
                const program = [[ASM_ADD, addressA, 0, 0]]
                const data = []
                const vm = new VM(program, data)
                super(PAUL_SECRET, vicky, vm)
            }
        }

        const dummyVicky = new DummyVicky()
        const dummyPaul = new DummyPaul(dummyVicky)
        const dummyLeaf = new MerkleALeafHashRightLeaf({}, dummyVicky, dummyPaul)

        const result = dummyLeaf.runScript()
        const finalStack = result.get('final_stack')
        expect(result.get('error')).toBe('')
        expect(finalStack[0]).toBe('01')
        expect(finalStack.length).toBe(1)
    })


    it('can hash a right-hand side Merkle leaf (Operand: B)', function() {

        class DummyVicky extends DummyVickyBase {

            get traceIndex() {
                return 3
            }

            nextTraceIndex(roundIndex) {
                return [16, 8, 4, 2, 3][roundIndex]
            }

            get merkleIndexB() {
                return 0b11111
            }

            nextMerkleIndexB(roundIndex) {
                return [0b10000, 0b11000, 0b11100, 0b11110, 0b11111][roundIndex]
            }
        }

        class DummyPaul extends PaulPlayer {
            constructor(vicky) {
                const addressB = 1
                const program = [[ASM_ADD, 0, addressB, 0]]
                const data = []
                const vm = new VM(program, data)
                super(PAUL_SECRET, vicky, vm)
            }
        }

        const dummyVicky = new DummyVicky()
        const dummyPaul = new DummyPaul(dummyVicky)
        const dummyLeaf = new MerkleBLeafHashRightLeaf({}, dummyVicky, dummyPaul)

        const result = dummyLeaf.runScript()
        const finalStack = result.get('final_stack')
        expect(result.get('error')).toBe('')
        expect(finalStack[0]).toBe('01')
        expect(finalStack.length).toBe(1)
    })
})
