import {
    MerkleHashLeftLeaf,
    MerkleHashRightLeaf,
    MerkleHashRootLeftLeaf,
    MerkleHashRootRightLeaf,
    MerkleLeafHashLeftLeaf,
    MerkleLeafHashRightLeaf
} from '../bitvm/merkle-sequence.js'
import { PaulPlayer, VickyPlayer } from '../bitvm/bitvm-player.js'
import { LOG_TRACE_LEN, LOG_PATH_LEN, PATH_LEN, ASM_ADD } from '../bitvm/constants.js'
import { VM } from '../bitvm/vm.js'
import { program, data } from '../run/dummy-program.js'

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

    merkleChallenge(roundIndex) {
        return Number(this.merkleIndex.toString(2).replace('0b', '').padStart(5, '0')[roundIndex])
    }  

    traceChallenge(roundIndex) {
        return Number(this.traceIndex.toString(2).replace('0b', '').padStart(LOG_TRACE_LEN, '0')[roundIndex])
    }
}

describe('MerkleHashLeaf', function() {

    it('can hash a left-hand side Merkle round', function() {

        class DummyVicky extends DummyVickyBase {
            nextTraceIndex(roundIndex) {
                return [16, 8, 4, 2, 3][roundIndex]
            }

            nextMerkleIndex(roundIndex) {
                return [16, 8, 4, 2, 3][roundIndex]
            }

            get traceIndex() {
                return 3
            }

            get merkleIndex() {
                return 0b00011
            }
        }

        const dummyVicky = new DummyVicky()
        const dummyPaul = new DummyPaul(dummyVicky)
        const dummyLeaf = new MerkleHashLeftLeaf({}, dummyVicky, dummyPaul, dummyVicky.merkleIndex)

        const result = dummyLeaf.runScript()
        const finalStack = result.get('final_stack')
        expect(result.get('error')).toBe('')
        expect(finalStack[0]).toBe('01')
        expect(finalStack.length).toBe(1)
    })



    it('can hash a right-hand side Merkle round', function() {
        
        class DummyVicky extends DummyVickyBase {

            nextTraceIndex(roundIndex) {
                return [0b10000, 0b01000, 0b00100, 0b00010, 0b00011][roundIndex]
            }

            nextMerkleIndex(roundIndex) {
                return [0b10000, 0b11000, 0b11100, 0b11110, 0b11111][roundIndex]
            }

            get traceIndex() {
                return 0b00011
            }

            get merkleIndex() {
                return 0b11110
            }
        }

        const dummyVicky = new DummyVicky()
        const dummyPaul = new DummyPaul(dummyVicky)
        const dummyLeaf = new MerkleHashRightLeaf({}, dummyVicky, dummyPaul, dummyVicky.merkleIndex)

        const result = dummyLeaf.runScript()
        const finalStack = result.get('final_stack')
        expect(finalStack[0]).toBe('01')
        expect(finalStack.length).toBe(1)
    })



    it('can hash a left-hand side Merkle root', function() {

        class DummyVicky extends DummyVickyBase {

            get traceIndex() {
                return 3
            }

            nextTraceIndex(roundIndex) {
                return [0b10000, 0b01000, 0b00100, 0b00010, 0b00011][roundIndex]
            }


            get merkleIndex() {
                return 0b00000
            }

            nextMerkleIndex(roundIndex) {
                return [0b10000, 0b01000, 0b00100, 0b00010, 0b00001][roundIndex]
            }

        }

        const dummyVicky = new DummyVicky()
        const dummyPaul = new DummyPaul(dummyVicky)
        const dummyLeaf = new MerkleHashRootLeftLeaf({}, dummyVicky, dummyPaul, dummyVicky.traceIndex)

        const result = dummyLeaf.runScript()
        const finalStack = result.get('final_stack')
        expect(result.get('error')).toBe('')
        expect(finalStack[0]).toBe('01')
        expect(finalStack.length).toBe(1)
    })



    it('can hash a right-hand side Merkle root', function() {

        class DummyVicky extends DummyVickyBase {

            get traceIndex() {
                return 3
            }

            nextTraceIndex(roundIndex) {
                return [0b10000, 0b01000, 0b00100, 0b00010, 0b00011][roundIndex]
            }

            get merkleIndex() {
                return 0b00000
            }

            nextMerkleIndex(roundIndex) {
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
        const dummyLeaf = new MerkleHashRootRightLeaf({}, dummyVicky, dummyPaul, dummyVicky.traceIndex)

        const result = dummyLeaf.runScript()
        console.log(result)
        const finalStack = result.get('final_stack')
        expect(result.get('error')).toBe('')
        expect(finalStack[0]).toBe('01')
        expect(finalStack.length).toBe(1)
    })



    it('can hash a left-hand side Merkle leaf', function() {

        class DummyVicky extends DummyVickyBase {

            get traceIndex() {
                return 3
            }

            nextTraceIndex(roundIndex) {
                return [16, 8, 4, 2, 3][roundIndex]
            }

            get merkleIndex() {
                return 0b11111
            }

            nextMerkleIndex(roundIndex) {
                return [0b10000, 0b11000, 0b11100, 0b11110, 0b11111][roundIndex]
            }
        }

        const dummyVicky = new DummyVicky()
        const dummyPaul = new DummyPaul(dummyVicky)
        const dummyLeaf = new MerkleLeafHashLeftLeaf({}, dummyVicky, dummyPaul)

        const result = dummyLeaf.runScript()
        const finalStack = result.get('final_stack')
        expect(result.get('error')).toBe('')
        expect(finalStack[0]).toBe('01')
        expect(finalStack.length).toBe(1)
    })

    it('can hash a right-hand side Merkle leaf', function() {

        class DummyVicky extends DummyVickyBase {

            get traceIndex() {
                return 3
            }

            nextTraceIndex(roundIndex) {
                return [16, 8, 4, 2, 3][roundIndex]
            }

            get merkleIndex() {
                return 0b11111
            }

            nextMerkleIndex(roundIndex) {
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
        const dummyLeaf = new MerkleLeafHashRightLeaf({}, dummyVicky, dummyPaul)

        const result = dummyLeaf.runScript()
        const finalStack = result.get('final_stack')
        expect(result.get('error')).toBe('')
        expect(finalStack[0]).toBe('01')
        expect(finalStack.length).toBe(1)
    })
})