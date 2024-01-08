import { Leaf } from '../scripts/transaction.js'

describe('A Leaf', function () {

    it('can execute its script', function(){
        class DummyLeaf extends Leaf{
            lock(){
                return [OP_TRUE]
            }
            unlock(){
                return []
            }
        }

        const dummyLeaf = new DummyLeaf({}, 1, 2, 3)
        const result = dummyLeaf.canExecute()
        expect(result).toBeTrue()
    })

})
