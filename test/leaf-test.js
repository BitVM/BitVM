import { Leaf } from '../transactions/transaction.js'

describe('InstructionCommitLeafs', function () {

    it('can run its script', function(){
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
        console.log(result)
    })

})
