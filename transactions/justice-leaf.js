import { u2_state_unlock, u2_state_justice } from '../scripts/opcodes/u32_state.js'
import { Leaf } from './transaction.js'


class U2StateJusticeLeaf extends Leaf {
    lock(actor, victim, identifier, index) {
        return [
            ...u2_state_justice(actor, identifier, index),
            victim.pubkey,
            OP_CHECKSIG,
        ]
    }

    unlock(actor, victim, identifier, index, valueA, valueB){
        if (valueA >= valueB) throw `Error: valueA >= valueB`
        return [ 
            victim.sign(this),
            u2_state_unlock(actor, identifier, valueA, index),
            u2_state_unlock(actor, identifier, valueB, index),
        ]
    }
}


export const u8_state_justice_leaves = (actor, victim, identifier) => [
	[U2StateJusticeLeaf, actor, victim, identifier, 3],
	[U2StateJusticeLeaf, actor, victim, identifier, 2],
	[U2StateJusticeLeaf, actor, victim, identifier, 1],
	[U2StateJusticeLeaf, actor, victim, identifier, 0],
]


export const u32_state_justice_leaves = (actor, victim, identifier) => [
	...u8_state_justice_leaves(actor, victim, identifier + '_byte0'),
	...u8_state_justice_leaves(actor, victim, identifier + '_byte1'),
	...u8_state_justice_leaves(actor, victim, identifier + '_byte2'),
	...u8_state_justice_leaves(actor, victim, identifier + '_byte3'),
]



export const u160_state_justice_leaves = (actor, victim, identifier) => [
    ...u32_state_justice_leaves(actor, victim, identifier + '_5'),
    ...u32_state_justice_leaves(actor, victim, identifier + '_4'),
    ...u32_state_justice_leaves(actor, victim, identifier + '_3'),
    ...u32_state_justice_leaves(actor, victim, identifier + '_2'),
    ...u32_state_justice_leaves(actor, victim, identifier + '_1')
]