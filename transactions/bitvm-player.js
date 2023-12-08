import { u160_state_unlock } from '../scripts/opcodes/u160_std.js'
import { bit_state_justice_unlock } from '../scripts/opcodes/u32_state.js'
import { Opponent } from '../scripts/player.js'
import { u32_state_unlock, u32_state_commit, u32_state, u8_state_commit, u8_state, u8_state_unlock, bit_state_commit, bit_state_unlock} from './opcodes/u32_state.js'

// Variables
const INSTRUCTION_VALUE_A = 'INSTRUCTION_VALUE_A'
const INSTRUCTION_ADDRESS_A = 'INSTRUCTION_ADDRESS_A'
const INSTRUCTION_VALUE_B = 'INSTRUCTION_VALUE_B'
const INSTRUCTION_ADDRESS_B = 'INSTRUCTION_ADDRESS_B'
const INSTRUCTION_VALUE_C = 'INSTRUCTION_VALUE_C'
const INSTRUCTION_ADDRESS_C = 'INSTRUCTION_ADDRESS_C'
const INSTRUCTION_PC_CURR = 'INSTRUCTION_PC_CURR'
const INSTRUCTION_PC_NEXT = 'INSTRUCTION_PC_NEXT'
const INSTRUCTION_TYPE = 'INSTRUCTION_TYPE'

class UnlockWrapperPaul {
	actor;

	constructor(actor) {
		this.actor = actor
	}
	// TODO have to put values into state before we can get them
	get valueA() {
		return u32_state_unlock(this.actor, INSTRUCTION_VALUE_A, this.actor.state.get_u32(INSTRUCTION_VALUE_A))
	}

	get valueB() {
		return u32_state_unlock(this.actor, INSTRUCTION_VALUE_B, this.actor.state.get_u32(INSTRUCTION_VALUE_B))
	}

	get valueC() {
		return u32_state_unlock(this.actor, INSTRUCTION_VALUE_C, this.actor.state.get_u32(INSTRUCTION_VALUE_C))
	}

	get addressA() {
		return u32_state_unlock(this.actor, INSTRUCTION_ADDRESS_A, this.actor.state.get_u32(INSTRUCTION_ADDRESS_A))
	}

	get addressB() {
		return u32_state_unlock(this.actor, INSTRUCTION_ADDRESS_B, this.actor.state.get_u32(INSTRUCTION_ADDRESS_B))
	}

	get addressC() {
		return u32_state_unlock(this.actor, INSTRUCTION_ADDRESS_C, this.actor.state.get_u32(INSTRUCTION_ADDRESS_C))
	}

	get pcCurr() {
		return u32_state_unlock(this.actor, INSTRUCTION_PC_CURR, this.actor.state.get_u32(INSTRUCTION_PC_CURR))
	}
	get pcNext() {
		return u32_state_unlock(this.actor, INSTRUCTION_PC_NEXT, this.actor.state.get_u32(INSTRUCTION_PC_NEXT))
	}
	get type() {
		return u8_state_unlock(this.actor, INSTRUCTION_TYPE, this.actor.state.get_u32(INSTRUCTION_TYPE))
	}

	get traceIndex() {
		let traceIndex = 0
		for (var i = 0; i < LOG_TRACE_LEN; i++) {
			const bit = this.actor.state.get_u1(TRACE_CHALLENGE(i))
			traceIndex += bit * 2 ** (LOG_TRACE_LEN - i)
		}
		return traceIndex
	}
}

class CommitWrapperPaul {
	actor;

	constructor(actor) {
		this.actor = actor
	}

	get valueA() {
		return u32_state_commit(this.actor, INSTRUCTION_VALUE_A)
	}

	get valueB() {
		return u32_state_commit(this.actor, INSTRUCTION_VALUE_B)
	}

	get valueC() {
		return u32_state_commit(this.actor, INSTRUCTION_VALUE_C)
	}

	get addressA() {
		return u32_state_commit(this.actor, INSTRUCTION_ADDRESS_A)
	}

	get addressB() {
		return u32_state_commit(this.actor, INSTRUCTION_ADDRESS_B)
	}

	get addressC() {
		return u32_state_commit(this.actor, INSTRUCTION_ADDRESS_C)
	}

	get pcCurr() {
		return u32_state_commit(this.actor, INSTRUCTION_PC_CURR)
	}
	get pcNext() {
		return u32_state_commit(this.actor, INSTRUCTION_PC_NEXT)
	}
	get type() {
		return u8_state_commit(this.actor, INSTRUCTION_TYPE)
	}
	
	u160_state(identifier) {
		return u160_state_unlock(this.actor, identifier, this.actor.state.get_u160(identifier))
	}
	//traceIndex() {
	//	let traceIndex = 0
	//	for (var i = 0; i < LOG_TRACE_LEN; i++) {
	//	    const bit = this.state.get_u1( TRACE_CHALLENGE(i) )
	//	    traceIndex += bit * 2 ** (LOG_TRACE_LEN - i)
	//	}
	//	return traceIndex
	//}
}

class PushWrapperPaul {
	actor;

	constructor(actor) {
		this.actor = actor
	}

	get valueA() {
		return u32_state(this.actor, INSTRUCTION_VALUE_A)
	}

	get valueB() {
		return u32_state(this.actor, INSTRUCTION_VALUE_B)
	}

	get valueC() {
		return u32_state(this.actor, INSTRUCTION_VALUE_C)
	}

	get addressA() {
		return u32_state(this.actor, INSTRUCTION_ADDRESS_A)
	}

	get addressB() {
		return u32_state(this.actor, INSTRUCTION_ADDRESS_B)
	}

	get addressC() {
		return u32_state(this.actor, INSTRUCTION_ADDRESS_C)
	}

	get pcCurr() {
		return u32_state(this.actor, INSTRUCTION_PC_CURR)
	}
	get pcNext() {
		return u32_state(this.actor, INSTRUCTION_PC_NEXT)
	}
	get type() {
		return u8_state(this.actor, INSTRUCTION_TYPE)
	}
}

class CommitWrapperVicky {
	actor;

	constructor(actor) {
		this.actor = actor
	}

	bit_state(identifier) {
		return bit_state_commit(this.actor, identifier)
	}
}

class UnlockWrapperVicky {
	actor;

	constructor(actor) {
		this.actor = actor
	}

	bit_state(identifier) {
		return bit_state_unlock(this.actor, identifier, this.actor.state.get_u1(identifier))
	}
}

class PushWrapperVicky {
	actor;

	constructor(actor) {
		this.actor = actor
	}
	
	bit_state(identifier) {
		return bit_state_justice_unlock(this.actor, identifier, this.actor.state.get_u1(identifier))
	}
}

export class PaulPlayer extends Player {
    constructor(secret) {
        super(secret, UnlockWrapperPaul, CommitWrapperPaul, PushWrapperPaul)
    }

}

export class PaulOpponent extends Opponent {
    constructor(hashes) {
        super(hashes, UnlockWrapperPaul, CommitWrapperPaul, PushWrapperPaul)
    }
}

export class VickyPlayer extends Player {
    constructor(secret) {
        super(secret, UnlockWrapperVicky, CommitWrapperVicky, PushWrapperVicky)
    }

}

export class VickyOpponent extends Opponent {
    constructor(hashes) {
        super(hashes, UnlockWrapperVicky, CommitWrapperVicky, PushWrapperVicky)
    }
}
