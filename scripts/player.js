import { keys } from '../libs/crypto_tools.js'
import { ripemd160 } from '../libs/ripemd160.js'
import { toHex, fromUnicode, fromHex } from '../libs/bytes.js'
import { Tx, Signer } from '../libs/tapscript.js'
import { u32_state_unlock, u32_state_commit, u32_state, u8_state_commit, u8_state, u8_state_unlock } from './opcodes/u32_state.js'

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

function toPublicKey(secret) {
	// Drop the first byte of the pubkey
	return toHex(keys.get_pubkey(secret)).slice(2)
}

const hash = buffer => ripemd160(buffer)

const PREIMAGE_SIZE = 20
const PREIMAGE_SIZE_HEX = PREIMAGE_SIZE * 2

const DELIMITER = '='

const hashId = (identifier, index, value = 0) => {
	// TODO: ensure there's no DELIMITER in identifier, index, or value
	if (index === undefined)
		return `${identifier}${DELIMITER}${value}`
	return `${identifier}_${index}${DELIMITER}${value}`
}

const toCommitmentId = (identifier, index) => {
	if (index === undefined)
		return `${identifier}`
	return `${identifier}_${index}`
}

const parseHashId = hashId => {
	if (!hashId)
		throw Error('hashId is undefined')
	const [commitmentId, value] = hashId.split(DELIMITER)
	return { commitmentId, value }
}

const _preimage = (secret, hashId) =>
	hash(fromUnicode(secret + hashId))

const _hashLock = (secret, hashId) =>
	toHex(hash(_preimage(secret, hashId)))

const preimage = (secret, identifier, index, value) =>
	toHex(_preimage(secret, hashId(identifier, index, value)))

const hashLock = (secret, identifier, index, value) =>
	toHex(hash(_preimage(secret, hashId(identifier, index, value))))


class UnlockWrapper {
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

class CommitWrapper {
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
	//traceIndex() {
	//	let traceIndex = 0
	//	for (var i = 0; i < LOG_TRACE_LEN; i++) {
	//	    const bit = this.state.get_u1( TRACE_CHALLENGE(i) )
	//	    traceIndex += bit * 2 ** (LOG_TRACE_LEN - i)
	//	}
	//	return traceIndex
	//}
}

class CommitStackWrapper {
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

class Actor {
	unlock;
	commit;
	commit_stack;

	constructor() {
		this.unlock = new UnlockWrapper(this)
		this.commit = new CommitWrapper(this)
		this.commit_stack = new CommitStackWrapper(this)
	}


}

export class Player extends Actor {
	#secret;
	hashes = {};
	state;

	constructor(secret, state = new State()) {
		super()
		this.#secret = secret;
		// TODO: make the seckey private too. Add a sign function instead
		this.seckey = keys.get_seckey(secret)
		this.pubkey = toPublicKey(this.seckey)
		this.hashes.pubkey = this.pubkey
		this.state = state
	}

	//TODO: REMOVE debug code
	print_state() {
		console.log(state)
	}

	hashlock(identifier, index, value) {
		const hash = hashLock(this.#secret, identifier, index, value)
		this.hashes[hashId(identifier, index, value)] = hash
		return hash
	}

	preimage(identifier, index, value) {
		const commitmentId = toCommitmentId(identifier, index)
		this.state.set(commitmentId, value)
		return preimage(this.#secret, identifier, index, value)
	}

	sign(leaf, inputIndex = 0) {
		const tx = leaf.tx.tx()
		const extension = leaf.encodedLockingScript
		return Signer.taproot.sign(this.seckey, tx, inputIndex, { extension }).hex
	}

	computeHashes(hashIds) {
		return hashIds.reduce((result, hashId) => {
			result[hashId] = _hashLock(this.#secret, hashId)
			return result
		}, {})
	}
}

class EquivocationError extends Error {
	constructor(preimageA, preimageB) {
		super(`Equivocation ${preimageA} ${preimageB}`);
		this.name = 'EquivocationError';
	}
}

export class Opponent extends Actor {
	#idToHash;
	#hashToId;
	#preimages = {};
	#commitments = {};
	state

	onstructor(hashes, state = new State()) {
		super()
		this.#idToHash = hashes
		this.#hashToId = Object.keys(hashes).reduce((accu, hashId) => {
			accu[hashes[hashId]] = hashId
			return accu
		}, {})
		this.state = state
	}

	hashlock(identifier, index, value) {
		const id = hashId(identifier, index, value)
		const hash = this.#idToHash[id]
		if (!hash)
			throw `Hash for ${id} is not known`
		return hash
	}

	preimage(identifier, index, value) {
		const id = hashId(identifier, index, value)
		const preimage = this.#preimages[id]
		if (!preimage)
			throw `Preimage of ${id} is not known`
		return preimage
	}

	learnPreimage(preimage) {
		const hash = toHex(ripemd160(fromHex(preimage)))
		const id = this.#hashToId[hash]
		if (!id)
			return console.log('discarding', hash)

		this.#preimages[id] = preimage

		const { commitmentId, value } = parseHashId(id)


		// Check if we know some conflicting preimage
		const prevPreimage = this.#commitments[commitmentId]
		if (!prevPreimage) {
			this.#commitments[commitmentId] = preimage
			this.state.set(commitmentId, value)
			return
		}

		if (preimage != prevPreimage)
			throw new EquivocationError(prevPreimage, preimage)
	}

	processTx(txHex) {
		const tx = Tx.decode(txHex)

		// Read the preimages
		const preimages = tx.vin[0].witness.filter(el => el.length == PREIMAGE_SIZE_HEX)

		preimages.forEach(preimage => this.learnPreimage(preimage))
	}

	get pubkey() {
		return this.#idToHash.pubkey
	}
}



class State {

	#state = {};

	set(commitmentId, value) {
		if (this.#state[commitmentId] === undefined || this.#state[commitmentId] === parseInt(value)) {
			this.#state[commitmentId] = parseInt(value)
		} else {
			throw Error(`Value of ${commitmentId} is already set to a different value: ${value} in state: ${this.#state[commitmentId]}`)
		}
	}

	get_u160(identifier) {
		let result = 0n
		for (let i = 1; i <= 5; i++) {
			const childId = `${identifier}_${6 - i}`
			const value = BigInt(this.get_u32(childId))
			result <<= 32n
			result += value
		}
		return result.toString(16).padStart(40, 0)
	}

	get_u32(identifier) {
		let result = 0
		for (let i = 0; i < 4; i++) {
			const childId = `${identifier}_byte${i}`
			const value = this.get_u8(childId)
			result *= 2 ** 8	// Want to do a left shift here, but JS numbers are weird
			result += value
		}
		return result
	}

	get_u8(identifier) {
		let result = 0
		for (let i = 0; i < 4; i++) {
			const childId = `${identifier}_${3 - i}`
			const value = this.get_u2(childId)
			result <<= 2
			result += value
		}
		return result
	}

	get_u2(identifier) {
		const value = this.#state[identifier]
		if (value === undefined)
			throw Error(`Value of ${identifier} is not known`)
		return value
	}

	get_u1(identifier) {
		const value = this.#state[identifier]
		if (value === undefined)
			throw Error(`Value of ${identifier} is not known`)
		return value
	}
}
