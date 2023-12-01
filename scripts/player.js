import { keys } from '../libs/crypto_tools.js'
import { ripemd160 } from '../libs/ripemd160.js'
import { toHex, fromUnicode } from '../libs/bytes.js'
import { Signer } from '../libs/tapscript.js'

function toPublicKey(secret){
    // Drop the first byte of the pubkey
    return toHex(keys.get_pubkey(secret)).slice(2)
}


const hash = buffer => ripemd160(buffer)

const hashId = (identifier, index, value) => `${identifier}_${index}_${value}`

const _preimage = (secret, hashId) => 
	hash(fromUnicode(secret + hashId))

const _hashLock = (secret, hashId) =>
	toHex(hash(_preimage(secret, hashId)))

const preimage = (secret, identifier, index, value) =>
	toHex(_preimage(secret, hashId(identifier, index, value)))

const hashLock = (secret, identifier, index, value) => 
	toHex(hash(_preimage(secret, hashId(identifier, index, value))))


export class Player {
	#secret;
	// hashes = {};

	constructor(secret){
		this.#secret = secret;
		// TODO: make the seckey private too. Add a sign function instead
    	this.seckey = keys.get_seckey(secret)
    	this.pubkey = toPublicKey(this.seckey)
	}

	hashlock(identifier, index=0, value=0){	
		const hash = hashLock(this.#secret, identifier, index, value)
		// this.hashes[hashId(identifier, index, value)] = hash
		return hash
	}

	preimage(identifier, index=0, value=0){
		// TODO: check that the value is non-conflicting
		return preimage(this.#secret, identifier, index, value)
	}

	sign(leaf, inputIndex=0){
		const tx = leaf.tx.tx()
		const extension = leaf.encodedLockingScript
		return Signer.taproot.sign(this.seckey, tx, inputIndex, { extension }).hex
	}

	getHashes(hashIds){
		return hashIds.reduce((result, hashId) => {
			result[hashId] = _hashLock(this.#secret, hashId)
			return result
		}, {})
	}
}


export class Opponent {
	#hashes;
	#preimages = {}

	constructor(hashes){
		this.#hashes = hashes
	}

	hashlock(identifier, index, value){
		const id = hashId(identifier, index, value)
		const hash = this.#hashes[id]
		if(!hash) throw `Hash for ${id} is not known`
		return hash
	}

	preimage(identifier, index, value){
		const id = hashId(identifier, index, value)
		const preimage = this.#preimages[id]
		if(!preimage) throw `Preimage of ${id} is not known`
		return preimage
	}

	learnPreimage(identifier, index, value, preimage){
		// TODO check if there is any other preimage in 
		// this.#preimages[identifier + index] ??

		this.#preimages[hashId(identifier, index, value)] = preimage
	}
}

