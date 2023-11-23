import { keys } from '../libs/crypto_tools.js'
import { RIPEMD } from '../libs/ripemd.js'
import { toHex, fromUnicode } from '../libs/bytes.js'


const hash = buffer => RIPEMD.hash(new Uint8Array(buffer).buffer)

const hashLock = (secret, identifier, index, value) => 
	toHex(hash(preimage(secret, identifier, index, value)))

const preimage = (secret, identifier, index, value) => 
	hash(fromUnicode(secret + identifier + `index: ${index}, value: ${value}`))

function toPublicKey(secret){
    // Drop the first byte of the pubkey
    return toHex(keys.get_pubkey(secret)).slice(2)
}

export class Player {
	#secret;

	constructor(secret){
		this.#secret = secret;
		// TODO: make the seckey private too. Add a sign function instead
    	this.seckey = keys.get_seckey(secret)
    	this.pubkey = toPublicKey(this.seckey)
	}

	hashlock(identifier, index, value){
		return hashLock(this.#secret, identifier, index, value)
	}

	preimage(identifier, index, value){
		// TODO: check that the value is non-conflicting
		return toHex(preimage(this.#secret, identifier, index, value))
	}
}


export class Opponent {
	#hashes;
	#preimages = {}

	constructor(hashes){
		this.#hashes = hashes
	}

	hashlock(identifier, index, value){
		return this.#hashes[index + value]
	}

	preimage(identifier, index, value){
		return this.#preimages[identifier + index][value]
	}

	learnPreimage(identifier, index, value, preimage){
		// TODO is there any other preimage in 
		// this.#preimages[identifier + index] ??

		this.#preimages[identifier + index][value] = preimage
	}
}