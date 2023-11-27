import { keys } from '../libs/crypto_tools.js'
import { ripemd160 } from '../libs/ripemd160.js'
import { toHex, fromUnicode } from '../libs/bytes.js'
import { Signer } from '../libs/tapscript.js'

const hash = buffer => ripemd160(buffer)

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

	sign(leaf, inputIndex=0){
		const tx = leaf.tx.tx()
		const extension = leaf.encodedLockingScript
		return Signer.taproot.sign(this.seckey, tx, inputIndex, { extension }).hex
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

