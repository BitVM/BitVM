import {hashId} from '../player.js'

export const bit_state = (actor, identifier, index) => [
	// TODO: validate size of preimage here 
	OP_RIPEMD160,
	OP_DUP,
	actor.hashlock(identifier, index, 1), // hash1
	OP_EQUAL,
	OP_DUP,
	OP_ROT,
	actor.hashlock(identifier, index, 0), // hash0
	OP_EQUAL,
	OP_BOOLOR,
	OP_VERIFY
]

export const bit_state_commit = (actor, identifier, index) => [
	// TODO: validate size of preimage here 
	OP_RIPEMD160,
	OP_DUP,
	actor.hashlock(identifier, index, 1), // hash1
	OP_EQUAL,
	OP_SWAP,
	actor.hashlock(identifier, index, 0), // hash0
	OP_EQUAL,
	OP_BOOLOR,
	OP_VERIFY
]

export const bit_state_unlock = (actor, identifier, value, index) => 
	actor.preimage(identifier, index, value)


export const bit_state_justice = (actor, identifier, index) => [
	OP_RIPEMD160,
	actor.hashlock(identifier, index, 0), // hash0
	OP_EQUALVERIFY,
	OP_SWAP,
	OP_RIPEMD160,
	actor.hashlock(identifier, index, 1), // hash1
	OP_EQUALVERIFY
]

export const bit_state_justice_unlock = (actor, identifier, index) => [
	actor.preimage(identifier, index, 1),
	actor.preimage(identifier, index, 0)
]

export const bit_state_json = (actor, identifier, index) => {
	const result = {}
	result[hashId(identifier, index, 1)] = actor.hashlock(identifier, index, 1)
	result[hashId(identifier, index, 0)] = actor.hashlock(identifier, index, 0)
	return result
}



export const u2_state = (actor, identifier, index) => [
	// TODO: validate size of preimage here
	
	// Locking Script
	OP_RIPEMD160,
	OP_DUP,
	actor.hashlock(identifier, index, 3), // hash3
	OP_EQUAL,
	OP_IF,
		OP_DROP,
		3,
	OP_ELSE,
		OP_DUP,
		actor.hashlock(identifier, index, 2),  // hash2
		OP_EQUAL,
		OP_IF,
			OP_DROP,
			2,
		OP_ELSE,
			OP_DUP,
			actor.hashlock(identifier, index, 1),  // hash1
			OP_EQUAL,
			OP_IF,
				OP_DROP,
				1,
			OP_ELSE,
				actor.hashlock(identifier, index, 0),  // hash0
				OP_EQUALVERIFY,
				0,
			OP_ENDIF,
		OP_ENDIF,
	OP_ENDIF
]


export const u2_state_commit = (actor, identifier, index) => [
	// TODO: validate size of preimage here
	OP_RIPEMD160,

	OP_DUP,
	actor.hashlock(identifier, index, 3), // hash3
	OP_EQUAL,

	OP_OVER,
	actor.hashlock(identifier, index, 2), // hash2
	OP_EQUAL,
	OP_BOOLOR,

	OP_OVER,
	actor.hashlock(identifier, index, 1), // hash1
	OP_EQUAL,
	OP_BOOLOR,

	OP_SWAP,
	actor.hashlock(identifier, index, 0), // hash0
	OP_EQUAL,
	OP_BOOLOR,
	OP_VERIFY,
]

export const u2_state_json = (actor, identifier, index) => {
	const result = {}
	result[hashId(identifier, index, 3)] = actor.hashlock(identifier, index, 3)
	result[hashId(identifier, index, 2)] = actor.hashlock(identifier, index, 2)
	result[hashId(identifier, index, 1)] = actor.hashlock(identifier, index, 1)
	result[hashId(identifier, index, 0)] = actor.hashlock(identifier, index, 0)
	return result
}

export const u2_state_unlock = (actor, identifier, value, index) => 
	actor.preimage(identifier, index, value)



export const u2_state_justice = (actor, identifier, index) => [
	// Ensure the two preimages are different
	OP_2DUP,
	OP_EQUAL,
	OP_NOT,
	OP_VERIFY,

	// Check that preimageA hashes to either hash3, hash2, or hash1 
	OP_RIPEMD160,

	OP_DUP,
	actor.hashlock(identifier, index, 3), // hash3
	OP_EQUAL,

	OP_OVER,
	actor.hashlock(identifier, index, 2), // hash2
	OP_EQUAL,
	OP_BOOLOR,

	OP_SWAP,
	actor.hashlock(identifier, index, 1), // hash1
	OP_EQUAL,
	OP_BOOLOR,

	OP_SWAP,

	// Check that preimageB hashes to either hash2, hash1, or hash0
	OP_RIPEMD160,

	OP_DUP,
	actor.hashlock(identifier, index, 2), // hash3
	OP_EQUAL,

	OP_OVER,
	actor.hashlock(identifier, index, 1), // hash2
	OP_EQUAL,
	OP_BOOLOR,

	OP_SWAP,
	actor.hashlock(identifier, index, 0), // hash1
	OP_EQUAL,
	OP_BOOLOR,

	OP_BOOLAND,
	OP_VERIFY
]



export const u8_state = (actor, identifier) => [
	// Bit 1 and 2
	loop(4, i => [

		u2_state(actor, identifier, 3 - i), // hash0		

		i == 0 ? [ 
			OP_TOALTSTACK 
		] : [
			OP_FROMALTSTACK,
			OP_DUP,
			OP_ADD,
			OP_DUP,
			OP_ADD,
			OP_ADD,
			i != 3 ? OP_TOALTSTACK : OP_NOP
		]
	])
	// Now there's the u8 value on the stack
]

export const u8_state_commit = (actor, identifier) => [
	u2_state_commit(actor, identifier, 3),
	u2_state_commit(actor, identifier, 2),
	u2_state_commit(actor, identifier, 1),
	u2_state_commit(actor, identifier, 0),
]

export const u8_state_unlock = (actor, identifier, value) => [
	actor.preimage(identifier, 0, (value & 0b00000011) >>> 0),
	actor.preimage(identifier, 1, (value & 0b00001100) >>> 2),
	actor.preimage(identifier, 2, (value & 0b00110000) >>> 4),
	actor.preimage(identifier, 3, (value & 0b11000000) >>> 6),
]


export const u8_state_json = (actor, identifier) => {
	const result = {}
	Object.assign(result, u2_state_json(actor, identifier, 3))
	Object.assign(result, u2_state_json(actor, identifier, 2))
	Object.assign(result, u2_state_json(actor, identifier, 1))
	Object.assign(result, u2_state_json(actor, identifier, 0))
	return result
}


const u32_id = (identifier, i) => `${identifier}_byte${i}`

export const u32_state = (actor, identifier) => [
	u8_state(actor, u32_id(identifier,0)),
	OP_TOALTSTACK,
	u8_state(actor, u32_id(identifier,1)),
	OP_TOALTSTACK,
	u8_state(actor, u32_id(identifier,2)), 
	OP_TOALTSTACK,
	u8_state(actor, u32_id(identifier,3)),
	OP_FROMALTSTACK,
	OP_FROMALTSTACK,
	OP_FROMALTSTACK
]

export const u32_state_commit = (actor, identifier) => [
	u8_state_commit(actor, u32_id(identifier,0)),
	u8_state_commit(actor, u32_id(identifier,1)),
	u8_state_commit(actor, u32_id(identifier,2)),
	u8_state_commit(actor, u32_id(identifier,3)),
]

export const u32_state_json = (actor, identifier) => {
	const result = {}
	Object.assign(result, u8_state_json(actor, u32_id(identifier,0)))
	Object.assign(result, u8_state_json(actor, u32_id(identifier,1)))
	Object.assign(result, u8_state_json(actor, u32_id(identifier,2)))
	Object.assign(result, u8_state_json(actor, u32_id(identifier,3)))
	return result
}

export const u32_state_unlock = (actor, identifier, value) => [
	u8_state_unlock(actor, u32_id(identifier,3), (value & 0xff000000) >>> 24),
	u8_state_unlock(actor, u32_id(identifier,2), (value & 0x00ff0000) >>> 16),
	u8_state_unlock(actor, u32_id(identifier,1), (value & 0x0000ff00) >>> 8),
	u8_state_unlock(actor, u32_id(identifier,0), (value & 0x000000ff) >>> 0)
]




const u2_state_bit0 = (actor, identifier, index) => [
	// TODO: validate size of preimage here
	
	// Locking Script
	OP_RIPEMD160,
	OP_DUP,
	actor.hashlock(identifier, index, 3), // hash3
	OP_EQUAL,
	OP_IF,
		OP_DROP,
		1,
	OP_ELSE,
		OP_DUP,
		actor.hashlock(identifier, index, 2),  // hash2
		OP_EQUAL,
		OP_IF,
			OP_DROP,
			0,
		OP_ELSE,
			OP_DUP,
			actor.hashlock(identifier, index, 1),  // hash1
			OP_EQUAL,
			OP_IF,
				OP_DROP,
				1,
			OP_ELSE,
				actor.hashlock(identifier, index, 0),  // hash0
				OP_EQUALVERIFY,
				0,
			OP_ENDIF,
		OP_ENDIF,
	OP_ENDIF
]


const u2_state_bit1 = (actor, identifier, index) => [
	// TODO: validate size of preimage here
	
	// Locking Script
	OP_RIPEMD160,
	OP_DUP,
	actor.hashlock(identifier, index, 3), // hash3
	OP_EQUAL,
	OP_IF,
		OP_DROP,
		1,
	OP_ELSE,
		OP_DUP,
		actor.hashlock(identifier, index, 2),  // hash2
		OP_EQUAL,
		OP_IF,
			OP_DROP,
			1,
		OP_ELSE,
			OP_DUP,
			actor.hashlock(identifier, index, 1),  // hash1
			OP_EQUAL,
			OP_IF,
				OP_DROP,
				0,
			OP_ELSE,
				actor.hashlock(identifier, index, 0),  // hash0
				OP_EQUALVERIFY,
				0,
			OP_ENDIF,
		OP_ENDIF,
	OP_ENDIF
]

export const u2_state_bit = (actor, identifier, index, bitIndex) => {
    if(bitIndex)
        return u2_state_bit1(actor, identifier, index)
    else
        return u2_state_bit0(actor, identifier, index)
}

export const u8_state_bit = (actor, identifier, bitIndex /* 3 bits */) => {
	if(bitIndex > 2**3 - 1)
		throw Error(`Out of range! bitIndex=${bitIndex} is larger than 7`)
	const isOdd = bitIndex & 1 	 // bitIndex mod 2
	const index = bitIndex >> 1  // bitIndex div 2
	return u2_state_bit(actor, identifier, index, isOdd)
}

export const u8_state_bit_unlock = (actor, identifier, value, bitIndex) => {
	const index = bitIndex >> 1  // bitIndex div 2
    const childValue = value >> 2 * index & 0b11
	return u2_state_unlock(actor, identifier, childValue, index)
}

export const u32_state_bit = (actor, identifier, bitIndex) => {
	if(bitIndex > 2**5 - 1)
		throw Error(`Out of range! bitIndex=${bitIndex} is larger than 31`)
	const byteIndex = bitIndex >> 3 		// bitIndex div 8
	const childIdentifier = u32_id(identifier, 3-byteIndex)
	const childBitIndex = bitIndex & 0b111	// bitIndex mod 8
	return u8_state_bit(actor, childIdentifier, childBitIndex)
}

export const u32_state_bit_unlock = (actor, identifier, value, bitIndex) => {
	const byteIndex = bitIndex >> 3 		// bitIndex div 8
	const childIdentifier = u32_id(identifier, 3-byteIndex)
	const childBitIndex = bitIndex & 0b111 	// bitIndex mod 8
    const childValue = value >> 8 * byteIndex & 0xFF
    return u8_state_bit_unlock(actor, childIdentifier, childValue, childBitIndex)
}