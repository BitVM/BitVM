
export const bit_state = (actor, identifier, index = 0) => [
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

export const bit_state_commit = (actor, identifier, index = 0) => [
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

export const bit_state_unlock = (actor, identifier, value, index = 0) => 
	actor.preimage(identifier, index, value)


export const bit_state_justice = (actor, identifier, index = 0) => [
	OP_RIPEMD160,
	actor.hashlock(identifier, index, 0), // hash0
	OP_EQUALVERIFY,
	OP_SWAP,
	OP_RIPEMD160,
	actor.hashlock(identifier, index, 1), // hash1
	OP_EQUALVERIFY
]

export const bit_state_justice_unlock = (actor, identifier, index = 0) => [
	actor.preimage(identifier, index, 1),
	actor.preimage(identifier, index, 0)
]



export const u2_state = (actor, identifier, index = 0) => [
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


export const u2_state_commit = (actor, identifier, index = 0) => [
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

export const u2_state_unlock = (actor, identifier, value, index = 0) => 
	actor.preimage(identifier, index, value)



export const u2_state_justice = (actor, identifier, index = 0) => [
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
			i != 3 ? OP_TOALTSTACK : ''
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




export const u32_state = (actor, identifier) => [
	u8_state(actor, identifier + '_byte0'),
	OP_TOALTSTACK,
	u8_state(actor, identifier + '_byte1'),
	OP_TOALTSTACK,
	u8_state(actor, identifier + '_byte2'), 
	OP_TOALTSTACK,
	u8_state(actor, identifier + '_byte3'),
	OP_FROMALTSTACK,
	OP_FROMALTSTACK,
	OP_FROMALTSTACK
]

export const u32_state_commit = (actor, identifier) => [
	u8_state_commit(actor, identifier + '_byte0'),
	u8_state_commit(actor, identifier + '_byte1'),
	u8_state_commit(actor, identifier + '_byte2'),
	u8_state_commit(actor, identifier + '_byte3'),
]

export const u32_state_unlock = (actor, identifier, value) => [
	u8_state_unlock(actor, identifier + '_byte3', (value & 0xff000000) >>> 24),
	u8_state_unlock(actor, identifier + '_byte2', (value & 0x00ff0000) >>> 16),
	u8_state_unlock(actor, identifier + '_byte1', (value & 0x0000ff00) >>> 8),
	u8_state_unlock(actor, identifier + '_byte0', (value & 0x000000ff) >>> 0)
]


