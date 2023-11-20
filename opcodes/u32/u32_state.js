import { RIPEMD } from '../../libs/ripemd.js'
import { toHex, fromUnicode } from '../../libs/bytes.js'


const hash = buffer => RIPEMD.hash(new Uint8Array(buffer).buffer)

export const hashLock = (secret, identifier, index, value) => 
	toHex(hash(preimage(secret, identifier, index, value)))

const preimage = (secret, identifier, index, value) => 
	hash(fromUnicode(secret + identifier + `index: ${index}, value: ${value}`))

export const preimageHex = (secret, identifier, index, value) => 
	toHex(preimage(secret, identifier, index, value))


export const bit_state = (secret, identifier, index = 0) => [
	OP_RIPEMD160,
	OP_DUP,
	hashLock(secret, identifier, index, 1), // hash1
	OP_EQUAL,
	OP_DUP,
	OP_ROT,
	hashLock(secret, identifier, index, 0), // hash0
	OP_EQUAL,
	OP_BOOLOR,
	OP_VERIFY
]

export const bit_state_commit = (secret, identifier, index = 0) => [
	OP_RIPEMD160,
	OP_DUP,
	hashLock(secret, identifier, index, 1), // hash1
	OP_EQUAL,
	OP_SWAP,
	hashLock(secret, identifier, index, 0), // hash0
	OP_EQUAL,
	OP_BOOLOR,
	OP_VERIFY
]

export const bit_state_unlock = (secret, identifier, value, index = 0) => 
	preimageHex(secret, identifier, index, value)


export const bit_state_justice = (secret, identifier, index = 0) => [
	OP_RIPEMD160,
	hashLock(secret, identifier, index, 0), // hash0
	OP_EQUALVERIFY,
	OP_SWAP,
	OP_RIPEMD160,
	hashLock(secret, identifier, index, 1), // hash1
	OP_EQUALVERIFY
]

export const bit_state_justice_unlock = (secret, identifier, index = 0) => [
	preimageHex(secret, identifier, index, 1),
	preimageHex(secret, identifier, index, 0)
]



export const u2_state = (secret, identifier, index = 0) => [
	// Locking Script
	OP_RIPEMD160,
	OP_DUP,
	hashLock(secret, identifier, index, 3), // hash3
	OP_EQUAL,
	OP_IF,
		OP_DROP,
		3,
	OP_ELSE,
		OP_DUP,
		hashLock(secret, identifier, index, 2),  // hash2
		OP_EQUAL,
		OP_IF,
			OP_DROP,
			2,
		OP_ELSE,
			OP_DUP,
			hashLock(secret, identifier, index, 1),  // hash1
			OP_EQUAL,
			OP_IF,
				OP_DROP,
				1,
			OP_ELSE,
				hashLock(secret, identifier, index, 0),  // hash0
				OP_EQUALVERIFY,
				0,
			OP_ENDIF,
		OP_ENDIF,
	OP_ENDIF
]


export const u2_state_commit = (secret, identifier, index = 0) => [
	OP_RIPEMD160,

	OP_DUP,
	hashLock(secret, identifier, index, 3), // hash3
	OP_EQUAL,

	OP_OVER,
	hashLock(secret, identifier, index, 2), // hash2
	OP_EQUAL,
	OP_BOOLOR,

	OP_OVER,
	hashLock(secret, identifier, index, 1), // hash1
	OP_EQUAL,
	OP_BOOLOR,

	OP_SWAP,
	hashLock(secret, identifier, index, 0), // hash0
	OP_EQUAL,
	OP_BOOLOR,
	OP_VERIFY,
]

export const u2_state_unlock = (secret, identifier, value, index = 0) => 
	preimageHex(secret, identifier, index, value)



export const u2_state_justice = (secret, identifier, index = 0) => [
	// Ensure the two preimages are different
	OP_2DUP,
	OP_EQUAL,
	OP_NOT,
	OP_VERIFY,

	// Check that preimageA hashes to either hash3, hash2, or hash1 
	OP_RIPEMD160,

	OP_DUP,
	hashLock(secret, identifier, index, 3), // hash3
	OP_EQUAL,

	OP_OVER,
	hashLock(secret, identifier, index, 2), // hash2
	OP_EQUAL,
	OP_BOOLOR,

	OP_SWAP,
	hashLock(secret, identifier, index, 1), // hash1
	OP_EQUAL,
	OP_BOOLOR,

	OP_SWAP,

	// Check that preimageB hashes to either hash2, hash1, or hash0
	OP_RIPEMD160,

	OP_DUP,
	hashLock(secret, identifier, index, 2), // hash3
	OP_EQUAL,

	OP_OVER,
	hashLock(secret, identifier, index, 1), // hash2
	OP_EQUAL,
	OP_BOOLOR,

	OP_SWAP,
	hashLock(secret, identifier, index, 0), // hash1
	OP_EQUAL,
	OP_BOOLOR,

	OP_BOOLAND,
	OP_VERIFY
]





export const u8_state = (secret, identifier) => [
	// Bit 1 and 2
	loop(4, i => [

		u2_state(secret, identifier, 3 - i), // hash0		

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

export const u8_state_commit = (secret, identifier) => [
	u2_state_commit(secret, identifier, 3),
	u2_state_commit(secret, identifier, 2),
	u2_state_commit(secret, identifier, 1),
	u2_state_commit(secret, identifier, 0),
]

export const u8_state_unlock = (secret, identifier, value) => [
	preimageHex(secret, identifier, 0, (value & 0b00000011) >>> 0),
	preimageHex(secret, identifier, 1, (value & 0b00001100) >>> 2),
	preimageHex(secret, identifier, 2, (value & 0b00110000) >>> 4),
	preimageHex(secret, identifier, 3, (value & 0b11000000) >>> 6),
]


export const u8_state_justice_leaves = (secret, identifier) => [
	u2_state_justice(secret, identifier, 3),
	u2_state_justice(secret, identifier, 2),
	u2_state_justice(secret, identifier, 1),
	u2_state_justice(secret, identifier, 0),
]

export const u32_state = (secret, identifier) => [
	u8_state(secret, identifier + '_byte0'),
	OP_TOALTSTACK,
	u8_state(secret, identifier + '_byte1'),
	OP_TOALTSTACK,
	u8_state(secret, identifier + '_byte2'), 
	OP_TOALTSTACK,
	u8_state(secret, identifier + '_byte3'),
	OP_FROMALTSTACK,
	OP_FROMALTSTACK,
	OP_FROMALTSTACK
]

export const u32_state_commit = (secret, identifier) => [
	u8_state_commit(secret, identifier + '_byte0'),
	u8_state_commit(secret, identifier + '_byte1'),
	u8_state_commit(secret, identifier + '_byte2'),
	u8_state_commit(secret, identifier + '_byte3'),
]

export const u32_state_unlock = (secret, identifier, value) => [
	u8_state_unlock(secret, identifier + '_byte3', (value & 0xff000000) >>> 24),
	u8_state_unlock(secret, identifier + '_byte2', (value & 0x00ff0000) >>> 16),
	u8_state_unlock(secret, identifier + '_byte1', (value & 0x0000ff00) >>> 8),
	u8_state_unlock(secret, identifier + '_byte0', (value & 0x000000ff) >>> 0)
]

export const u32_state_justice_leaves = (secret, identifier) => [
	...u8_state_justice_leaves(secret, identifier + '_byte0'),
	...u8_state_justice_leaves(secret, identifier + '_byte1'),
	...u8_state_justice_leaves(secret, identifier + '_byte2'),
	...u8_state_justice_leaves(secret, identifier + '_byte3'),
]
