import { RIPEMD } from '../../libs/ripemd.js'
import { toHex, fromUnicode } from '../../libs/bytes.js'


const hash = buffer => RIPEMD.hash(new Uint8Array(buffer).buffer)

export const hashLock = (secret, identifier, index, value) => 
	toHex(hash(preimage(secret, identifier, index, value)))

const preimage = (secret, identifier, index, value) => 
	hash(fromUnicode(secret + identifier + `index: ${index}, value: ${value}`))

export const preimageHex = (secret, identifier, index, value) => 
	toHex(preimage(secret, identifier, index, value))

export const u8_state = (secret, identifier) => [
	// Bit 1 and 2
	loop(4, i => [
		OP_TOALTSTACK,

		OP_DUP,
		OP_TOALTSTACK, 

		hashLock(secret, identifier, 3 - i, 3), // hash3
		hashLock(secret, identifier, 3 - i, 2), // hash2
		hashLock(secret, identifier, 3 - i, 1), // hash1
		hashLock(secret, identifier, 3 - i, 0), // hash0

		OP_FROMALTSTACK,
		OP_ROLL,

		OP_FROMALTSTACK,
		OP_RIPEMD160,
		OP_EQUALVERIFY,

		OP_2DROP,
		OP_DROP,

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

export const u8_state_unlock = (secret, identifier, value) => [
	value & 0b00000011,
	preimageHex(secret, identifier, 0, value & 0b00000011),
	(value & 0b00001100) >>> 2,
	preimageHex(secret, identifier, 1, (value & 0b00001100) >>> 2),
	(value & 0b00110000) >>> 4,
	preimageHex(secret, identifier, 2, (value & 0b00110000) >>> 4),
	(value & 0b11000000) >>> 6,
	preimageHex(secret, identifier, 3, (value & 0b11000000) >>> 6),
]

export const u32_state =  (secret, identifier) => [
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

export const u32_state_unlock =  (secret, identifier, value) => [
	u8_state_unlock(secret, identifier + '_byte3', (value & 0xff000000) >>> 24),
	u8_state_unlock(secret, identifier + '_byte2', (value & 0x00ff0000) >>> 16),
	u8_state_unlock(secret, identifier + '_byte1', (value & 0x0000ff00) >>> 8),
	u8_state_unlock(secret, identifier + '_byte0', (value & 0x000000ff))
]


export const bit_state_reveal = (secret, identifier, index = 0) => [
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
