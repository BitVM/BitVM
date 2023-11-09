import '../std/opcodes.js'
import {RIPEMD} from '../ripemd.js'

function fromUnicode(string, encoding = 'utf-8') {
    const encoder = new TextEncoder(encoding);
    return encoder.encode(string);
}

export function toHex(buffer) {
    return [...new Uint8Array(buffer)]
        .map(x => x.toString(16).padStart(2, '0'))
        .join('');
}

const hash = buffer => RIPEMD.hash(new Uint8Array(buffer).buffer)

export const hashLock = (secret, identifier, index, value) => 
	toHex(hash(preimage(secret, identifier,index,value)))

const preimage = (secret, identifier, index, value) => 
	hash(fromUnicode(secret + identifier + `index: ${index}, value: ${value}`))

export const preimageHex = (secret, identifier, index, value) => 
	toHex(preimage(secret, identifier, index, value))

export const u8_state = (secret, identifier) => [
	// Bit 1 and 2

	OP_TOALTSTACK,

	OP_DUP,
	OP_TOALTSTACK, 

	hashLock(secret, identifier, 3, 3), // hash3
	hashLock(secret, identifier, 3, 2), // hash2
	hashLock(secret, identifier, 3, 1), // hash1
	hashLock(secret, identifier, 3, 0), // hash0


	OP_FROMALTSTACK,
	OP_ROLL,

	OP_FROMALTSTACK,
	OP_RIPEMD160,
	OP_EQUALVERIFY,

	OP_2DROP,
	OP_DROP,

	OP_TOALTSTACK,



	// Bit 3 and 4

	OP_TOALTSTACK,

	OP_DUP,
	OP_TOALTSTACK,

	hashLock(secret, identifier, 2, 3), // hash3
	hashLock(secret, identifier, 2, 2), // hash2
	hashLock(secret, identifier, 2, 1), // hash1
	hashLock(secret, identifier, 2, 0), // hash0

	OP_FROMALTSTACK,
	OP_ROLL,

	OP_FROMALTSTACK,
	OP_RIPEMD160,
	OP_EQUALVERIFY,

	OP_2DROP,
	OP_DROP,

	OP_FROMALTSTACK,
	OP_DUP,
	OP_ADD,
	OP_DUP,
	OP_ADD,
	OP_ADD,
	OP_TOALTSTACK,


	// Bit 5 and 6

	OP_TOALTSTACK,

	OP_DUP,
	OP_TOALTSTACK,

	hashLock(secret, identifier, 1, 3), // hash3
	hashLock(secret, identifier, 1, 2), // hash2
	hashLock(secret, identifier, 1, 1), // hash1
	hashLock(secret, identifier, 1, 0), // hash0

	OP_FROMALTSTACK,
	OP_ROLL,

	OP_FROMALTSTACK,
	OP_RIPEMD160,
	OP_EQUALVERIFY,

	OP_2DROP,
	OP_DROP,

	OP_FROMALTSTACK,
	OP_DUP,
	OP_ADD,
	OP_DUP,
	OP_ADD,
	OP_ADD,
	OP_TOALTSTACK,



	// Bit 7 and 8

	OP_TOALTSTACK,

	OP_DUP,
	OP_TOALTSTACK,

	hashLock(secret, identifier, 0, 3), // hash3
	hashLock(secret, identifier, 0, 2), // hash2
	hashLock(secret, identifier, 0, 1), // hash1
	hashLock(secret, identifier, 0, 0), // hash0

	OP_FROMALTSTACK,
	OP_ROLL,

	OP_FROMALTSTACK,
	OP_RIPEMD160,
	OP_EQUALVERIFY,

	OP_2DROP,
	OP_DROP,

	OP_FROMALTSTACK,
	OP_DUP,
	OP_ADD,
	OP_DUP,
	OP_ADD,
	OP_ADD,

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

