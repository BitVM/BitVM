import './std.js'

// ((((((A_0 > B_0) && A_1 == B_1) || A_1 > B_1) && A_2 == B_2) || A_2 > B_2) && A_3 == B_3) || A_3 > B_3

const u32_cmp = opcode => [
	4,
	OP_ROLL,
	OP_SWAP,
	opcode,
	OP_SWAP,
	4,
	OP_ROLL,
	OP_2DUP,
	OP_EQUAL,
	3,
	OP_ROLL,
	OP_BOOLAND,
	OP_SWAP,
	OP_ROT,
	opcode,
	OP_BOOLOR,
	OP_SWAP,
	3,
	OP_ROLL,
	OP_2DUP,
	OP_EQUAL,
	3,
	OP_ROLL,
	OP_BOOLAND,
	OP_SWAP,
	OP_ROT,
	opcode,
	OP_BOOLOR,
	OP_SWAP,
	OP_ROT,
	OP_2DUP,
	OP_EQUAL,
	3,
	OP_ROLL,
	OP_BOOLAND,
	OP_SWAP,
	OP_ROT,
	opcode,
	OP_BOOLOR,
]

// A_3 <> B_3 || (A_3 == B_3 && (A_2 <> B_2 || (A_2 == B_2 && (A_1 <> B_1 || (A_1 == B_1 && A_0 <> B_0)))))

export const u32_lessthan = u32_cmp(OP_LESSTHAN)
export const u32_greaterthan = u32_cmp(OP_GREATERTHAN)

const u32_cmpeq = opcode => [
	OP_4DUP,
	8,
	OP_PICK,
	OP_EQUAL,
	OP_SWAP,
	9,
	OP_PICK,
	OP_EQUAL,
	OP_BOOLAND,
	OP_SWAP,	
	9,
	OP_PICK,
	OP_EQUAL,
	OP_BOOLAND,
	OP_SWAP,	
	9,
	OP_PICK,
	OP_EQUAL,
	OP_BOOLAND,
	OP_TOALTSTACK,
	u32_cmp(opcode),
	OP_FROMALTSTACK,
	OP_BOOLOR
]

export const u32_lessthanorequal = u32_cmpeq(OP_LESSTHAN)
export const u32_greaterthanorequal = u32_cmpeq(OP_GREATERTHAN)
