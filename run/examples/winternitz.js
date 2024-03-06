// 
// Winternitz One-time Signatures
// 

//
// Winternitz signatures are an improved version of Lamport signatures.
// A detailed introduction to Winternitz signatures can be found
// in "A Graduate Course in Applied Cryptography" in chapter 14.3
// https://toc.cryptobook.us/book.pdf
//
// We are trying to closely follow the authors' notation here.
//



// The secret key
const MY_SECKEY = '0xb138982ce17ac813d505b5b40b665d404e9528e7'
// The message to sign
const MESSAGE   = '0x1234567890abcdef1234567890abcdef12345678'

// Digits are base d+1
const d = 2**4 - 1
// Bits per digit
const log_d = Math.ceil( Math.log(d+1)/Math.log(2) )
// Number of digits of the message
const n0 = Math.ceil( (MESSAGE.length/2 - 1) * 8 / log_d )
// Number of digits of the checksum
const n1 = Math.ceil(Math.log(d*n0)/Math.log(d+1)) + 1 
// Total number of digits to be signed
const n = n0 + n1



// 
// 
// Helper Functions
// 
// 

// Convert a byte value to two hex nibbles
function to_hex_byte(number){
	if (number > 255)
		throw 'number must be a byte value'
	return number.toString(16).padStart(2, '0')
}

// Generate the public key for the i-th digit of the message
function public_key(secret_key, digit_index){
	const secret_index = fromHex(secret_key + to_hex_byte(digit_index))
	let hash = ripemd160(secret_index)
	for(let i=0; i < d; i++){
		hash = ripemd160(hash)
	}
	return toHex(hash)
}

// Compute the signature for the i-th digit of the message
function digit_signature(secret_key, digit_index, message_digit){
	const secret_index = fromHex(secret_key + to_hex_byte(digit_index))
	let hash = ripemd160(secret_index)
	for(let i=0; i < message_digit; i++){
		hash = ripemd160(hash)
	}
	return [toHex(hash), message_digit]
}

// Compute the checksum of the message's digits
// Further infos in chapter "A domination free function for Winternitz signatures"
function checksum(digits){
	return d * n0 - digits.reduce( (a,e) => a + e, 0 )
}

// Convert a number to digits
function to_digits(number, digit_count){
	number = BigInt(number)
	const digits = []
	for(let i=0; i < digit_count; i++){
		const digit = number % BigInt(d+1)
		number = (number - digit) / BigInt(d+1)
		digits.push(digit)
	}
	return digits.map(Number)
}

// Compute the signature for a given message
function signature(secret_key, message){
	const message_digits = to_digits(message, n0)
	const checksum_digits = to_digits(checksum(message_digits), n1)
	const sig = checksum_digits.concat(message_digits)
	return sig.map( (m,i) => digit_signature(secret_key, n-i, m)).reverse()
}


//
//
// The Bitcoin Script
//
//
[


//
//
// Unlocking Script
//
//

// Signature for the message and the checksum
signature(MY_SECKEY, MESSAGE),





//
//
// Locking Script
//
//


//
// Verify the hash chain for each digit
//

// Repeat this for every of the n many digits
loop(n, digit_index => [
	// Verify that the digit is in the range [0, d]
	OP_DUP,
	0,
	d+1,
	OP_WITHIN,
	OP_VERIFY,

	// Push two copies of the digit onto the altstack
	OP_DUP,
	OP_TOALTSTACK,
	OP_TOALTSTACK,

	// Hash the input hash d times and put every result on the stack
	loop(d, _ => [OP_DUP, OP_RIPEMD160] ),

	// Verify the signature for this digit
	OP_FROMALTSTACK,
	OP_PICK,
	public_key(MY_SECKEY, n - digit_index),
	OP_EQUALVERIFY,

	// Drop the d+1 stack items
	loop((d+1)/2, _ => OP_2DROP),
]),




//
// Verify the Checksum
//

// 1. Compute the checksum of the message's digits
0,
loop(n0, _ => [OP_FROMALTSTACK, OP_DUP, OP_ROT, OP_ADD]),
d * n0,
OP_SWAP,
OP_SUB,


// 2. Sum up the signed checksum's digits
OP_FROMALTSTACK,
loop(n1 - 1, _ => [
	loop(log_d, _ => [OP_DUP, OP_ADD]),
	OP_FROMALTSTACK,
	OP_ADD,
]),

// 3. Ensure both checksums are equal
OP_EQUALVERIFY,



// Convert the message's digits to bytes
loop(n0/2, _ => [ 
	OP_SWAP, 
	loop(log_d, _ => [OP_DUP, OP_ADD]), 
	OP_ADD, 
	OP_TOALTSTACK
]),
loop(n0/2, _ => [OP_FROMALTSTACK])

]