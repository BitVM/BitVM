//
// Example of a Byte Commitment
//

const paul = new Player('730fff80e1413068a05b57d6a58261f07551163369787f349438ea38ca80fac6');

[
	
	// 
	// Unlocking Script
	// 
	u8_state_unlock(paul, 'my_varA', 0b11100100),

	

	// 
	// Program (four 2-bit commitments)
	// 
	u8_state(paul, 'my_varA'),

	0b11100100,
	OP_EQUALVERIFY,
	// Success! The value was correct

	// Let's push some random data onto the stack 
	// to signal that we successfully got here
	42

]
