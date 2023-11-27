//
// Example of a Hash Commitment
//

const player = new Player('730fff80e1413068a05b57d6a58261f07551163369787f349438ea38ca80fac6');

[

	//
	// Unlocking Script
	//

	// Some arbitrary hash here
	u160_state_unlock(player, 'my_varA', '1234567890abcdef1234567890abcdef12345678'),


	//
	// Program (eighty 2-bit commitments)
	//
	u160_state(player, 'my_varA')

]