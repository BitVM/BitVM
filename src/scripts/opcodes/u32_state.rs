#![allow(dead_code)]

use super::pushable;
use bitcoin::ScriptBuf as Script;
use bitcoin_script::bitcoin_script as script;
use crate::scripts::actor::Actor;


pub fn bit_state<T: Actor>(actor: &mut T, identifier: &str, index: Option<u32>) -> Script {
	// TODO: validate size of preimage here 
	script! {
		OP_RIPEMD160
		OP_DUP
		{ actor.hashlock(identifier, index, 1) } // hash1
		OP_EQUAL
		OP_DUP
		OP_ROT
		{ actor.hashlock(identifier, index, 0) } // hash0
		OP_EQUAL
		OP_BOOLOR
		OP_VERIFY
	}
}

pub fn bit_state_commit<T: Actor>(actor: &mut T, identifier: &str, index: Option<u32>) -> Script {
	// TODO: validate size of preimage here 
	script! {
		OP_RIPEMD160
		OP_DUP
		{ actor.hashlock(identifier, index, 1) } // hash1
		OP_EQUAL
		OP_SWAP
		{ actor.hashlock(identifier, index, 0) } // hash0
		OP_EQUAL
		OP_BOOLOR
		OP_VERIFY
	}
}

pub fn bit_state_unlock<T: Actor>(actor: &mut T, identifier: &str, index: Option<u32>, value: u32) -> Script {
	script!{ {actor.preimage(identifier, index, value)} }
}

pub fn bit_state_justice<T: Actor>(actor: &mut T, identifier: &str, index: Option<u32>) -> Script {
	script!{
		OP_RIPEMD160
		{ actor.hashlock(identifier, index, 0) }  // hash0
		OP_EQUALVERIFY
		OP_SWAP
		OP_RIPEMD160
		{ actor.hashlock(identifier, index, 1) }  // hash1
		OP_EQUALVERIFY
	}
}

pub fn bit_state_justice_unlock<T: Actor>(actor: &mut T, identifier: &str, index: Option<u32>) -> Script {
	script!{
		{ actor.preimage(identifier, index, 1) }
		{ actor.preimage(identifier, index, 0) } 
	}
}




#[cfg(test)]
pub mod tests {
	use super::pushable;
	use bitcoin_script::bitcoin_script as script;

	use crate::scripts::actor::{ Player };
	use super::{bit_state, bit_state_unlock};
    use crate::scripts::opcodes::{execute_script};

	#[test]
	fn test_bit_state() {
		bit_state_test(0);
		bit_state_test(1);
	}
	
	fn bit_state_test(test_value : u32){
		let mut player = Player::new("d898098e09898a0980989b980809809809f09809884324874302975287524398");
		let test_identifier = "my_test_identifier";
		let script = script!{
			// Unlocking script
			{ bit_state_unlock(&mut player, test_identifier, None, test_value) }
			// Locking script
			{ bit_state(&mut player, test_identifier, None) }
			
			// Ensure the correct value was pushed onto the stack
			{test_value} OP_EQUAL
		};
		let result = execute_script(script);
		assert!(result.success);
	}


	
}
