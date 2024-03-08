#![allow(dead_code)]

use super::pushable;
use bitcoin::ScriptBuf as Script;
use bitcoin_script::bitcoin_script as script;
use super::super::actor::Actor;



pub fn bit_state<T: Actor>(mut actor: T, identifier: &str, index: Option<u32>) -> Script {
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

pub fn bit_state_commit<T: Actor>(mut actor: T, identifier: &str, index: Option<u32>) -> Script {
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

pub fn bit_state_unlock<T: Actor>(mut actor: T, identifier: &str, value: u32, index: Option<u32>) -> Script {
	script!{ {actor.preimage(identifier, index, value)} }
} 

pub fn bit_state_justice<T: Actor>(mut actor: T, identifier: &str, index: Option<u32>) -> Script {
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

pub fn bit_state_justice_unlock<T: Actor>(mut actor: T, identifier: &str, index: Option<u32>) -> Script {
	script!{
		{ actor.preimage(identifier, index, 1) }
		{ actor.preimage(identifier, index, 0) } 
	}
}


#[cfg(test)]
pub mod tests {
	use crate::actor:: {Player, Opponent};
	use super::bit_state;

	#[test]
	fn test_bit_state() {
		//TODO: Create Player and run bit_state script


		let opponent = Opponent::new();
		let player = Player::new("d898098e09898a0980989b980809809809f09809884324874302975287524398", &opponent);
		let script = bit_state(player, "test", None);
		println!("{:?}", script);
		assert!(true)
	}
}
