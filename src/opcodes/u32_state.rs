#![allow(dead_code)]

use super::pushable;
use super::unroll;
use bitcoin::ScriptBuf as Script;
use bitcoin_script::bitcoin_script as script;
use super::super::actor::Actor;

// TODO: Implement actor class and copy over rest of this file from the javascript bitvm
// implementation

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

#[cfg(test)]
pub mod tests {
	#[test]
	fn test_bit_state() {
		//TODO: Create Player and run bit_state script


	}
}
