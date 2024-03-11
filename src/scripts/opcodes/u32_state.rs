#![allow(dead_code)]

use super::pushable;
use crate::scripts::actor::Actor;
use bitcoin::ScriptBuf as Script;
use bitcoin_script::bitcoin_script as script;

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

pub fn bit_state_unlock<T: Actor>(
    actor: &mut T,
    identifier: &str,
    index: Option<u32>,
    value: u32,
) -> Script {
    script! { {actor.preimage(identifier, index, value)} }
}

pub fn bit_state_justice<T: Actor>(actor: &mut T, identifier: &str, index: Option<u32>) -> Script {
    script! {
        OP_RIPEMD160
        { actor.hashlock(identifier, index, 0) }  // hash0
        OP_EQUALVERIFY
        OP_SWAP
        OP_RIPEMD160
        { actor.hashlock(identifier, index, 1) }  // hash1
        OP_EQUALVERIFY
    }
}

pub fn bit_state_justice_unlock<T: Actor>(
    actor: &mut T,
    identifier: &str,
    index: Option<u32>,
) -> Script {
    script! {
        { actor.preimage(identifier, index, 1) }
        { actor.preimage(identifier, index, 0) }
    }
}

pub fn u2_state<T: Actor>(actor: &mut T, identifier: &str, index: Option<u32>) -> Script {
	script! {
		// TODO: validate size of preimage here
        OP_RIPEMD160
        OP_DUP
        {actor.hashlock(identifier, index, 3)} // hash3
        OP_EQUAL
        OP_IF
            OP_DROP
            3
        OP_ELSE
            OP_DUP
            {actor.hashlock(identifier, index, 2)}  // hash2
            OP_EQUAL
            OP_IF
                OP_DROP
                2
            OP_ELSE
                OP_DUP
                {actor.hashlock(identifier, index, 1)}  // hash1
                OP_EQUAL
                OP_IF
                    OP_DROP
                    1
                OP_ELSE
                    {actor.hashlock(identifier, index, 0)}  // hash0
                    OP_EQUALVERIFY
                    0
                OP_ENDIF
            OP_ENDIF
        OP_ENDIF
    }
}


pub fn u2_state_unlock<T: Actor>(
    actor: &mut T,
    identifier: &str,
    index: Option<u32>,
    value: u32,
) -> Script {
    script! { {actor.preimage(identifier, index, value)} }
}


#[cfg(test)]
pub mod tests {
    use super::pushable;
    use bitcoin_script::bitcoin_script as script;

    use super::{bit_state, bit_state_unlock, u2_state, u2_state_unlock};
    use crate::scripts::actor::Player;
    use crate::scripts::opcodes::execute_script;

    #[test]
    fn test_bit_state() {
        bit_state_test(0);
        bit_state_test(1);
    }

    fn bit_state_test(test_value: u32) {
        let mut player =
            Player::new("d898098e09898a0980989b980809809809f09809884324874302975287524398");
        let test_identifier = "my_test_identifier";
        let script = script! {
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

    #[test]
	fn test_u2_state() {
        u2_state_test(0);
        u2_state_test(1);
		u2_state_test(2);
		u2_state_test(3);
    }

    fn u2_state_test(test_value: u32) {
        let mut player =
            Player::new("d898098e09898a0980989b980809809809f09809884324874302975287524398");
        let test_identifier = "my_test_identifier";
        let script = script! {
            // Unlocking script
            { u2_state_unlock(&mut player, test_identifier, None, test_value) }
            // Locking script
            { u2_state(&mut player, test_identifier, None) }

            // Ensure the correct value was pushed onto the stack
            {test_value} OP_EQUAL
        };
        let result = execute_script(script);
        assert!(result.success);
    }
}
