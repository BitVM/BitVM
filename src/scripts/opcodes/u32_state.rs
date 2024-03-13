#![allow(dead_code)]

use super::pushable;
use crate::scripts::actor::Actor;
use crate::scripts::opcodes::unroll;
use bitcoin::opcodes::{OP_NOP, OP_TOALTSTACK};
use bitcoin::{ScriptBuf as Script, Opcode};
use bitcoin_script::bitcoin_script as script;

// The size of the preimage in bytes
const PREIMAGE_SIZE: u32 = 20;

pub fn bit_state<T: Actor>(actor: &mut T, identifier: &str, index: Option<u32>) -> Script {
    script! {
        // Validate size of the preimage
        OP_SIZE { PREIMAGE_SIZE } OP_EQUALVERIFY

        // Actual implementation
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
    script! {
        // Validate size of the preimage
        OP_SIZE { PREIMAGE_SIZE } OP_EQUALVERIFY

        // Actual implementation
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
    script! { { actor.preimage(identifier, index, value)} }
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
        // Validate size of the preimage
        OP_SIZE { PREIMAGE_SIZE } OP_EQUALVERIFY

        // Actual implementation
        OP_RIPEMD160
        OP_DUP
        { actor.hashlock(identifier, index, 3) } // hash3
        OP_EQUAL
        OP_IF
            OP_DROP
            3
        OP_ELSE
            OP_DUP
            { actor.hashlock(identifier, index, 2)}  // hash2
            OP_EQUAL
            OP_IF
                OP_DROP
                2
            OP_ELSE
                OP_DUP
                { actor.hashlock(identifier, index, 1)}  // hash1
                OP_EQUAL
                OP_IF
                    OP_DROP
                    1
                OP_ELSE
                    { actor.hashlock(identifier, index, 0)}  // hash0
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
    script! { { actor.preimage(identifier, index, value)} }
}

pub fn u2_state_commit<T: Actor>(actor: &mut T, identifier: &str, index: Option<u32>) -> Script {
    script! {
        // Validate size of the preimage
        OP_SIZE { PREIMAGE_SIZE } OP_EQUALVERIFY

        // Actual implementation
        OP_RIPEMD160

        OP_DUP
        { actor.hashlock(identifier, index, 3) } // hash3
        OP_EQUAL

        OP_OVER
        { actor.hashlock(identifier, index, 2) } // hash2
        OP_EQUAL
        OP_BOOLOR

        OP_OVER
        { actor.hashlock(identifier, index, 1) } // hash1
        OP_EQUAL
        OP_BOOLOR

        OP_SWAP
        { actor.hashlock(identifier, index, 0) } // hash0
        OP_EQUAL
        OP_BOOLOR
        OP_VERIFY
    }
}

pub fn u8_state<T: Actor>(actor: &mut T, identifier: &str) -> Script {
    script! {
        {unroll(4, |i| script!{
            { u2_state(actor, identifier, Some(3 - i)) }

            {
                if i == 0 {
                    script! {
                        OP_TOALTSTACK
                    }
                } else {
                    script! {
                        OP_FROMALTSTACK
                        OP_DUP
                        OP_ADD
                        OP_DUP
                        OP_ADD
                        OP_ADD
                        {
                            if i != 3 {
                                    OP_TOALTSTACK
                            } else {
                                    OP_NOP
                            }
                        }
                    }
                }
            }
        })
        // Now there's the u8 value on the stack
    }}
}

pub fn u8_state_commit<T: Actor>(actor: &mut T, identifier: &str) -> Script {
    script! {
        { u2_state_commit(actor, identifier, Some(3)) }
        { u2_state_commit(actor, identifier, Some(2)) }
        { u2_state_commit(actor, identifier, Some(1)) }
        { u2_state_commit(actor, identifier, Some(0)) }
    }
}

pub fn u8_state_unlock<T: Actor>(actor: &mut T, identifier: &str, value: u8) -> Script {
    let value = value as u32;
    script! {
        { actor.preimage(identifier, Some(0), value >> 0 & 0b11 ) }
        { actor.preimage(identifier, Some(1), value >> 2 & 0b11 ) }
        { actor.preimage(identifier, Some(2), value >> 4 & 0b11 ) }
        { actor.preimage(identifier, Some(3), value >> 6 & 0b11 ) }
    }
}

fn u32_id(identifier: &str, i: u32) -> String {
    format!("{identifier}_byte{i}")
}

pub fn u32_state<T: Actor>(actor: &mut T, identifier: &str) -> Script {
    script! {
        { u8_state(actor, &u32_id(identifier,0)) }
        OP_TOALTSTACK
        { u8_state(actor, &u32_id(identifier,1)) }
        OP_TOALTSTACK
        { u8_state(actor, &u32_id(identifier,2)) }
        OP_TOALTSTACK
        { u8_state(actor, &u32_id(identifier,3)) }
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_FROMALTSTACK
    }
}

pub fn u32_state_commit<T: Actor>(actor: &mut T, identifier: &str) -> Script {
    script! {
        { unroll(4, |i| u8_state_commit(actor, &u32_id(identifier, i))) }
    }
}

fn get_u8(value: u32, byte: u32) -> u8 {
    (value >> 8 * byte & 0xff)
        .try_into()
        .unwrap_or_else(|_| unreachable!())
}

pub fn u32_state_unlock<T: Actor>(actor: &mut T, identifier: &str, value: u32) -> Script {
    script! {
        { unroll(4, |i| u8_state_unlock(actor, &u32_id(identifier, 3 - i), get_u8(value, 3 - i))) }
    }
}

pub fn u2_state_bit0<T: Actor>(actor: &mut T, identifier: &str, index: Option<u32>) -> Script {
    script! {
        OP_RIPEMD160
        OP_DUP
        { actor.hashlock(identifier, index, 3) }// hash3
        OP_EQUAL
        OP_IF
            OP_DROP
            1
        OP_ELSE
            OP_DUP
            { actor.hashlock(identifier, index, 2) } // hash2
            OP_EQUAL
            OP_IF
                OP_DROP
                0
            OP_ELSE
                OP_DUP
                { actor.hashlock(identifier, index, 1) } // hash1
                OP_EQUAL
                OP_IF
                    OP_DROP
                    1
                OP_ELSE
                { actor.hashlock(identifier, index, 0) } // hash0
                    OP_EQUALVERIFY
                    0
                OP_ENDIF
            OP_ENDIF
        OP_ENDIF
    }
}

pub fn u2_state_bit1<T: Actor>(actor: &mut T, identifier: &str, index: Option<u32>) -> Script {
    script! {
        OP_RIPEMD160
        OP_DUP
        { actor.hashlock(identifier, index, 3) } // hash3
        OP_EQUAL
        OP_IF
            OP_DROP
            1
        OP_ELSE
            OP_DUP
            { actor.hashlock(identifier, index, 2) } // hash2
            OP_EQUAL
            OP_IF
                OP_DROP
                1
            OP_ELSE
                OP_DUP
                { actor.hashlock(identifier, index, 1) } // hash1
                OP_EQUAL
                OP_IF
                    OP_DROP
                    0
                OP_ELSE
                { actor.hashlock(identifier, index, 0) } // hash0
                    OP_EQUALVERIFY
                    0
                OP_ENDIF
            OP_ENDIF
        OP_ENDIF
    }
}

pub fn u2_state_bit<T: Actor>(
    actor: &mut T,
    identifier: &str,
    index: Option<u32>,
    bit_index: bool,
) -> Script {
    if bit_index {
        u2_state_bit1(actor, identifier, index)
    } else {
        u2_state_bit0(actor, identifier, index)
    }
}

pub fn u8_state_bit<T: Actor>(actor: &mut T, identifier: &str, bit_index: u8) -> Script {
    assert!(bit_index < 8);
    let index = (bit_index / 2).into();
    let is_odd = bit_index & 1 != 0;
    u2_state_bit(actor, identifier, Some(index), is_odd)
}

pub fn u8_state_bit_unlock<T: Actor>(
    actor: &mut T,
    identifier: &str,
    value: u8,
    bit_index: u8,
) -> Script {
    assert!(bit_index < 8);
    let index = (bit_index / 2).into();
    let child_value = value as u32 >> 2 * index & 0b11;
    u2_state_unlock(actor, identifier, Some(index), child_value)
}

pub fn u32_state_bit<T: Actor>(actor: &mut T, identifier: &str, bit_index: u8) -> Script {
    assert!(bit_index < 32);
    let byte_index = bit_index as u32 / 8;
    let child_identifier = &u32_id(identifier, byte_index);
    let child_bit_index = bit_index % 8;
    u8_state_bit(actor, child_identifier, child_bit_index)
}

pub fn u32_state_bit_unlock<T: Actor>(
    actor: &mut T,
    identifier: &str,
    value: u32,
    bit_index: u8,
) -> Script {
    assert!(bit_index < 32);
    let byte_index = bit_index as u32 / 8;
    let child_identifier = &u32_id(identifier, byte_index);
    let child_bit_index = bit_index % 8;
    let child_value = (value >> 8 * byte_index & 0xFF)
        .try_into()
        .unwrap_or_else(|_| unreachable!());
    u8_state_bit_unlock(actor, child_identifier, child_value, child_bit_index)
}

#[cfg(test)]
pub mod tests {
    use super::pushable;
    use bitcoin_script::bitcoin_script as script;

    use super::{
        bit_state, bit_state_unlock, u2_state, u2_state_unlock, u8_state, u8_state_unlock,
    };
    use crate::scripts::actor::tests::test_player;
    use crate::scripts::opcodes::execute_script;
    use crate::scripts::opcodes::u32_state::{u32_state_bit, u32_state_bit_unlock};

    #[test]
    fn test_bit_state() {
        bit_state_test(0);
        bit_state_test(1);
    }

    fn bit_state_test(test_value: u32) {
        let mut player = test_player();
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
        let mut player = test_player();
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

    #[test]
    fn test_u8_state() {
        u8_state_test(0);
        u8_state_test(1);
        u8_state_test(3);
        u8_state_test(128);
        u8_state_test(255);
    }

    fn u8_state_test(test_value: u32) {
        let mut player = test_player();
        let test_identifier = "my_test_identifier";
        let script = script! {
            // Unlocking script
            { u8_state_unlock(&mut player, test_identifier, test_value as u8) }
            // Locking script
            { u8_state(&mut player, test_identifier) }

            // Ensure the correct value was pushed onto the stack
            {test_value} OP_EQUAL
        };
        let result = execute_script(script);
        assert!(result.success);
    }

    #[test]
    fn test_u32_state_bit() {
        let mut player = test_player();
        let test_identifier = "my_test_identifier";
        let bit_index = 15;
        let value = 0b1000_0000_0000_0000;
        let script = script! {
            // Unlocking script
            { u32_state_bit_unlock(&mut player, test_identifier, value, bit_index) }
            // Locking script
            { u32_state_bit(&mut player, test_identifier, bit_index) }

            // Ensure the correct value was pushed onto the stack
            {1} OP_EQUAL
        };
        let result = execute_script(script);
        assert!(result.success);
    }
}
