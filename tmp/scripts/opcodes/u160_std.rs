#![allow(dead_code)]

use crate::scripts::opcodes::{pushable, unroll};
use crate::scripts::opcodes::u32_std::{
    u32_equalverify, u32_fromaltstack, u32_push, u32_roll, u32_toaltstack,
};
use bitcoin::opcodes::{OP_FROMALTSTACK, OP_TOALTSTACK};
use bitcoin::ScriptBuf as Script;
use bitcoin_script::bitcoin_script as script;

use crate::utils::u160::u160;

pub fn u160_equalverify() -> Script {
        script! {
            {
                unroll(5, |i| script! {
                    { u32_roll(5 - i) }
                    u32_equalverify
                })
            }
        }
}

pub fn u160_equal() -> Script {
    script! {
        {
            unroll(20 - 1, |i| script!{
                { (20 - i) as u32 }
                OP_ROLL
                OP_EQUAL
                OP_NOT
                OP_TOALTSTACK
            })
        }
        OP_EQUAL
        OP_NOT
        {
            unroll(20 - 1, |_| script!{
                OP_FROMALTSTACK
                OP_BOOLOR
            })
        }
    }
}

pub fn u160_notequal() -> Script {
    script! {
        {
            unroll(20 - 1, |i| script!{
                { (20 - i) as u32 }
                OP_ROLL
                OP_EQUAL
                OP_NOT
                OP_TOALTSTACK
            })
        }
        OP_EQUAL
        OP_NOT
        {
            unroll(20 - 1, |_| script!{
                 OP_FROMALTSTACK
                 OP_BOOLOR
            })
        }
    }
}

// TODO confirm correct endiannes with js version
pub fn u160_push(value: u160) -> Script {
    script! {
        { u32_push(value[0]) }
        { u32_push(value[1]) }
        { u32_push(value[2]) }
        { u32_push(value[3]) }
        { u32_push(value[4]) }
    }
}

pub fn u160_swap_endian() -> Script {
    script! {
        { unroll(20, |i| script! {
            { 3 | i as u32 }
            OP_ROLL
        }) }
    }
}

pub fn u160_toaltstack() -> Script {
    script! {
        { unroll(20, |_| OP_TOALTSTACK) }
    }
}

pub fn u160_fromaltstack() -> Script {
    script! {
        { unroll(20, |_| OP_FROMALTSTACK) }
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////
//
#[cfg(test)]
mod tests {
    use crate::scripts::actor::{Actor, tests::test_player};
    use crate::scripts::opcodes::execute_script;
    use crate::utils::u160::from_hex;
    
    use super::*;

    #[test]
    fn test_u160_state() {
        let u160 = from_hex("0123456789abcdef0123456789abcdef01234567");
        let mut player = test_player();
        let script = script! {
            { player.u160_unlock(/* TEST_U160 */ 1337, u160) }
            { player.u160_push(/* TEST_U160 */ 1337) }
            { u160_push(u160) }
            u160_equalverify
            1
        };
        assert!(execute_script(script).success)
    }

    #[test]
    fn test_u160_push() {
        let u160_value = from_hex("0123456789abcdef0123456789abcdef01234567");
        let script = script! {
            { u160_push(u160_value) }

            0x67  OP_EQUALVERIFY
            0x45  OP_EQUALVERIFY
            0x23  OP_EQUALVERIFY
            0x01  OP_EQUALVERIFY
            0xef  OP_EQUALVERIFY
            0xcd  OP_EQUALVERIFY
            0xab  OP_EQUALVERIFY
            0x89  OP_EQUALVERIFY

            0x67  OP_EQUALVERIFY
            0x45  OP_EQUALVERIFY
            0x23  OP_EQUALVERIFY
            0x01  OP_EQUALVERIFY
            0xef  OP_EQUALVERIFY
            0xcd  OP_EQUALVERIFY
            0xab  OP_EQUALVERIFY
            0x89  OP_EQUALVERIFY

            0x67  OP_EQUALVERIFY
            0x45  OP_EQUALVERIFY
            0x23  OP_EQUALVERIFY
            0x01  OP_EQUAL
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success)
    }
}
