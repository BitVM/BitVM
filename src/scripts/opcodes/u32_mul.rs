use crate::scripts::opcodes::pseudo::{OP_4DROP, OP_4DUP};
use crate::scripts::opcodes::u32_add::{u32_add, u32_add_drop};
use crate::scripts::opcodes::{pushable, unroll};
use bitcoin::ScriptBuf as Script;
use bitcoin_script::bitcoin_script as script;

pub fn u8_to_bits() -> Script {
    script! {
        OP_DUP
        127 OP_GREATERTHAN
        OP_SWAP OP_OVER
        OP_IF 128 OP_SUB OP_ENDIF
        OP_DUP
        63 OP_GREATERTHAN
        OP_SWAP OP_OVER
        OP_IF 64 OP_SUB OP_ENDIF
        OP_DUP
        31 OP_GREATERTHAN
        OP_SWAP OP_OVER
        OP_IF 32 OP_SUB OP_ENDIF
        OP_DUP
        15 OP_GREATERTHAN
        OP_SWAP OP_OVER
        OP_IF 16 OP_SUB OP_ENDIF
        OP_DUP
        7 OP_GREATERTHAN
        OP_SWAP OP_OVER
        OP_IF 8 OP_SUB OP_ENDIF
        OP_DUP
        3 OP_GREATERTHAN
        OP_SWAP OP_OVER
        OP_IF 4 OP_SUB OP_ENDIF
        OP_DUP
        1 OP_GREATERTHAN
        OP_SWAP OP_OVER
        OP_IF 2 OP_SUB OP_ENDIF
    }
}

pub fn u32_double() -> Script {
    script! {
        OP_4DUP
        { u32_add_drop(1, 0) }
    }
}

pub fn u32_to_bits() -> Script {
    script! {
        3 OP_ROLL
        { u8_to_bits() }
        10 OP_ROLL
        { u8_to_bits() }
        17 OP_ROLL
        { u8_to_bits() }
        24 OP_ROLL
        { u8_to_bits() }
    }
}

pub fn u32_mul_drop() -> Script {
    script! {
        { u32_to_bits() }
        0 0 0 0
        OP_TOALTSTACK OP_TOALTSTACK OP_TOALTSTACK OP_TOALTSTACK
        35 OP_ROLL 35 OP_ROLL 35 OP_ROLL 35 OP_ROLL
        {unroll(31, |_| script! {
            4 OP_ROLL
            OP_IF
                OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK
                { u32_add(1, 0) }
                OP_TOALTSTACK OP_TOALTSTACK OP_TOALTSTACK OP_TOALTSTACK
            OP_ENDIF
            { u32_double() }
        })}
        4 OP_ROLL
        OP_IF
            OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK
            { u32_add_drop(1, 0) }
            OP_TOALTSTACK OP_TOALTSTACK OP_TOALTSTACK OP_TOALTSTACK
        OP_ELSE
            OP_4DROP
        OP_ENDIF
        OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK
    }
}

#[cfg(test)]
mod test {
    use crate::scripts::opcodes::execute_script;
    use crate::scripts::opcodes::pushable;
    use crate::scripts::opcodes::u32_std::u32_push;
    use bitcoin::opcodes::OP_EQUALVERIFY;

    use super::*;

    #[test]
    fn test_u8_to_bits() {
        let u8_value = 0x34u32;

        let script = script! {
            { u8_value }
            { u8_to_bits() }
            { 0x00 } OP_EQUALVERIFY
            { 0x00 } OP_EQUALVERIFY
            { 0x01 } OP_EQUALVERIFY
            { 0x00 } OP_EQUALVERIFY
            { 0x01 } OP_EQUALVERIFY
            { 0x01 } OP_EQUALVERIFY
            { 0x00 } OP_EQUALVERIFY
            { 0x00 } OP_EQUAL
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success)
    }

    #[test]
    fn test_u32_to_bits() {
        let u32_value = 0x12345678u32;
        let script = script! {
            { u32_push(u32_value) }
            { u32_to_bits() }
            0 OP_EQUALVERIFY 0 OP_EQUALVERIFY 0 OP_EQUALVERIFY 1 OP_EQUALVERIFY
            1 OP_EQUALVERIFY 1 OP_EQUALVERIFY 1 OP_EQUALVERIFY 0 OP_EQUALVERIFY
            0 OP_EQUALVERIFY 1 OP_EQUALVERIFY 1 OP_EQUALVERIFY 0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY 0 OP_EQUALVERIFY 1 OP_EQUALVERIFY 0 OP_EQUALVERIFY
            0 OP_EQUALVERIFY 0 OP_EQUALVERIFY 1 OP_EQUALVERIFY 0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY 1 OP_EQUALVERIFY 0 OP_EQUALVERIFY 0 OP_EQUALVERIFY
            0 OP_EQUALVERIFY 1 OP_EQUALVERIFY 0 OP_EQUALVERIFY 0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY 0 OP_EQUALVERIFY 0 OP_EQUALVERIFY 0 OP_EQUAL
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success)
    }

    #[test]
    fn test_u32_double() {
        let u32_value = 0x12345678u32;
        let script = script! {
            { u32_push(u32_value) }
            { u32_double() }
            { 0xf0 } OP_EQUALVERIFY
            { 0xac } OP_EQUALVERIFY
            { 0x68 } OP_EQUALVERIFY
            { 0x24 } OP_EQUAL
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success)
    }

    #[test]
    fn test_u32_mul() {
        let u32_value_a = 0x12345678u32;
        let u32_value_b = 0x89abcdefu32;
        let script = script! {
            { u32_push(u32_value_a) }
            { u32_push(u32_value_b) }
            { u32_mul_drop() }
            { 0x08 } OP_EQUALVERIFY
            { 0xd2 } OP_EQUALVERIFY
            { 0x42 } OP_EQUALVERIFY
            { 0xe2 } OP_EQUAL
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success)
    }
}
