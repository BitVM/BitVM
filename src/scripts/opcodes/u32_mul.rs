use crate::scripts::opcodes::{pushable, unroll};
use bitcoin::ScriptBuf as Script;
use bitcoin_script::bitcoin_script as script;
use crate::scripts::opcodes::pseudo::OP_256MUL;


fn u8_to_u16() -> Script {
    script! {
        OP_SWAP
        OP_256MUL
        OP_ADD
    }
}

fn u32_to_u32compact() -> Script {
    script! {
        OP_TOALTSTACK OP_TOALTSTACK
        u8_to_u16
        OP_FROMALTSTACK OP_FROMALTSTACK
        u8_to_u16
    }
}

fn u8_to_bits() -> Script {
    script! {
        {
            unroll(7, |i| {
                let a = 1 << (7 - i);
                script! {
                    OP_DUP
                    { a } OP_GREATERTHANOREQUAL
                    OP_SWAP OP_OVER
                    OP_IF 
                        { a } OP_SUB 
                    OP_ENDIF
                }
        })}
    }
}

/// Zip the top two u32 elements
/// input:  a0 a1 b0 b1
/// output: a0 b0 a1 b1
fn u32compact_zip(mut a: u32, mut b: u32) -> Script {
    if a > b {
        (a, b) = (b, a);
    }

    a = (a + 1) * 2 - 1;
    b = (b + 1) * 2 - 1;

    script! {
        {a+0} OP_ROLL {b} OP_ROLL
        {a+1} OP_ROLL {b} OP_ROLL
    }
}

/// Copy and zip the top two u32 elements
/// input:  a0 a1 b0 b1
/// output: a0 b0 a1 b1 a0 a1
fn u32compact_copy_zip(a: u32, b: u32) -> Script {
    if a < b {
        _u32compact_copy_zip(a, b)
    } else {
        _u32compact_zip_copy(b, a)
    }
}

fn _u32compact_copy_zip(mut a: u32, mut b: u32) -> Script {
    assert!(a < b);

    a = (a + 1) * 2 - 1;
    b = (b + 1) * 2 - 1;

    script! {
        {a+0} OP_PICK {b+1} OP_ROLL
        {a+1} OP_PICK {b+2} OP_ROLL
    }
}

fn _u32compact_zip_copy(mut a: u32, mut b: u32) -> Script {
    assert!(a < b);

    a = (a + 1) * 2 - 1;
    b = (b + 1) * 2 - 1;
    script! {
        {a+0} OP_ROLL {b} OP_PICK
        {a+1} OP_ROLL {b} OP_PICK
    }
}

fn u16_add_carrier() -> Script {
    script! {
        OP_ADD
        OP_DUP
        65535
        OP_GREATERTHAN
        OP_IF
            65536
            OP_SUB
            1
        OP_ELSE
            0
        OP_ENDIF
    }
}

fn u16_add() -> Script {
    script! {
        OP_ADD
        OP_DUP
        65535
        OP_GREATERTHAN
        OP_IF
            65536
            OP_SUB
        OP_ENDIF
    }
}

fn u32compact_add(a: u32, b: u32) -> Script {
    assert_ne!(a, b);
    script! {
        {u32compact_copy_zip(a, b)}

        // A0 + B0
        u16_add_carrier
        OP_SWAP
        OP_TOALTSTACK

        // A1 + B1 + carry_0
        OP_ADD
        u16_add

        OP_FROMALTSTACK

        // Now there's the result C_1 C_0 on the stack
    }
}

fn u32compact_add_drop(a: u32, b: u32) -> Script {
    assert_ne!(a, b);
    script! {
        {u32compact_zip(a, b)}

        // A0 + B0
        u16_add_carrier
        OP_SWAP
        OP_TOALTSTACK

        // A1 + B1 + carry_0
        OP_ADD
        u16_add

        OP_FROMALTSTACK
        // Now there's the result C_1 C_0 on the stack
    }
}

fn u32compact_double() -> Script {
    script! {
        OP_2DUP
        { u32compact_add_drop(1, 0) }
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

fn u32compact_mul_drop() -> Script {
    script! {
        u32_to_bits
        0 0
        OP_TOALTSTACK OP_TOALTSTACK
        33 OP_ROLL 33 OP_ROLL
        {unroll(31, |_| script! {
            2 OP_ROLL
            OP_IF
                OP_FROMALTSTACK OP_FROMALTSTACK
                { u32compact_add(1, 0) }
                OP_TOALTSTACK OP_TOALTSTACK
            OP_ENDIF
            u32compact_double
        })}
        2 OP_ROLL
        OP_IF
            OP_FROMALTSTACK OP_FROMALTSTACK
            { u32compact_add_drop(1, 0) }
            OP_TOALTSTACK OP_TOALTSTACK
        OP_ELSE
            OP_2DROP
        OP_ENDIF
        OP_FROMALTSTACK OP_FROMALTSTACK
    }
}

fn u16_to_u8() -> Script {
    script! {
        0 OP_TOALTSTACK
        { unroll(7, |i| {
            let a = 1 << (15 - i);
            let b = a - 1;
            let c = 1 << (7 - i);
            script! {
                OP_DUP
                { b } OP_GREATERTHAN
                OP_IF
                    { a } OP_SUB
                    OP_FROMALTSTACK { c } OP_ADD OP_TOALTSTACK
                OP_ENDIF
            }
        })}
        OP_DUP
        255 OP_GREATERTHAN
        OP_IF
            256 OP_SUB
            OP_FROMALTSTACK OP_1ADD OP_TOALTSTACK
        OP_ENDIF
        OP_FROMALTSTACK
        OP_SWAP
    }
}

fn u32compact_to_u32() -> Script {
    script! {
        OP_TOALTSTACK
        u16_to_u8
        OP_FROMALTSTACK
        u16_to_u8
    }
}

pub fn u32_mul_drop() -> Script {
    script! {
        OP_TOALTSTACK OP_TOALTSTACK OP_TOALTSTACK OP_TOALTSTACK
        u32_to_u32compact
        OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK
        u32compact_mul_drop
        u32compact_to_u32
    }
}

#[cfg(test)]
mod test{
    use crate::scripts::opcodes::execute_script;
    use crate::scripts::opcodes::u32_std::u32_push;
    use super::*;

    #[test]
    fn test_u8_to_bits() {
        let u8_value = 0x34u32;

        let script = script! {
            {u8_value}
            u8_to_bits
            0 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            0 OP_EQUAL
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success)
    }

    #[test]
    fn test_u32_to_bits() {
        let u32_value = 0x12345678u32;
        let script = script! {
            { u32_push(u32_value) }
            u32_to_bits
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
    fn test_u32_to_u32compact() {
        let u32_value = 0x12345678u32;
        let script = script! {
            { u32_push(u32_value) }
            u32_to_u32compact
            0x5678 OP_EQUALVERIFY
            0x1234 OP_EQUAL
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success)
    }

    #[test]
    fn test_u32compact_to_u32() {
        let u32_value = 0x12345678u32;
        let script = script! {
            { u32_push(u32_value) }
            u32_to_u32compact
            u32compact_to_u32
            0x78 OP_EQUALVERIFY
            0x56 OP_EQUALVERIFY
            0x34 OP_EQUALVERIFY
            0x12 OP_EQUAL
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success)
    }

    #[test]
    fn test_u32compact_double() {
        let u32_value = 0x12345678u32;
        let script = script! {
            { u32_push(u32_value) }
            u32_to_u32compact
            u32compact_double
            0xacf0 OP_EQUALVERIFY
            0x2468 OP_EQUAL
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success)
    }

    #[test]
    fn test_u32compact_add() {
        let u32_value_a = 0xFFEEFFEEu32;
        let u32_value_b = 0xEEFFEEFFu32;

        let script = script! {
            { u32_push(u32_value_a) }
            u32_to_u32compact
            { u32_push(u32_value_b) }
            u32_to_u32compact
            { u32compact_add_drop(1, 0) }
            0xeeed OP_EQUALVERIFY
            0xeeee OP_EQUAL
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success)
    }

    #[test]
    fn test_u32compact_mul() {
        let u32_value_a = 0x12345678u32;
        let u32_value_b = 0x89abcdefu32;
        let script = script! {
            { u32_push(u32_value_a) }
            u32_to_u32compact
            { u32_push(u32_value_b) }
            u32compact_mul_drop
            0xd208 OP_EQUALVERIFY
            0xe242 OP_EQUAL
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
            u32_mul_drop
            0x08 OP_EQUALVERIFY
            0xd2 OP_EQUALVERIFY
            0x42 OP_EQUALVERIFY
            0xe2 OP_EQUAL
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success)
    }
}
