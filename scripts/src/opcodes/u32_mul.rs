use crate::opcodes::{pushable, unroll};
use bitcoin::ScriptBuf as Script;
use bitcoin_script::bitcoin_script as script;
use crate::opcodes::pseudo::OP_256MUL;


pub fn u8_to_u16() -> Script {
    script! {
        OP_SWAP
        OP_256MUL
        OP_ADD
    }
}

pub fn u32_to_u32compact() -> Script {
    script! {
        OP_TOALTSTACK OP_TOALTSTACK
        u8_to_u16
        OP_FROMALTSTACK OP_FROMALTSTACK
        u8_to_u16
    }
}

pub fn u8_to_bits() -> Script {
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
    })
}

/// Zip the top two u32 elements
/// input:  a0 a1 b0 b1
/// output: a0 b0 a1 b1
pub fn u32compact_zip(mut a: u32, mut b: u32) -> Script {
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
pub fn u32compact_copy_zip(a: u32, b: u32) -> Script {
    if a < b {
        _u32compact_copy_zip(a, b)
    } else {
        _u32compact_zip_copy(b, a)
    }
}

pub fn _u32compact_copy_zip(mut a: u32, mut b: u32) -> Script {
    assert!(a < b);

    a = (a + 1) * 2 - 1;
    b = (b + 1) * 2 - 1;

    script! {
        {a+0} OP_PICK {b+1} OP_ROLL
        {a+1} OP_PICK {b+2} OP_ROLL
    }
}

pub fn _u32compact_zip_copy(mut a: u32, mut b: u32) -> Script {
    assert!(a < b);

    a = (a + 1) * 2 - 1;
    b = (b + 1) * 2 - 1;
    script! {
        {a+0} OP_ROLL {b} OP_PICK
        {a+1} OP_ROLL {b} OP_PICK
    }
}

pub fn u16_add_carrier() -> Script {
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

pub fn u16_add() -> Script {
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

pub fn u32compact_add(a: u32, b: u32) -> Script {
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

pub fn u32compact_add_drop(a: u32, b: u32) -> Script {
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

pub fn u32compact_double() -> Script {
    script! {
        OP_2DUP
        { u32compact_add_drop(1, 0) }
    }
}

pub fn u32_to_bits() -> Script {
    script! {
        3 OP_ROLL
        u8_to_bits
        10 OP_ROLL
        u8_to_bits
        17 OP_ROLL
        u8_to_bits
        24 OP_ROLL
        u8_to_bits
    }
}

pub fn u32compact_mul_drop() -> Script {
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

pub fn u16_to_u8() -> Script {
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

pub fn u32compact_to_u32() -> Script {
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
