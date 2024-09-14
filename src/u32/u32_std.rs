#![allow(dead_code)]

use crate::pseudo::{push_to_stack, OP_256MUL, OP_4DUP};

use crate::treepp::{script, Script};

/// Pushes a value as u32 element onto the stack
pub fn u32_push(value: u32) -> Script {
    script! {
        //optimization
        if (value >> 24 & 0xff) == (value >> 16 & 0xff) &&
            (value >> 24 & 0xff) == (value >> 8 & 0xff) &&
            (value >> 24 & 0xff) == (value & 0xff) {

                { push_to_stack((value >> 24 & 0xff) as usize,4) }
        }
        else{

                {value >> 24 & 0xff}
                {value >> 16 & 0xff}
                {value >>  8 & 0xff}
                {value & 0xff}
        }
    }
}

/// Marks transaction as invalid if the top two stack value are not equal
pub fn u32_equalverify() -> Script {
    script! {
        4
        OP_ROLL
        OP_EQUALVERIFY
        3
        OP_ROLL
        OP_EQUALVERIFY
        OP_ROT
        OP_EQUALVERIFY
        OP_EQUALVERIFY
    }
}
/// Returns 1 if the top two u32 are equal, 0 otherwise
pub fn u32_equal() -> Script {
    script! {
        4
        OP_ROLL
        OP_EQUAL OP_TOALTSTACK
        3
        OP_ROLL
        OP_EQUAL OP_TOALTSTACK
        OP_ROT
        OP_EQUAL OP_TOALTSTACK
        OP_EQUAL
        OP_FROMALTSTACK OP_BOOLAND
        OP_FROMALTSTACK OP_BOOLAND
        OP_FROMALTSTACK OP_BOOLAND
    }
}

/// Returns 1 if the top two u32 are not equal, 0 otherwise
pub fn u32_notequal() -> Script {
    script! {
        4
        OP_ROLL
        OP_NUMNOTEQUAL OP_TOALTSTACK
        3
        OP_ROLL
        OP_NUMNOTEQUAL OP_TOALTSTACK
        OP_ROT
        OP_NUMNOTEQUAL OP_TOALTSTACK
        OP_NUMNOTEQUAL
        OP_FROMALTSTACK OP_BOOLOR
        OP_FROMALTSTACK OP_BOOLOR
        OP_FROMALTSTACK OP_BOOLOR
    }
}

/// Puts the top u32 element onto the top of the alt stack. Removes it from the main stack.
pub fn u32_toaltstack() -> Script {
    script! {
        OP_TOALTSTACK
        OP_TOALTSTACK
        OP_TOALTSTACK
        OP_TOALTSTACK
    }
}

/// Puts the top u32 element of the alt stack onto the top of the main stack. Removes it from the alt stack.
pub fn u32_fromaltstack() -> Script {
    script! {
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_FROMALTSTACK
    }
}

/// Duplicates the top u32 stack element
pub fn u32_dup() -> Script {
    script! { OP_4DUP }
}

/// Removes the top u32 element from the stack.
pub fn u32_drop() -> Script {
    script! {
        OP_2DROP
        OP_2DROP
    }
}

/// The u32 element n back in the stack is moved to the top.
pub fn u32_roll(n: u32) -> Script {
    let n = (n + 1) * 4 - 1;
    script! {
        {n} OP_ROLL
        {n} OP_ROLL
        {n} OP_ROLL
        {n} OP_ROLL
    }
}

/// The u32 element n back in the stack is copied to the top.
pub fn u32_pick(n: u32) -> Script {
    let n = (n + 1) * 4 - 1;
    script! {
        {n} OP_PICK
        {n} OP_PICK
        {n} OP_PICK
        {n} OP_PICK
    }
}

/// The top u32 element is compressed into a single 4-byte word
pub fn u32_compress() -> Script {
    script! {
        OP_SWAP
        OP_ROT
        3
        OP_ROLL
        OP_DUP
        127
        OP_GREATERTHAN
        OP_IF
            128
            OP_SUB
            1
        OP_ELSE
            0
        OP_ENDIF
        OP_TOALTSTACK
        OP_256MUL
        OP_ADD
        OP_256MUL
        OP_ADD
        OP_256MUL
        OP_ADD
        OP_FROMALTSTACK
        OP_IF
            OP_NEGATE
        OP_ENDIF
    }
}

#[cfg(test)]
mod test {

    use crate::run;
    use crate::treepp::script;
    use crate::u32::u32_std::*;
    use rand::Rng;

    #[test]
    fn test_u32_push() {
        let script = script! {
            { u32_push(0x01020304) }
            0x04
            OP_EQUALVERIFY
            0x03
            OP_EQUALVERIFY
            0x02
            OP_EQUALVERIFY
            0x01
            OP_EQUAL
        };
        run(script);
    }

    #[test]
    fn test_with_u32_compress() {
        let mut rng = rand::thread_rng();

        for _ in 0..30 {
            let mut origin_value0: u32 = rng.gen();
            origin_value0 = (origin_value0 % 1) << 31;
            let mut origin_value1: u32 = rng.gen();
            origin_value1 = (origin_value1 % 1) << 31;

            let v = origin_value0 + origin_value1;

            let script = script! {
                { u32_push(origin_value0)}
                { u32_compress()}
                { u32_push(origin_value1)}
                { u32_compress()}
                OP_ADD
                { u32_push(v)}
                { u32_compress()}
                OP_EQUAL

            };

            run(script);
        }
    }
}
