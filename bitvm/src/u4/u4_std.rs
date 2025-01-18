use crate::treepp::{script, Script};
use bitcoin::{opcodes::all::*, Opcode};

/// u4 to altstack
pub fn u4_toaltstack(n: u32) -> Script {
    script! {
        for _ in 0..n {
            OP_TOALTSTACK
        }
    }
}

/// u4 from altstack
pub fn u4_fromaltstack(n: u32) -> Script {
    script! {
        for _ in 0..n {
            OP_FROMALTSTACK
        }
    }
}

/// Picks (or copies) an u32 number consisting of u4 elements from stack
pub fn u4_copy_u32_from(address: u32) -> Script {
    script! {
        for _ in 0..8 {
            { address + 7 }
            OP_PICK
        }
    }
}

/// Rolls (or gets) an u32 number consisting of u4 elements from stack
pub fn u4_move_u32_from(address: u32) -> Script {
    script! {
        for _ in 0..8 {
            { address + 7 }
            OP_ROLL
        }
    }
}

/// Checks if the top 2n elements have the period n, i.e. are in the form a, b, c ..., a, b, c ...
pub fn verify_n(n: u32) -> Script {
    script! {
        for i in 0..n {
            { n - i}
            OP_ROLL
            OP_EQUALVERIFY
        }
    }
}

/// Verifies if the u32 elements on the top of the altstack and the stack is the same
pub fn u4_u32_verify_from_altstack() -> Script {
    script! {
        for _ in 0..8 {
            OP_FROMALTSTACK
        }

        for i in 0..8 {
            { 8 - i}
            OP_ROLL
            OP_EQUALVERIFY
        }
    }
}

/// Drops n u4 (1 element) elements of the stack
pub fn u4_drop(n: u32) -> Script {
    script! {
        for _ in 0..n / 2 {
            OP_2DROP
        }
        if n & 1 == 1 {
            OP_DROP
        }
    }
}

/// Divides the number onto u4 parts and push them to the stack, least significant part being on the top
pub fn u4_number_to_nibble(n: u32) -> Script {
    script! {
       for i in (0..8).rev() {
            { (n >> (i * 4)) & 0xF }
        }
    }
}

/// Divides the hex number onto u4 parts and push them to the stack, least significant part being on the top
pub fn u4_hex_to_nibbles(hex_str: &str) -> Script {
    let nibbles: Result<Vec<u8>, std::num::ParseIntError> = hex_str
        .chars()
        .map(|c| u8::from_str_radix(&c.to_string(), 16))
        .collect();
    let nibbles = nibbles.unwrap();
    script! {
        for nibble in nibbles {
            { nibble }
        }
    }
}

/// Pushes the number n count times
pub fn u4_repeat_number(n: u32, count: u32) -> Script {
    match count {
        0 => script! {},
        1 => script! { { n } },
        2 => script! { { n } OP_DUP },
        _ => {
            let diff = count - 2;
            let count = diff / 2;
            let rem = diff % 2;
            script! {
                {u4_repeat_number(n, 2)}
                for _ in 0..count {
                    OP_2DUP
                }
                if rem == 1 {
                    OP_DUP
                }
            }
        }
    }
}

pub trait CalculateOffset {
    fn modify(&mut self, element: Opcode) -> Script;
}

impl CalculateOffset for i32 {
    /// To calculate the place of the tables on the stack, opcodes are pushed with this function in certain parts
    fn modify(&mut self, element: Opcode) -> Script {
        match element {
            OP_TOALTSTACK | OP_ADD => *self -= 1,
            OP_PICK => {} //pick replaces the value so it does not change the stack count
            OP_DUP => *self += 1,
            _ => {
                panic!("unexpected opcode: {:?}", element);
            }
        }
        
        Script::new("").push_opcode(element)
    }
}
#[cfg(test)]
mod tests {
    use crate::run;
    use crate::treepp::script;
    use crate::u4::u4_std::u4_number_to_nibble;
    use super::{u4_hex_to_nibbles, u4_repeat_number};

    #[test]
    fn test_repeat() {
        for n in 0..30 {
            let script = script! {
                { u4_repeat_number(1, n) }
                for _ in 0..n {
                    OP_DROP
                }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_number_to_nibble() {
        let script = script! {
            { u4_number_to_nibble(0xfedc8765) }
            5
            OP_EQUALVERIFY
            6
            OP_EQUALVERIFY
            7
            OP_EQUALVERIFY
            8
            OP_EQUALVERIFY
            12
            OP_EQUALVERIFY
            13
            OP_EQUALVERIFY
            14
            OP_EQUALVERIFY
            15
            OP_EQUALVERIFY
            OP_TRUE
        };
        run(script);
    }

    #[test]
    fn test_hex_to_nibble() {
        let script = script! {
            { u4_hex_to_nibbles("fedc8765")}
            5
            OP_EQUALVERIFY
            6
            OP_EQUALVERIFY
            7
            OP_EQUALVERIFY
            8
            OP_EQUALVERIFY
            12
            OP_EQUALVERIFY
            13
            OP_EQUALVERIFY
            14
            OP_EQUALVERIFY
            15
            OP_EQUALVERIFY
            OP_TRUE
        };
        run(script);
    }
}
