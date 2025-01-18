use crate::treepp::{script, Script};

/// Right rotation of an u32 element by 16 bits
pub fn u32_rrot16() -> Script {
    script! {
      OP_2SWAP
    }
}

/// Right rotation of an u32 element by 8 bits
pub fn u32_rrot8() -> Script {
    script! {
      OP_2SWAP
      3 OP_ROLL
    }
}

/// Right rotation of the i-th u8 element by 7 bits
pub fn u8_rrot7(i: u32) -> Script {
    let roll_script = match i {
        0 => script! {},
        1 => script! { OP_SWAP },
        2 => script! { OP_ROT },
        _ => script! { {i} OP_ROLL },
    };
    script! {
        { roll_script }
        128
        OP_2DUP
        OP_GREATERTHANOREQUAL
        OP_IF
            OP_SUB
            1
        OP_ELSE
            OP_DROP
            0
        OP_ENDIF
    }
}

/// Right rotation of an u32 element by 7 bits
pub fn u32_rrot7() -> Script {
    script! {
        // First Byte
        {u8_rrot7(0)}

        // Second byte
        {u8_rrot7(2)}

        OP_TOALTSTACK
        OP_DUP
        OP_ADD
        OP_ADD
        OP_FROMALTSTACK

        // Third byte
        {u8_rrot7(3)}

        OP_TOALTSTACK
        OP_DUP
        OP_ADD
        OP_ADD
        OP_FROMALTSTACK

        // Fourth byte
        {u8_rrot7(4)}

        OP_TOALTSTACK
        OP_DUP
        OP_ADD
        OP_ADD
        OP_FROMALTSTACK

        // Close the circle
        4 OP_ROLL
        OP_DUP
        OP_ADD
        OP_ADD

        OP_SWAP
        OP_2SWAP
        OP_SWAP
    }
}

/// Extracts (puts it at the top of the stack) the most significant bit of the u8 number and multiplies it by 2 modulo 256
pub fn u8_extract_1bit() -> Script {
    script! {
        OP_DUP
        OP_ADD
        256
        OP_2DUP
        OP_GREATERTHANOREQUAL
        OP_IF
            OP_SUB
            1
        OP_ELSE
            OP_DROP
            0
        OP_ENDIF
    }
}

/// Extracts (puts them at the top of the stack as the sum) the h most significant bits of the u8 number and multiplies it by 2^h modulo 256
pub fn u8_extract_hbit(hbit: usize) -> Script {
    assert!((1..8).contains(&hbit));
    if hbit == 1 {
        return u8_extract_1bit();
    }
    let x: u32 = 1 << (hbit - 1);
    script! {
        0
        OP_TOALTSTACK

        for i in 0..hbit
        {
            128
            OP_2DUP
            OP_GREATERTHANOREQUAL
            OP_IF
                OP_SUB
                OP_FROMALTSTACK
                { x >> i }
                OP_ADD
                OP_TOALTSTACK
                OP_DUP
            OP_ENDIF
            OP_DROP
            OP_DUP
            OP_ADD
        }

        OP_FROMALTSTACK
    }
}
/// Reorders (reverse and rotate) the bytes of an u32 number, assuming the starting order is 1 2 3 4 (4 being at the top): 
/// if offset is 0, then reorder is 4 3 2 1
/// if offset is 1, then reorder is 1 4 3 2
/// if offset is 2, then reorder is 2 1 4 3
/// if offset is 3, then reorder is 3 2 1 4 
pub fn byte_reorder(offset: usize) -> Script {
    assert!((0..4).contains(&offset));
    if offset == 0 {
        script! {
            OP_SWAP
            OP_2SWAP
            OP_SWAP
        }
    } else if offset == 1 {
        return script! {
            OP_SWAP
            OP_ROT
        };
    } else if offset == 2 {
        return script! {
            OP_SWAP
            OP_2SWAP
            OP_SWAP
            OP_2SWAP
        };
    } else /* if offset == 3 */ {
        return script! {
            OP_SWAP
            OP_ROT
            OP_2SWAP
        };
    }
}

/// Rotates the bits of a u32 number by rot_num
pub fn u32_rrot(rot_num: usize) -> Script {
    assert!((0..32).contains(&rot_num));
    let specific_optimize: Option<Script> = match rot_num {
        0 => script! {}.into(),            // 0
        7 => script! {u32_rrot7}.into(),   // 76
        8 => script! {u32_rrot8}.into(),   // 3
        16 => script! {u32_rrot16}.into(), // 1
        23 => script! {u32_rrot16 u32_rrot7}.into(),
        24 => script! {3 OP_ROLL}.into(), // 2
        _ => None,
    };

    if let Some(res) = specific_optimize {
        return res;
    }

    let remainder: usize = rot_num % 8;

    let hbit: usize = 8 - remainder;
    let offset: usize = (rot_num - remainder) / 8;

    script! {
        {u8_extract_hbit(hbit)}
        OP_ROT {u8_extract_hbit(hbit)}
        4 OP_ROLL {u8_extract_hbit(hbit)}
        6 OP_ROLL {u8_extract_hbit(hbit)}

        7 OP_ROLL
        OP_ADD
        OP_TOALTSTACK

        OP_ADD
        OP_TOALTSTACK

        OP_ADD
        OP_TOALTSTACK

        OP_ADD
        OP_TOALTSTACK

        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        {byte_reorder(offset)}
    }.add_stack_hint(-4, 0)
}

#[cfg(test)]
mod tests {
    use crate::run;
    use crate::treepp::script;
    use crate::u32::u32_rrot::*;
    use crate::u32::u32_std::*;
    use rand::Rng;

    fn rrot(x: u32, n: usize) -> u32 {
        if n == 0 {
            return x;
        }
        (x >> n) | (x << (32 - n))
    }

    #[test]
    fn test_rrot() {
        for i in 0..32 {
            println!("u32_rrot({}): {} bytes", i, u32_rrot(i).len());
        }
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            let x: u32 = rng.gen();
            for i in 0..32 {
                let script = script! {
                    {u32_push(x)}
                    {u32_rrot(i)}
                    {u32_push(rrot(x, i))}
                    {u32_equal()}
                };
                run(script);
            }
        }
    }
    #[test]
    fn test_extract_hbit() {
        for x in 0..256 {
            for h in 1..8 {
                let script = script! {
                    { x }
                    { u8_extract_hbit(h) }
                    { x >> (8 - h) }
                    OP_EQUALVERIFY
                    { (x << h) % 256 }
                    OP_EQUAL
                };
                run(script);
            }
        }
    }
}
