#![allow(dead_code)]

use crate::treepp::{pushable, script, Script};
use core::panic;

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

/// Right rotation of an u8 element by 7 bits
pub fn u8_rrot7(i: u32) -> Script {
    script! {
      {i} OP_ROLL
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
    }
}

/// Right rotation of an u32 element by 7 bits
pub fn u32_rrot7() -> Script {
    script! {

      // First Byte
      {u8_rrot7(0)}

      // Second byte
      {u8_rrot7(2)}

      OP_SWAP
      OP_DUP
      OP_ADD
      OP_ROT
      OP_ADD
      OP_SWAP

      // Third byte
      {u8_rrot7(3)}

      OP_SWAP
      OP_DUP
      OP_ADD
      OP_ROT
      OP_ADD
      OP_SWAP

      // Fourth byte
      {u8_rrot7(4)}

      OP_SWAP
      OP_DUP
      OP_ADD
      OP_ROT
      OP_ADD
      OP_SWAP

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

pub fn u8_extract_1bit() -> Script {
    script! {
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

      OP_TOALTSTACK

      OP_DUP
      OP_ADD

      OP_FROMALTSTACK
    }
}

pub fn u8_extract_hbit(hbit: usize) -> Script {
    assert!(hbit < 8 && hbit != 0);
    if hbit == 1 {
        return u8_extract_1bit();
    }
    let base: usize = 2;
    let x: usize = base.pow((hbit - 1).try_into().unwrap());
    script! {
        0
        OP_TOALTSTACK

        for i in 0..hbit
        {
            OP_DUP
            127
            OP_GREATERTHAN
            OP_IF
                128
                OP_SUB
                OP_FROMALTSTACK
                { x >> i }
                OP_ADD
                OP_TOALTSTACK
            OP_ENDIF

            OP_DUP
            OP_ADD
        }

        OP_FROMALTSTACK
    }
}
// 1 2 3 4
pub fn byte_reorder(offset: usize) -> Script {
    assert!(offset < 4);
    if offset == 0 {
        // 4 3 2 1
        return script! {
            OP_SWAP
            OP_2SWAP
            OP_SWAP
        };
    } else if offset == 1 {
        // 1 4 3 2
        return script! {
            OP_SWAP
            OP_ROT
        };
    } else if offset == 2 {
        // 2 1 4 3
        return script! {
            OP_SWAP
            OP_2SWAP
            OP_SWAP
            OP_2SWAP
        };
    } else if offset == 3 {
        return script! {
            OP_SWAP
            OP_ROT
            OP_2SWAP
        };
    } else {
        panic!("offset out of range")
    }
}

pub fn specific_optimize(rot_num: usize) -> Option<Script> {
    let res: Option<Script> = match rot_num {
        0 => script! {}.into(),            // 0
        7 => script! {u32_rrot7}.into(),   // 86
        8 => script! {u32_rrot8}.into(),   // 3
        16 => script! {u32_rrot16}.into(), // 1
        24 => script! {3 OP_ROLL}.into(),  // 4
        _ => None,
    };
    res
}

pub fn u32_rrot(rot_num: usize) -> Script {
    assert!(rot_num < 32);
    match specific_optimize(rot_num) {
        Some(res) => return res,
        None => {}
    }
    let remainder: usize = rot_num % 8;

    let hbit: usize = 8 - remainder;
    let offset: usize = (rot_num - remainder) / 8;

    script! {
        {u8_extract_hbit(hbit)}
        2 OP_ROLL {u8_extract_hbit(hbit)}
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
    }
}

#[cfg(test)]
mod tests {

    use crate::treepp::{execute_script, script};
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
        for _ in 0..100 {
            let mut rng = rand::thread_rng();
            let x: u32 = rng.gen();
            for i in 0..32 {
                let exec_script = script! {
                    {u32_push(x)}
                    {u32_rrot(i)}
                    {u32_push(rrot(x, i))}
                    {u32_equal()}
                };
                let res = execute_script(exec_script);
                assert_eq!(res.success, true);
            }
        }
    }
}
