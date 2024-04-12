#![allow(dead_code)]

use core::panic;
use std::hint;

use bitcoin::opcodes::all::{
    OP_DROP, OP_DUP, OP_ELSE, OP_ENDIF, OP_FROMALTSTACK, OP_GREATERTHANOREQUAL, OP_TOALTSTACK,
};

use crate::treepp::{pushable, script, Script};

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

/// Right rotation of an u8 element by 12 bits
pub fn u8_rrot12() -> Script {
    script! {
      0
      OP_TOALTSTACK

      for i in 0..4
      {
          OP_DUP
          127
          OP_GREATERTHAN
          OP_IF
              128
              OP_SUB
              OP_FROMALTSTACK
              { 8 >> i }
              OP_ADD
              OP_TOALTSTACK
          OP_ENDIF

          OP_DUP
          OP_ADD
    }

      OP_FROMALTSTACK
    }
}

/// Right rotation of an u32 element by 12 bits
pub fn u32_rrot12() -> Script {
    script! {
                u8_rrot12
      2 OP_ROLL u8_rrot12
      4 OP_ROLL u8_rrot12
      6 OP_ROLL u8_rrot12

      //
      // Glue it all together
      //
      5 OP_ROLL
      6 OP_ROLL
      OP_ADD
      OP_SWAP

      6 OP_ROLL
      OP_ADD

      OP_ROT
      3 OP_ROLL
      OP_ADD

      4 OP_ROLL

      4 OP_ROLL
      OP_ADD
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

pub fn byte_reorder(offset: usize) -> Script {
    assert!(offset < 4);
    if offset == 0 {
        return script! {
            OP_SWAP
            OP_2SWAP
            OP_SWAP
        };
    } else if offset == 1 {
        return script! {
            OP_SWAP
            2 OP_ROLL
        };
    } else if offset == 2 {
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

pub fn u32_rrot(rot_num: usize) -> Script {
    assert!(rot_num < 32);
    let remainder: usize = rot_num % 8;

    let hbit: usize = 8 - remainder;
    let offset: usize = (rot_num - remainder) / 8;
    if remainder == 0 {
        match offset {
            0 => {
                return script! {};
            }
            1 => {
                return script! {{u32_rrot8()}};
            }
            2 => {
                return script! {{u32_rrot16()}};
            }
            3 => {
                return script! {{u32_rrot16()} {u32_rrot8()}};
            }
            _ => {
                panic!("offset out of range");
            }
        }
    }
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

/// rot and extract 6 high bit to stack: [rotted_low_bits, rotted_high_bits]
pub fn u8_extract_h4() -> Script {
    script! {
    for i in 0..4
    {
        128
        OP_2DUP
        OP_GREATERTHANOREQUAL
        OP_IF
            OP_SUB
            { 8 >> i }
        OP_ELSE
            OP_DROP
            { 0 }
        OP_ENDIF

        OP_TOALTSTACK
        OP_DUP
        OP_ADD
    }

    OP_FROMALTSTACK
    for _ in 0..3
    {
        OP_FROMALTSTACK
        OP_ADD
    }
    }
}

/// rot and extract 6 high bit to stack: [rotted_low_bits, rotted_high_bits]
pub fn u8_extract_h6() -> Script {
    script! {
    for i in 0..6
    {
        128
        OP_2DUP
        OP_GREATERTHANOREQUAL
        OP_IF
            OP_SUB
            { 32 >> i }
            OP_TOALTSTACK
        OP_ELSE
            OP_DROP
            { 0 }
            OP_TOALTSTACK
        OP_ENDIF

        OP_DUP
        OP_ADD
    }

    OP_FROMALTSTACK
    for _ in 0..5
    {
        OP_FROMALTSTACK
        OP_ADD
    }
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::opcodes::all::{
        OP_2OVER, OP_2SWAP, OP_ADD, OP_FROMALTSTACK, OP_ROLL, OP_SWAP, OP_TOALTSTACK,
    };

    use crate::treepp::{execute_script, script};
    use crate::u32::u32_rrot::*;
    use crate::u32::u32_std::*;
    use crate::ExecuteInfo;
    use rand::Rng;

    fn rrot(x: u32, n: usize) -> u32 {
        if n == 0 {
            return x;
        }
        (x >> n) | (x << (32 - n))
    }

    fn top_u32(info: &ExecuteInfo, i: usize) -> u32 {
        u32::from_be_bytes([
            if info.final_stack.get(0 + 4 * i).len() == 0 {
                0
            } else {
                info.final_stack.get(0 + 4 * i)[0]
            },
            if info.final_stack.get(1 + 4 * i).len() == 0 {
                0
            } else {
                info.final_stack.get(1 + 4 * i)[0]
            },
            if info.final_stack.get(2 + 4 * i).len() == 0 {
                0
            } else {
                info.final_stack.get(2 + 4 * i)[0]
            },
            if info.final_stack.get(3 + 4 * i).len() == 0 {
                0
            } else {
                info.final_stack.get(3 + 4 * i)[0]
            },
        ])
    }

    #[test]
    fn test_u8_rrot2() {
        let x: u32 = 0x83848586;
        println!(
            "x >> 12 : {:X}, x >> 10: {:X}, x >> 2: {:X}",
            rrot(x, 12),
            rrot(x, 10),
            rrot(x, 2)
        );

        let exec_script = script! {
            {u32_push(x)}
            u8_extract_h6
            2 OP_ROLL u8_extract_h6
            4 OP_ROLL u8_extract_h6
            6 OP_ROLL u8_extract_h6

            OP_TOALTSTACK
            OP_ADD

            1 OP_ROLL
            2 OP_ROLL
            OP_ADD

            2 OP_ROLL
            3 OP_ROLL
            OP_ADD

            3 OP_ROLL
            OP_FROMALTSTACK
            OP_ADD

            {u32_rrot8()}
        };

        let res = execute_script(exec_script);
        println!("final stack: {:100}, top ele: {:X}", res, top_u32(&res, 0));
    }

    #[test]
    fn test_u8_rrot12() {
        let x: u32 = 0x83848586;
        println!(
            "x >> 4 : {:X}, x >> 12: {:X}, x >> 20: {:X}, x >> 28: {:X}",
            rrot(x, 4),
            rrot(x, 12),
            rrot(x, 20),
            rrot(x, 28)
        );

        let y: u32 = 0x58683848;

        let exec_script = script! {
            {u32_push(x)}
            u8_rrot12
            2 OP_ROLL u8_rrot12
            4 OP_ROLL u8_rrot12
            6 OP_ROLL u8_rrot12

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

            /* for origin + 8
            OP_SWAP
            2 OP_ROLL
            */

            /* for origin + 16
            OP_SWAP
            OP_2SWAP
            OP_SWAP
            OP_2SWAP
            */

            /* for origin + 24
            OP_SWAP
            OP_ROT
            OP_2SWAP
            */

            // {u32_push(y)}

            // {u32_equal()}


            /* for origin
            OP_SWAP
            OP_2SWAP
            OP_SWAP
            */

        };

        println!(
            "new exec_script size: {}, u8_h4: {}",
            exec_script.len(),
            u8_extract_h4().len()
        );
        println!(
            "old exec_script size: {}, u8_rrot12: {}",
            u32_rrot12().len(),
            u8_rrot12().len()
        );

        println!("{}", exec_script.to_asm_string());
        println!("{}", u32_rrot(12).to_asm_string());

        let res = execute_script(exec_script);
        println!("final stack: {:100}, top ele: {:X}", res, top_u32(&res, 0));
    }

    #[test]
    fn test_rrot() {
        // let x: u32 = 0x83848586;
        for _ in 0..100 {
            let mut rng = rand::thread_rng();
            let x: u32 = rng.gen();
            println!("x is {}", x);
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
        // // println!("final stack: {:100}, top ele: {:X}", res, top_u32(&res, 0));
        // println!(
        // "x >> 4 : {:X}, x >> 12: {:X}, x >> 20: {:X}, x >> 28: {:X}",
        // rrot(x, 4),
        // rrot(x, 12),
        // rrot(x, 20),
        // rrot(x, 28)
        // );
        // let exec_script = script! {
        // {u32_push(x)}
        // {u32_rrot(12)}
        // };
        // let res = execute_script(exec_script);
        // println!("final stack: {:100}, top ele: {:X}", res, top_u32(&res, 0));
    }

    #[test]
    fn test_length() {
        for i in 0..32 {
            println!("{} length is {}", i, u32_rrot(i).len());
        }

        println!("u32_rrot7 length is {}", u32_rrot7().len());
        println!("u32_rrot8 length is {}", u32_rrot8().len());
        println!("u32_rrot12 length is {}", u32_rrot12().len());
        println!("u32_rrot16 length is {}", u32_rrot16().len());

        println!("u32_rrot7 asm is {}", u8_rrot7(0).to_asm_string());
        println!("extract_hbit asm is {}", u8_extract_hbit(1));
    }
}
