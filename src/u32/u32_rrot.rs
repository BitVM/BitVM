#![allow(dead_code)]

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

/// Right rotation of an u32 element by 2 bits
pub fn u32_rrot2() -> Script {
  script! {

    {u32_rrot12()} //12+8+7+7=34 mod 32=2
    {u32_rrot8()}
    {u32_rrot7()}
    {u32_rrot7()}

  }
}

/// Right rotation of an u32 element by 4 bits
pub fn u32_rrot4() -> Script {
  script! {

    {u32_rrot12()} //12+8+16=36 mod 32=4
    {u32_rrot8()}
    {u32_rrot16()}

  }
}

/// Right rotation of an u32 element by 13 bits
pub fn u32_rrot13() -> Script {
  script! {

    {u32_rrot12()} //12+8+16+7+2=45 mod 32=13
    {u32_rrot8()}
    {u32_rrot16()}
    {u32_rrot7()}
    {u32_rrot2()}
  }
}

/// Right rotation of an u32 element by 22 bits
pub fn u32_rrot22() -> Script {
  script! {

    {u32_rrot12()} //12+8+2=22 mod 32=22
    {u32_rrot8()}
    {u32_rrot2()}
  }
}

/// Right rotation of an u32 element by 6 bits
pub fn u32_rrot6() -> Script {
  script! {

    {u32_rrot2()} //2+2+2=6 mod 32=6
    {u32_rrot2()}
    {u32_rrot2()}
  }
}

/// Right rotation of an u32 element by 11 bits
pub fn u32_rrot11() -> Script {
  script! {

    {u32_rrot12()} //12+8+16+7=43 mod 32=11
    {u32_rrot8()}
    {u32_rrot16()}
    {u32_rrot7()}
  }
}

/// Right rotation of an u32 element by 25 bits
pub fn u32_rrot25() -> Script {
  script! {

    {u32_rrot16()} //16+16+16+2+7=57 mod 32=25
    {u32_rrot16()}
    {u32_rrot16()}
    {u32_rrot2()}
    {u32_rrot7()}
  }
}

/// Right rotation of an u32 element by 18 bits
pub fn u32_rrot18() -> Script {
  script! {

    {u32_rrot16()} //16+16+16+2=50 mod 32=18
    {u32_rrot16()}
    {u32_rrot16()}
    {u32_rrot2()}
  }
}

/// Right rotation of an u32 element by 3 bits
pub fn u32_rrot3() -> Script {
  script! {

    {u32_rrot12()} //12+8+12+8+12+8+7=67 mod 32=3
    {u32_rrot8()}
    {u32_rrot12()}
    {u32_rrot8()}
    {u32_rrot12()}
    {u32_rrot8()}
    {u32_rrot7()}
  }
}

/// Right rotation of an u32 element by 17 bits
pub fn u32_rrot17() -> Script {
  script! {

    {u32_rrot16()} //16+8+25=49 mod 32=17
    {u32_rrot8()}
    {u32_rrot25()}
  }
}

/// Right rotation of an u32 element by 19 bits
pub fn u32_rrot19() -> Script {
  script! {

    {u32_rrot16()} //16+3=19 mod 32=19
    {u32_rrot3()}
  }
}

/// Right rotation of an u32 element by 10 bits
pub fn u32_rrot10() -> Script {
  script! {

    {u32_rrot8()} //8+2=10 mod 32=10
    {u32_rrot2()}
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
    }
}

pub fn specific_debug(rot_num: usize) -> Option<Script> {
  let res: Option<Script> = match rot_num {
      0 => script! {}.into(),            // 0
      7 => script! {u32_rrot7}.into(),   // 86
      8 => script! {u32_rrot8}.into(),   // 3
      16 => script! {u32_rrot16}.into(), // 1
      24 => script! {3 OP_ROLL}.into(),  // 4

      2 => script! {u32_rrot2}.into(),   
      13 => script! {u32_rrot13}.into(),   
      22 => script! {u32_rrot22}.into(), 
      6 => script! {u32_rrot6}.into(),   
      11 => script! {u32_rrot11}.into(),   
      25 => script! {u32_rrot25}.into(), 
      18 => script! {u32_rrot18}.into(),   
      3 => script! {u32_rrot3}.into(), 
      17 => script! {u32_rrot17}.into(), 
      19 => script! {u32_rrot19}.into(),   
      10 => script! {u32_rrot10}.into(), 
      _ => None,
  };
  res
}

pub fn u32_rrot_debug(rot_num: usize) -> Script {
  assert!(rot_num < 32);
  match specific_debug(rot_num) {
      Some(res) => return res,
      None => {}
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
  }
}