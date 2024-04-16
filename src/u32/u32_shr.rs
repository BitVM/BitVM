#![allow(dead_code)]

use bitcoin::opcodes::all::{OP_2DROP, OP_DROP, OP_DUP, OP_ELSE, OP_FROMALTSTACK, OP_TOALTSTACK};

use crate::treepp::{pushable, script, Script};
use core::panic;
use crate::u32::{
    u32_and::*,
    u32_rrot::*,
    u32_std::*,
};

/// Right shift of an u32 element by 16 bits
pub fn u32_shr16() -> Script {
    script! {
      OP_2SWAP
      OP_2DROP
      0
      0
    }
}


/// Right shift of an u32 element by 8 bits
pub fn u32_shr8() -> Script {
    script! {
      3 OP_ROLL
      OP_DROP
      0
    }
}

/// Right shift of an u32 element by 24 bits
pub fn u32_shr24() -> Script {
    script! {
      OP_TOALTSTACK
      OP_2DROP
      OP_DROP
      OP_FROMALTSTACK
    }
}


/// Expects the u8_xor_table to be on the stack
pub fn u32_shr(shr_num :usize, ap: u32) -> Script{
    assert!(shr_num < 32);
    match sepcial_case(shr_num) {
        Some(res) => return res,
        None => {}
    }
    let script = script!(
        {u32_rrot(shr_num)}
        {u32_push(0xffff_ffff >> shr_num)}
        {u32_and(1, 0, ap + 1)} // 1 more element on stack
        {u32_roll(1)}
        {u32_drop()}
    );
    script
}

// a1,a2,a3,a4
pub fn preprocess(offset: usize) -> Script {
    assert!(offset < 4);
    if offset == 0 {
        /*
        return script! {
            OP_SWAP
            OP_2SWAP
            OP_SWAP
        };*/
        //a1,a2,a3,a4
        return script!();
    } else if offset == 1 {
        return script! {
            OP_TOALTSTACK
            OP_TOALTSTACK
            OP_TOALTSTACK
            OP_DROP
            0
            OP_FROMALTSTACK
            OP_FROMALTSTACK
            OP_FROMALTSTACK
        };// 0,a2,a3,a4
    } else if offset == 2 {
        return script! {
            OP_2SWAP
            OP_2DROP
            0
            0
            OP_2SWAP
        }; // 0,0,a3,a4
    } else if offset == 3 {
        return script! {
            OP_TOALTSTACK
            OP_DROP
            OP_2DROP
            0
            0
            0
            OP_FROMALTSTACK
        }; //0,0,0,a4
    } else {
        panic!("offset out of range")
    }
}

pub fn sepcial_case(rot_num: usize) -> Option<Script> {
    let res: Option<Script> = match rot_num {
        0 => script! {}.into(),           
        8 => script! {u32_shr8}.into(),   
        16 => script! {u32_shr16}.into(), 
        24 => script! {u32_shr24}.into(),  
        _ => None,
    };
    res
}
/// Expects the u8_xor_table to be on the stack
pub fn u32_shr_debug(shr_num :usize, ap: u32) -> Script{
    let remainder: usize = shr_num % 8;

    let offset: usize = (shr_num - remainder) / 8;

    let script = script!(
        {u32_rrot(shr_num)}
        {u32_push(0xffff_ffff >> shr_num)}
        {preprocess(offset)}
        {u32_and(1, 0, ap + 1)} // 1 more element on stack
        {u32_roll(1)}
        {u32_drop()}  
    );
    script
}