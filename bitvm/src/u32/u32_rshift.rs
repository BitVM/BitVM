#![allow(dead_code)]

use crate::{
    treepp::{script, Script},
    u32::u32_rrot::u8_extract_hbit,
};
use core::panic;

pub fn post_process(offset: usize) -> Script {
    assert!(offset < 4);
    let res: Script = match offset {
        0 => script! {
            OP_FROMALTSTACK //[c+cD]
            OP_FROMALTSTACK //[c+cD, b+bC]
            OP_FROMALTSTACK //[c+cD, b+bC, a+cB]
            OP_FROMALTSTACK //[c+cD, b+bC, a+cB, cA]
            OP_SWAP         //[c+cD, b+bC, cA, a+cB]
            OP_2SWAP        //[cA, a+cB, c+cD, b+bC]
            OP_SWAP         //[cA, a+cB, b+bC, c+cD]
        },
        1 => script! {
            OP_FROMALTSTACK // [c+cD]
            OP_DROP         // []
            0               // [0]
            OP_FROMALTSTACK // [0,b+bC]
            OP_FROMALTSTACK // [0,b+bC,a+cB]
            OP_FROMALTSTACK // [0,b+bC,a+cB,cA]
            OP_SWAP         // [0,b+bC,cA,a+cB]
            OP_ROT          // [0,cA,a+cB,b+bC]
        },
        2 => script! {
            OP_FROMALTSTACK // [c+cD]
            OP_DROP         // []
            0               // [0]
            OP_FROMALTSTACK // [0,b+bC]
            OP_DROP         // [0]
            0               // [0, 0]
            OP_FROMALTSTACK // [0,0,a+cB]
            OP_FROMALTSTACK // [0,0,a+cB,cA]
            OP_SWAP         // [0,0,cA,a+cB]
        },
        3 => script! {
            OP_FROMALTSTACK // [c+cD]
            OP_DROP         // []
            0               // [0]
            OP_FROMALTSTACK // [0,b+bC]
            OP_DROP         // [0]
            0               // [0, 0]
            OP_FROMALTSTACK // [0,0,a+cB]
            OP_DROP         // [0,0]
            0               // [0,0,0]
            OP_FROMALTSTACK // [0,0,0,cA]
        },
        _ => panic!("offset out of range"),
    };
    res
}
pub fn specific_optimize_rshift(shift_num: usize) -> Option<Script> {
    let res: Option<Script> = match shift_num {
        0 => script! {}.into(),
        8 => script! {  // [a, b, c, d]
            OP_DROP        //[a, b, c]
            0              //[a, b, c, 0]
            3 OP_ROLL      //[b, c, 0, a]
            3 OP_ROLL      //[c, 0, a, b]
            3 OP_ROLL      //[0, c, a, b]

        }
        .into(),
        16 => script! {
            OP_DROP         //[a, b, c]
            OP_DROP         //[a, b]
            0               //[a, b, 0]
            0               //[a, b, 0, 0]
            OP_2SWAP        //[0, 0, a, b]
        }
        .into(),
        24 => script! {
            OP_DROP         //[a, b, c]
            OP_DROP         //[a, b]
            OP_DROP         //[a]
            0               //[a, 0]
            0               //[a, 0, 0]
            0               //[a, 0, 0, 0]
            3 OP_ROLL       //[0, 0, 0, a]
        }
        .into(),
        _ => None,
    };
    res
}
pub fn u32_rshift(shift_num: usize) -> Script {
    assert!(shift_num < 32);
    if let Some(res) = specific_optimize_rshift(shift_num) { return res }
    let remainder: usize = shift_num % 8;

    let hbit: usize = 8 - remainder;
    let offset: usize = (shift_num - remainder) / 8;

    script! {
        {u8_extract_hbit(hbit)} //[A, B, C, d, carryD]
        OP_ROT {u8_extract_hbit(hbit)} //[A, B, d, carryD, c, carryC]
        4 OP_ROLL {u8_extract_hbit(hbit)} //[A, d, carryD, c, carryC, b, carryB]
        6 OP_ROLL {u8_extract_hbit(hbit)} //[d, carryD, c, carryC, b, carryB, a, carryA]

        OP_TOALTSTACK // carryA

        OP_ADD
        OP_TOALTSTACK // a+carryB

        OP_ADD
        OP_TOALTSTACK // b+carryC

        OP_ADD
        OP_TOALTSTACK // c+carryD

        OP_DROP

        {post_process(offset)}
    }.add_stack_hint(-4, 0)
}

#[cfg(test)]
mod tests {

    use crate::run;
    use crate::treepp::script;
    use crate::u32::u32_rshift::*;
    use crate::u32::u32_std::*;
    use rand::Rng;

    fn rshift(x: u32, n: usize) -> u32 {
        if n == 0 {
            return x;
        }
        x >> n
    }

    #[test]
    fn test_rshift() {
        for _ in 0..10000 {
            let mut rng = rand::thread_rng();
            let x: u32 = rng.gen();
            for i in 0..32 {
                let script = script! {
                    {u32_push(x)}
                    {u32_rshift(i)}
                    {u32_push(rshift(x, i))}
                    {u32_equal()}
                };
                run(script);
            }
        }
    }
}
