#![allow(non_snake_case)]
#![allow(dead_code)]

use crate::treepp::{pushable, script, Script};

pub fn OP_CHECKSEQUENCEVERIFY() -> Script {
    script! {OP_CSV}
}

/// OP_4PICK
/// The 4 items n back in the stack are copied to the top.
pub fn OP_4PICK() -> Script {
    script! {
        OP_ADD
        OP_DUP  OP_PICK OP_SWAP
        OP_DUP  OP_PICK OP_SWAP
        OP_DUP  OP_PICK OP_SWAP
        OP_1SUB OP_PICK
    }
}

/// OP_4ROLL
/// The 4 items n back in the stack are moved to the top.
pub fn OP_4ROLL() -> Script {
    script! {
        4 OP_ADD
        OP_DUP  OP_ROLL OP_SWAP
        OP_DUP  OP_ROLL OP_SWAP
        OP_DUP  OP_ROLL OP_SWAP
        OP_1SUB OP_ROLL
    }
}

/// Duplicates the top 4 items
pub fn OP_4DUP() -> Script {
    script! {
        OP_2OVER OP_2OVER
    }
}

/// Drops the top 4 items
pub fn OP_4DROP() -> Script {
    script! {
        OP_2DROP OP_2DROP
    }
}

/// Swaps the top two groups of 4 items
pub fn OP_4SWAP() -> Script {
    script! {
        7 OP_ROLL 7 OP_ROLL
        7 OP_ROLL 7 OP_ROLL
    }
}

/// Puts the top 4 items onto the top of the alt stack. Removes them from the main stack.
pub fn OP_4TOALTSTACK() -> Script {
    script! {
        OP_TOALTSTACK OP_TOALTSTACK OP_TOALTSTACK OP_TOALTSTACK
    }
}

/// Puts the top 4 items from the altstack onto the top of the main stack. Removes them from the alt stack.
pub fn OP_4FROMALTSTACK() -> Script {
    script! {
        OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK
    }
}

//
// Multiplication by Powers of 2
//

/// The top stack item is multiplied by 2
pub fn OP_2MUL() -> Script {
    script! {
        OP_DUP OP_ADD
    }
}

/// The top stack item is multiplied by 4
pub fn OP_4MUL() -> Script {
    script! {
        OP_DUP OP_ADD OP_DUP OP_ADD
    }
}

/// The top stack item is multiplied by 2**k
pub fn op_2k_mul(k: u32) -> Script {
    script! {
        for _ in 0..k{
            {OP_2MUL()}
        }
    }
}

/// The top stack item is multiplied by 16
pub fn OP_16MUL() -> Script {
    script! {
        OP_DUP OP_ADD OP_DUP OP_ADD
        OP_DUP OP_ADD OP_DUP OP_ADD
    }
}

/// The top stack item is multiplied by 256
pub fn OP_256MUL() -> Script {
    script! {
        OP_DUP OP_ADD OP_DUP OP_ADD
        OP_DUP OP_ADD OP_DUP OP_ADD
        OP_DUP OP_ADD OP_DUP OP_ADD
        OP_DUP OP_ADD OP_DUP OP_ADD
    }
}
