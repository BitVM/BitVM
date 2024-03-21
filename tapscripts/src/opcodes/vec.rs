use bitcoin::ScriptBuf as Script;
use bitcoin_script::bitcoin_script as script;
use crate::opcodes::{pushable, unroll};
use bitcoin::opcodes::{OP_FROMALTSTACK, OP_TOALTSTACK};


/// Verifies that the top two `item_count` many stack items are equal
pub fn vec_equalverify(item_count: u32) -> Script {
    unroll(item_count, |i| script! {
        {item_count - i} OP_ROLL OP_EQUALVERIFY
    })
}


/// Compares if the top two `item_count` many stack items are equal
pub fn vec_equal(item_count: u32) -> Script {
    script! {
        { unroll(item_count - 1, |i| script!{
                { item_count - i}
                OP_ROLL
                OP_EQUAL
                OP_TOALTSTACK
            })
        }
        OP_EQUAL
        { unroll(item_count - 1, |_| script!{
                OP_FROMALTSTACK
                OP_BOOLAND
            })
        }
    }
}

/// Compares if the top two `item_count` many stack items are not equal
pub fn vec_not_equal(item_count: u32) -> Script {
    script! {
        { unroll(item_count - 1, |i| script!{
                { item_count - i }
                OP_ROLL
                OP_EQUAL
                OP_NOT
                OP_TOALTSTACK
            })
        }
        OP_EQUAL
        OP_NOT
        { unroll(item_count - 1, |_| script!{
                OP_FROMALTSTACK
                OP_BOOLOR
            })
        }
    }
}

/// Moves the top `item_count` many stack items onto the altstack
pub fn vec_toaltstack(item_count: u32) -> Script {
    unroll(item_count, |_| OP_TOALTSTACK)
}

/// Moves the top `item_count` many altstack items onto the mainstack
pub fn vec_fromaltstack(item_count: u32) -> Script {
    unroll(item_count, |_| OP_FROMALTSTACK)
}
