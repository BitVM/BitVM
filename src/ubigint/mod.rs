use crate::treepp::{pushable, script, Script};

mod add;
mod cmp;
mod std;
mod sub;

pub struct UBigIntImpl<const N_BITS: usize>;

pub fn u30_to_bits(num_bits: usize) -> Script {
    if num_bits >= 2 {
        script! {
            2                           // 2^1
            for _ in 0..(num_bits - 2) as u32 {
                OP_DUP OP_DUP OP_ADD
            }                           // 2^2 to 2^{num_bits - 1}
            { num_bits - 1 } OP_ROLL

            for _ in 0..(num_bits - 2) as u32 {
                OP_2DUP OP_LESSTHANOREQUAL
                OP_IF
                    OP_SWAP OP_SUB 1
                OP_ELSE
                    OP_SWAP OP_DROP 0
                OP_ENDIF
                OP_TOALTSTACK
            }

            OP_2DUP OP_LESSTHANOREQUAL
            OP_IF
                OP_SWAP OP_SUB 1
            OP_ELSE
                OP_SWAP OP_DROP 0
            OP_ENDIF

            for _ in 0..(num_bits - 2) as u32 {
                OP_FROMALTSTACK
            }
        }
    } else {
        script! {}
    }
}
