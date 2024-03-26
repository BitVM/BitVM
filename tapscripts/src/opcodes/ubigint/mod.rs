use bitcoin::ScriptBuf as Script;
use crate::opcodes::{unroll, pushable};
use bitcoin_script::bitcoin_script as script;

mod std;
mod add;
mod sub;
mod cmp;

pub struct UBigIntImpl<const N_BITS: usize>;

pub fn u30_to_bits(num_bits: usize) -> Script {
    if num_bits >= 2 {
        script! {
            2                           // 2^1
            { unroll((num_bits - 2) as u32, |_| script! {
                OP_DUP OP_DUP OP_ADD
            })}                         // 2^2 to 2^{num_bits - 1}
            { num_bits - 1 } OP_ROLL

            { unroll((num_bits - 2) as u32, |_| script! {
                OP_2DUP OP_LESSTHANOREQUAL
                OP_IF
                    OP_SWAP OP_SUB 1
                OP_ELSE
                    OP_SWAP OP_DROP 0
                OP_ENDIF
                OP_TOALTSTACK
            })}

            OP_2DUP OP_LESSTHANOREQUAL
            OP_IF
                OP_SWAP OP_SUB 1
            OP_ELSE
                OP_SWAP OP_DROP 0
            OP_ENDIF

            { unroll((num_bits - 2) as u32, |_| script! {
                OP_FROMALTSTACK
            })}
        }
    } else {
        script! {}
    }
}
