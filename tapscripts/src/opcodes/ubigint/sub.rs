use crate::opcodes::ubigint::UBigIntImpl;
use bitcoin::ScriptBuf as Script;
use crate::opcodes::{unroll, pushable};
use bitcoin_script::bitcoin_script as script;

impl<const N_BITS: usize> UBigIntImpl<N_BITS> {
    pub fn sub(a: u32, b: u32) -> Script {
        let n_limbs: usize = (N_BITS + 30 - 1) / 30;
        let head = N_BITS - (n_limbs - 1) * 30;
        let head_offset = 1u32 << head;

        script! {
            {Self::zip(a,b)}

            1073741824

            // A0 - B0
            u30_sub_carry
            OP_SWAP
            OP_TOALTSTACK

            // from     A1      - (B1        + borrow_0)
            //   to     A{N-2}  - (B{N-2}    + borrow_{N-3})
            { unroll((n_limbs - 2) as u32, |_| script! {
                OP_ROT
                OP_ADD
                OP_SWAP
                u30_sub_carry
                OP_SWAP
                OP_TOALTSTACK
            })}

            // A{N-1} - (B{N-1} + borrow_{N-2})
            OP_SWAP OP_DROP
            OP_ADD
            { u30_sub_nocarry(head_offset) }

            { unroll((n_limbs - 1) as u32, |_| script! {
                OP_FROMALTSTACK
            })}
        }
    }
}


pub fn u30_sub_carry() -> Script {
    script! {
        OP_ROT OP_ROT
        OP_SUB
        OP_DUP
        0
        OP_LESSTHAN
        OP_IF
            OP_OVER
            OP_ADD
            1
        OP_ELSE
            0
        OP_ENDIF
    }
}

pub fn u30_sub_nocarry(head_offset: u32) -> Script {
    script! {
        OP_SUB
        OP_DUP
        0
        OP_LESSTHAN
        OP_IF
            { head_offset }
            OP_ADD
        OP_ENDIF
    }
}