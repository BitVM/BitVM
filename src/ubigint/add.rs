use crate::treepp::{pushable, script, Script};
use crate::ubigint::UBigIntImpl;

impl<const N_BITS: usize> UBigIntImpl<N_BITS> {
    pub fn double(a: u32) -> Script {
        let n_limbs: usize = (N_BITS + 30 - 1) / 30;
        let offset = (a + 1) * (n_limbs as u32) - 1;

        script! {
            for _ in 0..n_limbs as u32 {
                { offset } OP_PICK
            }
            { Self::add(a + 1, 0) }
        }
    }

    pub fn add(a: u32, b: u32) -> Script {
        let n_limbs: usize = (N_BITS + 30 - 1) / 30;
        let head = N_BITS - (n_limbs - 1) * 30;
        let head_offset = 1u32 << head;

        script! {
            { Self::zip(a, b) }

            1073741824

            // A0 + B0
            u30_add_carry
            OP_SWAP
            OP_TOALTSTACK

            // from     A1      + B1        + carry_0
            //   to     A{N-2}  + B{N-2}    + carry_{N-3}
            for _ in 0..(n_limbs - 2) as u32 {
                OP_ROT
                OP_ADD
                OP_SWAP
                u30_add_carry
                OP_SWAP
                OP_TOALTSTACK
            }

            // A{N-1} + B{N-1} + carry_{N-2}
            OP_SWAP OP_DROP
            OP_ADD
            { u30_add_nocarry(head_offset) }

            for _ in 0..(n_limbs - 1) as u32 {
                OP_FROMALTSTACK
            }
        }
    }

    pub fn add1() -> Script {
        let n_limbs: usize = (N_BITS + 30 - 1) / 30;
        let head = N_BITS - (n_limbs - 1) * 30;
        let head_offset = 1u32 << head;

        script! {
            1
            1073741824

            // A0 + 1
            u30_add_carry
            OP_SWAP
            OP_TOALTSTACK

            // from     A1        + carry_0
            //   to     A{N-2}    + carry_{N-3}
            for _ in 0..(n_limbs - 2) as u32 {
                OP_SWAP
                u30_add_carry
                OP_SWAP
                OP_TOALTSTACK
            }

            // A{N-1} + carry_{N-2}
            OP_SWAP OP_DROP
            { u30_add_nocarry(head_offset) }

            for _ in 0..(n_limbs - 1) as u32 {
                OP_FROMALTSTACK
            }
        }
    }
}

pub fn u30_add_carry() -> Script {
    script! {
        OP_ROT OP_ROT
        OP_ADD OP_2DUP
        OP_LESSTHAN
        OP_IF
            OP_OVER OP_SUB 1
        OP_ELSE
            0
        OP_ENDIF
    }
}

pub fn u30_add_nocarry(head_offset: u32) -> Script {
    script! {
        OP_ADD OP_DUP
        { head_offset } OP_GREATERTHANOREQUAL
        OP_IF
            { head_offset } OP_SUB
        OP_ENDIF
    }
}
