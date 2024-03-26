
use crate::treepp::{unroll, pushable, script, Script};
use crate::ubigint::UBigIntImpl;

impl<const N_BITS: usize> UBigIntImpl<N_BITS> {
    pub fn equalverify(a: u32, b: u32) -> Script {
        let n_limbs: usize = (N_BITS + 30 - 1) / 30;

        script! {
            { Self::zip(a, b) }
            { unroll(n_limbs as u32, |_| script!{
                OP_EQUALVERIFY
            })}
        }
    }

    pub fn equal(a: u32, b: u32) -> Script {
        let n_limbs: usize = (N_BITS + 30 - 1) / 30;

        script! {
            { Self::zip(a, b) }
            { unroll(n_limbs as u32, |_| script!{
                OP_EQUAL
                OP_TOALTSTACK
            })}
            { unroll(n_limbs as u32, |_| script! {
                OP_FROMALTSTACK
            })}
            { unroll((n_limbs - 1) as u32, |_| script! {
                OP_BOOLAND
            })}
        }
    }

    pub fn notequal(a: u32, b: u32) -> Script {
        script! {
            { Self::equal(a, b) }
            OP_NOT
        }
    }

    // return if a < b
    pub fn lessthan(a: u32, b: u32) -> Script {
        let n_limbs: usize = (N_BITS + 30 - 1) / 30;

        script! {
            { Self::zip(a, b) }
            OP_2DUP
            OP_GREATERTHAN OP_TOALTSTACK
            OP_LESSTHAN OP_TOALTSTACK

            { unroll((n_limbs - 1) as u32, |_| script! {
                OP_2DUP
                OP_GREATERTHAN OP_TOALTSTACK
                OP_LESSTHAN OP_TOALTSTACK
            })}

            OP_FROMALTSTACK OP_FROMALTSTACK
            OP_OVER OP_BOOLOR

            { unroll((n_limbs - 1) as u32, |_| script! {
                OP_FROMALTSTACK
                OP_FROMALTSTACK
                OP_ROT
                OP_IF
                    OP_2DROP 1
                OP_ELSE
                    OP_ROT OP_DROP
                    OP_OVER
                    OP_BOOLOR
                OP_ENDIF
            }) }

            OP_BOOLAND
        }
    }

    // return if a <= b
    pub fn lessthanorequal(a: u32, b: u32) -> Script {
        Self::greaterthanorequal(b, a)
    }

    // return if a > b
    pub fn greaterthan(a: u32, b: u32) -> Script {
        script! {
            { Self::lessthanorequal(a, b) }
            OP_NOT
        }
    }

    // return if a >= b
    pub fn greaterthanorequal(a: u32, b: u32) -> Script {
        script! {
            { Self::lessthan(a, b) }
            OP_NOT
        }
    }
}