use bitcoin::ScriptBuf as Script;
use bitcoin_script::bitcoin_script as script;
use crate::opcodes::{unroll, pushable};

pub struct UintImpl<const N_BITS: usize>;

impl<const N_BITS: usize> UintImpl<N_BITS> {
    pub fn push_u32_le(v: &[u32]) -> Script {
        let n_limbs: usize = (N_BITS + 30 - 1) / 30;

        let mut bits = vec![];
        for elem in v.iter() {
            for i in 0..32 {
                bits.push((elem & (1 << i)) != 0);
            }
        }

        let mut limbs = vec![];
        for chunk in bits.chunks(30) {
            let mut chunk_vec = chunk.to_vec();
            chunk_vec.resize(30, false);

            let mut elem = 0u32;
            for i in 0..30 {
                if chunk_vec[i] {
                    elem += 1 << i;
                }
            }

            limbs.push(elem);
        }

        limbs.reverse();

        script! {
            { unroll(limbs.len() as u32, |i| script! {
                { limbs[i as usize] }
            })}
            { unroll((n_limbs - limbs.len()) as u32, |i| script! {
                { 0 }
            })}
        }
    }

    /// Copy and zip the top two u{16N} elements
    /// input:  a0 ... a{N-1} b0 ... b{N-1}
    /// output: a0 b0 ... ... a{N-1} b{N-1}
    pub fn zip(mut a: u32, mut b: u32) -> Script {
        let n_limbs: usize = (N_BITS + 30 - 1) / 30;
        a = (a + 1) * (n_limbs as u32) - 1;
        b = (b + 1) * (n_limbs as u32) - 1;

        assert_ne!(a, b);
        if a < b {
            unroll(n_limbs as u32, |i| script! {
                { a + i } OP_ROLL { b } OP_ROLL
            })
        } else {
            unroll(n_limbs as u32, |i| script! {
                { a } OP_ROLL { b + i + 1 } OP_ROLL
            })
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
            { unroll((n_limbs - 2) as u32, |_| script! {
                OP_ROT
                OP_ADD
                OP_SWAP
                u30_add_carry
                OP_SWAP
                OP_TOALTSTACK
            })}

            // A{N-1} + B{N-1} + carry_{N-2}
            OP_SWAP OP_DROP
            OP_ADD
            { u30_add_nocarry(head_offset) }

            { unroll((n_limbs - 1) as u32, |_| script! {
                OP_FROMALTSTACK
            })}
        }
    }

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
            { u30_sub(head_offset) }

            { unroll((n_limbs - 1) as u32, |_| script! {
                OP_FROMALTSTACK
            })}
        }
    }

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

pub fn u30_sub(head_offset: u32) -> Script {
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