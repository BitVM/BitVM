use bitcoin::opcodes::OP_EQUALVERIFY;
use bitcoin::ScriptBuf as Script;
use bitcoin_script::bitcoin_script as script;
use crate::opcodes::{unroll, pushable};

pub struct UintImpl<const N_BITS: usize>;

impl<const N_BITS: usize> UintImpl<N_BITS> {
    fn push_u32_le(v: &[u32]) -> Script {
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
    /// output: a0 b0 ... ... a{N-1} b{N-1} (if a < b)
    ///     or: b0 a0 ... ... b{N-1} a{N-1} (if a > b)
    fn zip(mut a: u32, mut b: u32) -> Script {
        let n_limbs: usize = (N_BITS + 30 - 1) / 30;

        assert_ne!(a, b);
        if a > b {
            (a, b) = (b, a);
        }

        a = (a + 1) * (n_limbs as u32) - 1;
        b = (b + 1) * (n_limbs as u32) - 1;

        unroll(n_limbs as u32, |i| {
            script! {
                { a + i } OP_ROLL { b } OP_ROLL
            }
        })
    }

    fn add(a: u32, b: u32) -> Script {
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

    fn equalverify(a: u32, b: u32) -> Script {
        let n_limbs: usize = (N_BITS + 30 - 1) / 30;

        script! {
            { Self::zip(a, b) }
            { unroll(n_limbs as u32, |_| script!{
                OP_EQUALVERIFY
            })}
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

#[cfg(test)]
mod test {
    use core::ops::{Add, Rem, Shl};
    use bitcoin::opcodes::OP_PUSHNUM_1;
    use rand_chacha::ChaCha20Rng;
    use rand::{Rng, SeedableRng};
    use bitcoin_script::bitcoin_script as script;
    use num_bigint::{BigUint, RandomBits};
    use num_traits::One;
    use crate::opcodes::{execute_script, pushable, unroll};
    use crate::opcodes::uint::UintImpl;

    #[test]
    fn test_zip() {
        const N_BITS: usize = 1500;
        const N_U30_LIMBS: usize = 50;
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let mut v = vec![];
        for _ in 0..N_U30_LIMBS {
            v.push(prng.gen::<i32>());
        }
        for _ in 0..N_U30_LIMBS {
            v.push(prng.gen::<i32>());
        }

        let mut expected = vec![];
        for i in 0..N_U30_LIMBS {
            expected.push(v[N_U30_LIMBS + i]);
            expected.push(v[i]);
        }

        let script = script! {
            { unroll((N_U30_LIMBS * 2) as u32, |i| script! {
                { v[i as usize] }
            })}
            { UintImpl::<N_BITS>::zip(1, 0) }
            { unroll((N_U30_LIMBS * 2) as u32, |i| script! {
                { expected[N_U30_LIMBS * 2 - 1 - (i as usize)] }
                OP_EQUALVERIFY
            })}
            OP_PUSHNUM_1
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success)
    }

    #[test]
    fn test_add() {
        const N_BITS: usize = 256;

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let a: BigUint = prng.sample(RandomBits::new(256));
        let b: BigUint = prng.sample(RandomBits::new(256));
        let c: BigUint = (a.clone() + b.clone()).rem(BigUint::one().shl(256));

        let script = script! {
            { UintImpl::<N_BITS>::push_u32_le(&a.to_u32_digits()) }
            { UintImpl::<N_BITS>::push_u32_le(&b.to_u32_digits()) }
            { UintImpl::<N_BITS>::add(1, 0) }
            { UintImpl::<N_BITS>::push_u32_le(&c.to_u32_digits()) }
            { UintImpl::<N_BITS>::equalverify(1, 0) }
            OP_PUSHNUM_1
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success)
    }
}