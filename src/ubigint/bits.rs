use crate::treepp::{pushable, script, unroll, Script};
use crate::ubigint::UBigIntImpl;

impl<const N_BITS: usize> UBigIntImpl<N_BITS> {
    pub fn convert_to_bits() -> Script {
        let n_limbs: usize = (N_BITS + 30 - 1) / 30;

        script! {
            { unroll((n_limbs - 1) as u32, |i| script! {
                { u30_to_bits(30) }
                { 30 * (i + 1) } OP_ROLL
            }) }
            { u30_to_bits(N_BITS - 30 * (n_limbs - 1)) }
        }
    }
}

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

#[cfg(test)]
mod test {
    use super::u30_to_bits;
    use crate::treepp::{execute_script, pushable, script, unroll};
    use crate::ubigint::UBigIntImpl;
    use num_bigint::{BigUint, RandomBits};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use std::ops::ShrAssign;

    #[test]
    fn test_u30_to_bits() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..100 {
            let mut a: u32 = prng.gen();
            a = a % (1 << 30);

            let mut bits = vec![];
            let mut cur = a;
            for _ in 0..30 {
                bits.push(cur % 2);
                cur /= 2;
            }

            let script = script! {
                { a }
                { u30_to_bits(30) }
                { unroll(30, |i| script! {
                    { bits[29 - i as usize] }
                    OP_EQUALVERIFY
                })}
                OP_PUSHNUM_1
            };

            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }

        for _ in 0..100 {
            let mut a: u32 = prng.gen();
            a = a % (1 << 15);

            let mut bits = vec![];
            let mut cur = a;
            for _ in 0..15 {
                bits.push(cur % 2);
                cur /= 2;
            }

            let script = script! {
                { a }
                { u30_to_bits(15) }
                { unroll(15, |i| script! {
                    { bits[14 - i as usize] }
                    OP_EQUALVERIFY
                })}
                OP_PUSHNUM_1
            };

            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }

        for a in 0..4 {
            let script = script! {
                { a }
                { u30_to_bits(2) }
                { a >> 1 } OP_EQUALVERIFY
                { a & 1 } OP_EQUAL
            };

            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }

        for a in 0..2 {
            let script = script! {
                { a }
                { u30_to_bits(1) }
                { a } OP_EQUAL
            };

            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }

        let script = script! {
            0 { u30_to_bits(0) } 0 OP_EQUAL
        };

        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_ubigint_to_bits() {
        const N_BITS: usize = 254;

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..10 {
            let a: BigUint = prng.sample(RandomBits::new(N_BITS as u64));

            let mut bits = vec![];
            let mut cur = a.clone();
            for _ in 0..N_BITS {
                bits.push(if cur.bit(0) { 1 } else { 0 });
                cur.shr_assign(1);
            }

            let script = script! {
                { UBigIntImpl::<N_BITS>::push_u32_le(&a.to_u32_digits()) }
                { UBigIntImpl::<N_BITS>::convert_to_bits() }
                { unroll(N_BITS as u32, |i| script! {
                    { bits[N_BITS - 1 - i as usize] }
                    OP_EQUALVERIFY
                })}
                OP_PUSHNUM_1
            };

            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}
