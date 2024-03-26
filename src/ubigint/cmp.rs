use crate::treepp::{pushable, script, unroll, Script};
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
    pub fn lessthanorequal(a: u32, b: u32) -> Script { Self::greaterthanorequal(b, a) }

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

#[cfg(test)]
mod test {
    use crate::treepp::{execute_script, pushable, script};
    use crate::ubigint::UBigIntImpl;
    use core::cmp::Ordering;
    use num_bigint::{BigUint, RandomBits};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_cmp() {
        const N_BITS: usize = 254;

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..100 {
            let a: BigUint = prng.sample(RandomBits::new(254));
            let b: BigUint = prng.sample(RandomBits::new(254));
            let a_lessthan = if a.cmp(&b) == Ordering::Less {
                1u32
            } else {
                0u32
            };

            let script = script! {
                { UBigIntImpl::<N_BITS>::push_u32_le(&a.to_u32_digits()) }
                { UBigIntImpl::<N_BITS>::push_u32_le(&b.to_u32_digits()) }
                { UBigIntImpl::<N_BITS>::lessthan(1, 0) }
                { a_lessthan }
                OP_EQUAL
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }

        for _ in 0..100 {
            let a: BigUint = prng.sample(RandomBits::new(254));
            let b: BigUint = prng.sample(RandomBits::new(254));
            let a_lessthanorequal = if a.cmp(&b) != Ordering::Greater {
                1u32
            } else {
                0u32
            };

            let script = script! {
                { UBigIntImpl::<N_BITS>::push_u32_le(&a.to_u32_digits()) }
                { UBigIntImpl::<N_BITS>::push_u32_le(&b.to_u32_digits()) }
                { UBigIntImpl::<N_BITS>::lessthanorequal(1, 0) }
                { a_lessthanorequal }
                OP_EQUAL
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }

        for _ in 0..100 {
            let a: BigUint = prng.sample(RandomBits::new(254));
            let b: BigUint = prng.sample(RandomBits::new(254));
            let a_greaterthan = if a.cmp(&b) == Ordering::Greater {
                1u32
            } else {
                0u32
            };

            let script = script! {
                { UBigIntImpl::<N_BITS>::push_u32_le(&a.to_u32_digits()) }
                { UBigIntImpl::<N_BITS>::push_u32_le(&b.to_u32_digits()) }
                { UBigIntImpl::<N_BITS>::greaterthan(1, 0) }
                { a_greaterthan }
                OP_EQUAL
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }

        for _ in 0..100 {
            let a: BigUint = prng.sample(RandomBits::new(254));
            let b: BigUint = prng.sample(RandomBits::new(254));
            let a_greaterthanorequal = if a.cmp(&b) != Ordering::Less {
                1u32
            } else {
                0u32
            };

            let script = script! {
                { UBigIntImpl::<N_BITS>::push_u32_le(&a.to_u32_digits()) }
                { UBigIntImpl::<N_BITS>::push_u32_le(&b.to_u32_digits()) }
                { UBigIntImpl::<N_BITS>::greaterthanorequal(1, 0) }
                { a_greaterthanorequal }
                OP_EQUAL
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}
