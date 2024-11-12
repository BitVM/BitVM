use crate::bigint::BigIntImpl;
use crate::treepp::*;

impl<const N_BITS: u32, const LIMB_SIZE: u32> BigIntImpl<N_BITS, LIMB_SIZE> {
    pub fn equalverify(a: u32, b: u32) -> Script {
        script! {
            { Self::zip(a, b) }
            for _ in 0..Self::N_LIMBS {
                OP_EQUALVERIFY
            }
        }
    }

    pub fn equal(a: u32, b: u32) -> Script {
        script! {
            { Self::zip(a, b) }
            for _ in 0..Self::N_LIMBS {
                OP_EQUAL
                OP_TOALTSTACK
            }
            for _ in 0..Self::N_LIMBS {
                OP_FROMALTSTACK
            }
            for _ in 0..Self::N_LIMBS - 1 {
                OP_BOOLAND
            }
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
        script! {
            { Self::zip(a, b) }
            OP_2DUP
            OP_GREATERTHAN OP_TOALTSTACK
            OP_LESSTHAN OP_TOALTSTACK

            for _ in 0..Self::N_LIMBS - 1 {
                OP_2DUP
                OP_GREATERTHAN OP_TOALTSTACK
                OP_LESSTHAN OP_TOALTSTACK
            }

            OP_FROMALTSTACK OP_FROMALTSTACK
            OP_OVER OP_BOOLOR

            for _ in 0..Self::N_LIMBS - 1 {
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
            }

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
    use crate::bigint::{U254, U64};
    use crate::treepp::*;
    use core::cmp::Ordering;
    use num_bigint::{BigUint, RandomBits};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_u254_cmp() {
        let mut prng = ChaCha20Rng::seed_from_u64(2);

        for _ in 0..100 {
            let a: BigUint = prng.sample(RandomBits::new(254));
            let b: BigUint = prng.sample(RandomBits::new(254));
            let a_lessthan = if a.cmp(&b) == Ordering::Less {
                1u32
            } else {
                0u32
            };

            let script = script! {
                { U254::push_u32_le(&a.to_u32_digits()) }
                { U254::push_u32_le(&b.to_u32_digits()) }
                { U254::lessthan(1, 0) }
                { a_lessthan }
                OP_EQUAL
            };
            run(script);
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
                { U254::push_u32_le(&a.to_u32_digits()) }
                { U254::push_u32_le(&b.to_u32_digits()) }
                { U254::lessthanorequal(1, 0) }
                { a_lessthanorequal }
                OP_EQUAL
            };
            run(script);
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
                { U254::push_u32_le(&a.to_u32_digits()) }
                { U254::push_u32_le(&b.to_u32_digits()) }
                { U254::greaterthan(1, 0) }
                { a_greaterthan }
                OP_EQUAL
            };
            run(script);
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
                { U254::push_u32_le(&a.to_u32_digits()) }
                { U254::push_u32_le(&b.to_u32_digits()) }
                { U254::greaterthanorequal(1, 0) }
                { a_greaterthanorequal }
                OP_EQUAL
            };
            run(script);
        }
    }

    #[test]
    fn test_u64_cmp() {
        let mut prng = ChaCha20Rng::seed_from_u64(2);

        for _ in 0..100 {
            let a: BigUint = prng.sample(RandomBits::new(64));
            let b: BigUint = prng.sample(RandomBits::new(64));
            let a_lessthan = if a.cmp(&b) == Ordering::Less {
                1u32
            } else {
                0u32
            };

            let script = script! {
                { U64::push_u32_le(&a.to_u32_digits()) }
                { U64::push_u32_le(&b.to_u32_digits()) }
                { U64::lessthan(1, 0) }
                { a_lessthan }
                OP_EQUAL
            };
            run(script);
        }

        for _ in 0..100 {
            let a: BigUint = prng.sample(RandomBits::new(64));
            let b: BigUint = prng.sample(RandomBits::new(64));
            let a_lessthanorequal = if a.cmp(&b) != Ordering::Greater {
                1u32
            } else {
                0u32
            };

            let script = script! {
                { U64::push_u32_le(&a.to_u32_digits()) }
                { U64::push_u32_le(&b.to_u32_digits()) }
                { U64::lessthanorequal(1, 0) }
                { a_lessthanorequal }
                OP_EQUAL
            };
            run(script);
        }

        for _ in 0..100 {
            let a: BigUint = prng.sample(RandomBits::new(64));
            let b: BigUint = prng.sample(RandomBits::new(64));
            let a_greaterthan = if a.cmp(&b) == Ordering::Greater {
                1u32
            } else {
                0u32
            };

            let script = script! {
                { U64::push_u32_le(&a.to_u32_digits()) }
                { U64::push_u32_le(&b.to_u32_digits()) }
                { U64::greaterthan(1, 0) }
                { a_greaterthan }
                OP_EQUAL
            };
            run(script);
        }

        for _ in 0..100 {
            let a: BigUint = prng.sample(RandomBits::new(64));
            let b: BigUint = prng.sample(RandomBits::new(64));
            let a_greaterthanorequal = if a.cmp(&b) != Ordering::Less {
                1u32
            } else {
                0u32
            };

            let script = script! {
                { U64::push_u32_le(&a.to_u32_digits()) }
                { U64::push_u32_le(&b.to_u32_digits()) }
                { U64::greaterthanorequal(1, 0) }
                { a_greaterthanorequal }
                OP_EQUAL
            };
            run(script);
        }
    }

    #[test]
    fn test_is_zero() {
        let mut prng = ChaCha20Rng::seed_from_u64(2);

        for _ in 0..100 {
            let a: BigUint = prng.sample(RandomBits::new(254));
            // assume that it would never be a zero when sampling a random element

            let script = script! {
                { U254::push_u32_le(&a.to_u32_digits()) }
                { U254::is_zero_keep_element(0) }
                OP_NOT OP_TOALTSTACK
                { U254::drop() }
                OP_FROMALTSTACK
            };
            run(script);
        }

        for _ in 0..100 {
            let a: BigUint = prng.sample(RandomBits::new(254));
            // assume that it would never be a zero when sampling a random element

            let script = script! {
                { U254::push_u32_le(&a.to_u32_digits()) }
                { U254::is_zero(0) }
                OP_NOT
            };
            run(script);
        }

        for _ in 0..100 {
            let a: BigUint = prng.sample(RandomBits::new(64));
            // assume that it would never be a zero when sampling a random element

            let script = script! {
                { U64::push_u32_le(&a.to_u32_digits()) }
                { U64::is_zero_keep_element(0) }
                OP_NOT OP_TOALTSTACK
                { U64::drop() }
                OP_FROMALTSTACK
            };
            run(script);
        }

        for _ in 0..100 {
            let a: BigUint = prng.sample(RandomBits::new(64));
            // assume that it would never be a zero when sampling a random element

            let script = script! {
                { U64::push_u32_le(&a.to_u32_digits()) }
                { U64::is_zero(0) }
                OP_NOT
            };
            run(script);
        }

        let script = script! {
            { U254::push_u32_le(&[0]) }
            { U254::is_zero_keep_element(0) }
            OP_TOALTSTACK
            { U254::drop() }
            OP_FROMALTSTACK
        };
        run(script);

        let script = script! {
            { U254::push_u32_le(&[0]) }
            { U254::is_zero(0) }
        };
        run(script);

        let script = script! {
            { U64::push_u32_le(&[0]) }
            { U64::is_zero_keep_element(0) }
            OP_TOALTSTACK
            { U64::drop() }
            OP_FROMALTSTACK
        };
        run(script);

        let script = script! {
            { U64::push_u32_le(&[0]) }
            { U64::is_zero(0) }
        };
        run(script);
    }
}
