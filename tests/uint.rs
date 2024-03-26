#[cfg(test)]
mod test {
    use bitvm::treepp::{execute_script, pushable, script};
    use bitvm::uint::UintImpl;
    use core::cmp::Ordering;
    use core::ops::{Rem, Shl};
    use num_bigint::{BigUint, RandomBits};
    use num_traits::One;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_zip() {
        const N_BITS: usize = 1500;
        const N_U30_LIMBS: usize = 50;

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let mut v = vec![];
            for _ in 0..N_U30_LIMBS {
                v.push(prng.gen::<i32>());
            }
            for _ in 0..N_U30_LIMBS {
                v.push(prng.gen::<i32>());
            }

            let mut expected = vec![];
            for i in 0..N_U30_LIMBS {
                expected.push(v[i]);
                expected.push(v[N_U30_LIMBS + i]);
            }

            let script = script! {
                for i in 0..N_U30_LIMBS * 2 {
                    { v[i] }
                }
                { UintImpl::<N_BITS>::zip(1, 0) }
                for i in 0..N_U30_LIMBS * 2 {
                    { expected[N_U30_LIMBS * 2 - 1 - i] }
                    OP_EQUALVERIFY
                }
                OP_PUSHNUM_1
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }

        for _ in 0..50 {
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
                for i in 0..N_U30_LIMBS * 2 {
                    { v[i] }
                }
                { UintImpl::<N_BITS>::zip(0, 1) }
                for i in 0..N_U30_LIMBS * 2 {
                    { expected[N_U30_LIMBS * 2 - 1 - i] }
                    OP_EQUALVERIFY
                }
                OP_PUSHNUM_1
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_add() {
        const N_BITS: usize = 254;

        for _ in 0..100 {
            let mut prng = ChaCha20Rng::seed_from_u64(0);

            let a: BigUint = prng.sample(RandomBits::new(254));
            let b: BigUint = prng.sample(RandomBits::new(254));
            let c: BigUint = (a.clone() + b.clone()).rem(BigUint::one().shl(254));

            let script = script! {
                { UintImpl::<N_BITS>::push_u32_le(&a.to_u32_digits()) }
                { UintImpl::<N_BITS>::push_u32_le(&b.to_u32_digits()) }
                { UintImpl::<N_BITS>::add(1, 0) }
                { UintImpl::<N_BITS>::push_u32_le(&c.to_u32_digits()) }
                { UintImpl::<N_BITS>::equalverify(1, 0) }
                OP_PUSHNUM_1
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_sub() {
        const N_BITS: usize = 254;

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..100 {
            let a: BigUint = prng.sample(RandomBits::new(254));
            let b: BigUint = prng.sample(RandomBits::new(254));
            let mut c: BigUint = BigUint::one().shl(254) + &a - &b;
            c = c.rem(BigUint::one().shl(254));

            let script = script! {
                { UintImpl::<N_BITS>::push_u32_le(&a.to_u32_digits()) }
                { UintImpl::<N_BITS>::push_u32_le(&b.to_u32_digits()) }
                { UintImpl::<N_BITS>::sub(1, 0) }
                { UintImpl::<N_BITS>::push_u32_le(&c.to_u32_digits()) }
                { UintImpl::<N_BITS>::equalverify(1, 0) }
                OP_PUSHNUM_1
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);

            let script = script! {
                { UintImpl::<N_BITS>::push_u32_le(&b.to_u32_digits()) }
                { UintImpl::<N_BITS>::push_u32_le(&a.to_u32_digits()) }
                { UintImpl::<N_BITS>::sub(0, 1) }
                { UintImpl::<N_BITS>::push_u32_le(&c.to_u32_digits()) }
                { UintImpl::<N_BITS>::equalverify(1, 0) }
                OP_PUSHNUM_1
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_cmp() {
        const N_BITS: usize = 254;

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
                { UintImpl::<N_BITS>::push_u32_le(&a.to_u32_digits()) }
                { UintImpl::<N_BITS>::push_u32_le(&b.to_u32_digits()) }
                { UintImpl::<N_BITS>::lessthan(1, 0) }
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
                { UintImpl::<N_BITS>::push_u32_le(&a.to_u32_digits()) }
                { UintImpl::<N_BITS>::push_u32_le(&b.to_u32_digits()) }
                { UintImpl::<N_BITS>::lessthanorequal(1, 0) }
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
                { UintImpl::<N_BITS>::push_u32_le(&a.to_u32_digits()) }
                { UintImpl::<N_BITS>::push_u32_le(&b.to_u32_digits()) }
                { UintImpl::<N_BITS>::greaterthan(1, 0) }
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
                { UintImpl::<N_BITS>::push_u32_le(&a.to_u32_digits()) }
                { UintImpl::<N_BITS>::push_u32_le(&b.to_u32_digits()) }
                { UintImpl::<N_BITS>::greaterthanorequal(1, 0) }
                { a_greaterthanorequal }
                OP_EQUAL
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}
