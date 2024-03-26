#[cfg(test)]
mod test {
    use core::ops::{Add, Rem, Shl};
    use core::cmp::Ordering;
    use rand_chacha::ChaCha20Rng;
    use rand::{Rng, SeedableRng};
    use bitcoin_script::bitcoin_script as script;
    use num_bigint::{BigUint, RandomBits};
    use num_traits::One;
    use tapscripts::opcodes::uint::{u30_to_bits, UintImpl};
    use tapscripts::opcodes::{execute_script, pushable, unroll};

    #[test]
    fn test_zip() {
        const N_BITS: usize = 1500;
        const N_U30_LIMBS: usize = 50;

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for i in 0..50 {
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
            assert!(exec_result.success);
        }

        for i in 0..50 {
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
                { UintImpl::<N_BITS>::zip(0, 1) }
                { unroll((N_U30_LIMBS * 2) as u32, |i| script! {
                    { expected[N_U30_LIMBS * 2 - 1 - (i as usize)] }
                    OP_EQUALVERIFY
                })}
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
            let a_lessthan = if a.cmp(&b) == Ordering::Less { 1u32 } else { 0u32 };

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
            let a_lessthanorequal = if a.cmp(&b) != Ordering::Greater { 1u32 } else { 0u32 };

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
            let a_greaterthan = if a.cmp(&b) == Ordering::Greater { 1u32 } else { 0u32 };

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
            let a_greaterthanorequal = if a.cmp(&b) != Ordering::Less { 1u32 } else { 0u32 };

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

    #[test]
    fn test_u30_to_bits() {
        let mut prng = ChaCha20Rng::seed_from_u64(2);

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
    }
}