use tapscripts::opcodes::execute_script;

#[cfg(test)]
mod test {
    use core::ops::{Add, Rem, Shl};
    use rand_chacha::ChaCha20Rng;
    use rand::{Rng, SeedableRng};
    use bitcoin_script::bitcoin_script as script;
    use num_bigint::{BigUint, RandomBits};
    use num_traits::One;
    use tapscripts::opcodes::uint::UintImpl;
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
        const N_BITS: usize = 256;

        for _ in 0..100 {
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
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_sub() {
        const N_BITS: usize = 256;

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..100 {
            let a: BigUint = prng.sample(RandomBits::new(256));
            let b: BigUint = prng.sample(RandomBits::new(256));
            let mut c: BigUint = BigUint::one().shl(256) + &a - &b;
            c = c.rem(BigUint::one().shl(256));

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
}