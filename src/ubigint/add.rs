use crate::treepp::{pushable, script, Script};
use crate::ubigint::UBigIntImpl;
use crate::uint::{u30_add_carry, u30_add_nocarry};

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
            for _ in 0..n_limbs - 2 {
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

            for _ in 0..n_limbs - 1 {
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
            for _ in 0..n_limbs - 2 {
                OP_SWAP
                u30_add_carry
                OP_SWAP
                OP_TOALTSTACK
            }

            // A{N-1} + carry_{N-2}
            OP_SWAP OP_DROP
            { u30_add_nocarry(head_offset) }

            for _ in 0..n_limbs - 1 {
                OP_FROMALTSTACK
            }
        }
    }
}

#[cfg(test)]
mod test {
    use core::ops::{Add, Rem, Shl};
    use rand_chacha::ChaCha20Rng;
    use rand::{Rng, SeedableRng};
    use bitcoin_script::script;
    use num_bigint::{BigUint, RandomBits};
    use num_traits::One;
    use crate::treepp::{execute_script, pushable};
    use crate::ubigint::UBigIntImpl;

    #[test]
    fn test_add() {
        const N_BITS: usize = 254;

        for _ in 0..100 {
            let mut prng = ChaCha20Rng::seed_from_u64(0);

            let a: BigUint = prng.sample(RandomBits::new(254));
            let b: BigUint = prng.sample(RandomBits::new(254));
            let c: BigUint = (a.clone() + b.clone()).rem(BigUint::one().shl(254));

            let script = script! {
                { UBigIntImpl::<N_BITS>::push_u32_le(&a.to_u32_digits()) }
                { UBigIntImpl::<N_BITS>::push_u32_le(&b.to_u32_digits()) }
                { UBigIntImpl::<N_BITS>::add(1, 0) }
                { UBigIntImpl::<N_BITS>::push_u32_le(&c.to_u32_digits()) }
                { UBigIntImpl::<N_BITS>::equalverify(1, 0) }
                OP_PUSHNUM_1
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_double() {
        const N_BITS: usize = 254;

        for _ in 0..100 {
            let mut prng = ChaCha20Rng::seed_from_u64(0);

            let a: BigUint = prng.sample(RandomBits::new(254));
            let c: BigUint = (a.clone() + a.clone()).rem(BigUint::one().shl(254));

            let script = script! {
                { UBigIntImpl::<N_BITS>::push_u32_le(&a.to_u32_digits()) }
                { UBigIntImpl::<N_BITS>::double(0) }
                { UBigIntImpl::<N_BITS>::push_u32_le(&c.to_u32_digits()) }
                { UBigIntImpl::<N_BITS>::equalverify(1, 0) }
                OP_PUSHNUM_1
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_1add() {
        const N_BITS: usize = 254;

        for _ in 0..100 {
            let mut prng = ChaCha20Rng::seed_from_u64(0);

            let a: BigUint = prng.sample(RandomBits::new(254));
            let c: BigUint = (a.clone().add(BigUint::one())).rem(BigUint::one().shl(254));

            let script = script! {
                { UBigIntImpl::<N_BITS>::push_u32_le(&a.to_u32_digits()) }
                { UBigIntImpl::<N_BITS>::add1() }
                { UBigIntImpl::<N_BITS>::push_u32_le(&c.to_u32_digits()) }
                { UBigIntImpl::<N_BITS>::equalverify(1, 0) }
                OP_PUSHNUM_1
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}