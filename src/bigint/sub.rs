use crate::bigint::BigIntImpl;
use crate::treepp::*;

impl<const N_BITS: u32, const LIMB_SIZE: u32> BigIntImpl<N_BITS, LIMB_SIZE> {
    /// Compute the difference of two BigInts
    pub fn sub(a: u32, b: u32) -> Script {
        if b == 0 {
            script! {

                {a * Self::N_LIMBS} OP_ROLL OP_SWAP
                OP_SUB
                { 1 << LIMB_SIZE }
                OP_SWAP

                // A0 - B0
                {limb_create_borrow(2)} OP_TOALTSTACK

                // from     A1      - (B1        + borrow_0)
                //   to     A{N-2}  - (B{N-2}    + borrow_{N-3})
                for i in 0..Self::N_LIMBS - 2 {
                    OP_ROT
                    OP_ADD
                    {a * Self::N_LIMBS - i} OP_ROLL OP_SWAP
                    OP_SUB {limb_create_borrow(2)} OP_TOALTSTACK
                }

                // A{N-1} - (B{N-1} + borrow_{N-2})
                OP_NIP
                OP_ADD
                {(a-1) * Self::N_LIMBS + 1} OP_ROLL OP_SWAP
                { limb_sub_noborrow(Self::HEAD_OFFSET) }

                for _ in 0..Self::N_LIMBS - 1 {
                    OP_FROMALTSTACK
                }
            }
        } else {
            script! {
                {Self::zip(a, b)}

                OP_SUB
                { 1 << LIMB_SIZE }
                OP_SWAP

                // A0 - B0
                {limb_create_borrow(2)} OP_TOALTSTACK

                // from     A1      - (B1        + borrow_0)
                //   to     A{N-2}  - (B{N-2}    + borrow_{N-3})
                for _ in 0..Self::N_LIMBS - 2 {
                    OP_2SWAP
                    OP_SUB
                    OP_SWAP
                    OP_SUB {limb_create_borrow(2)} OP_TOALTSTACK
                }

                // A{N-1} - (B{N-1} + borrow_{N-2})
                OP_NIP
                OP_ADD
                { limb_sub_noborrow(Self::HEAD_OFFSET) }

                for _ in 0..Self::N_LIMBS - 1 {
                    OP_FROMALTSTACK
                }
            }
        }
    }
}

/// Create the borrow bit for the substitution operation
pub fn limb_create_borrow(a: u32) -> Script {
    script! {
        OP_DUP
        0
        OP_LESSTHAN
        OP_TUCK
        OP_IF
            {a} OP_PICK OP_ADD
        OP_ENDIF
    }
}

/// Compute the sum of two limbs, dropping the carry bit
///
/// Author: @weikengchen
pub fn limb_sub_noborrow(head_offset: u32) -> Script {
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

#[cfg(test)]
mod test {
    use crate::bigint::{U254, U64};
    use crate::treepp::*;
    use core::ops::{Rem, Shl};
    use num_bigint::{BigUint, RandomBits};
    use num_traits::One;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_sub() {
        println!("U254.sub: {} bytes", U254::sub(1, 0).len());

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..100 {
            let a: BigUint = prng.sample(RandomBits::new(254));
            let b: BigUint = prng.sample(RandomBits::new(254));
            let mut c: BigUint = BigUint::one().shl(254) + &a - &b;
            c = c.rem(BigUint::one().shl(254));

            let script = script! {
                { U254::push_u32_le(&a.to_u32_digits()) }
                { U254::push_u32_le(&b.to_u32_digits()) }
                { U254::sub(1, 0) }
                { U254::push_u32_le(&c.to_u32_digits()) }
                { U254::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);

            let script = script! {
                { U254::push_u32_le(&b.to_u32_digits()) }
                { U254::push_u32_le(&a.to_u32_digits()) }
                { U254::sub(0, 1) }
                { U254::push_u32_le(&c.to_u32_digits()) }
                { U254::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }

        for _ in 0..100 {
            let a: BigUint = prng.sample(RandomBits::new(64));
            let b: BigUint = prng.sample(RandomBits::new(64));
            let mut c: BigUint = BigUint::one().shl(64) + &a - &b;
            c = c.rem(BigUint::one().shl(64));

            let script = script! {
                { U64::push_u32_le(&a.to_u32_digits()) }
                { U64::push_u32_le(&b.to_u32_digits()) }
                { U64::sub(1, 0) }
                { U64::push_u32_le(&c.to_u32_digits()) }
                { U64::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);

            let script = script! {
                { U64::push_u32_le(&b.to_u32_digits()) }
                { U64::push_u32_le(&a.to_u32_digits()) }
                { U64::sub(0, 1) }
                { U64::push_u32_le(&c.to_u32_digits()) }
                { U64::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}
