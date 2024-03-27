use crate::treepp::*;
use crate::ubigint::UBigIntImpl;

impl<const N_BITS: u32> UBigIntImpl<N_BITS> {
    pub fn sub(a: u32, b: u32) -> Script {
        let head = N_BITS - (Self::N_LIMBS - 1) * 30;
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
            for _ in 0..Self::N_LIMBS - 2 {
                OP_ROT
                OP_ADD
                OP_SWAP
                u30_sub_carry
                OP_SWAP
                OP_TOALTSTACK
            }

            // A{N-1} - (B{N-1} + borrow_{N-2})
            OP_SWAP OP_DROP
            OP_ADD
            { u30_sub_nocarry(head_offset) }

            for _ in 0..Self::N_LIMBS - 1 {
                OP_FROMALTSTACK
            }
        }
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

pub fn u30_sub_nocarry(head_offset: u32) -> Script {
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
    use crate::treepp::{execute_script, pushable};
    use crate::ubigint::UBigIntImpl;
    use bitcoin_script::script;
    use core::ops::{Rem, Shl};
    use num_bigint::{BigUint, RandomBits};
    use num_traits::One;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_sub() {
        const N_BITS: u32 = 254;

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..100 {
            let a: BigUint = prng.sample(RandomBits::new(254));
            let b: BigUint = prng.sample(RandomBits::new(254));
            let mut c: BigUint = BigUint::one().shl(254) + &a - &b;
            c = c.rem(BigUint::one().shl(254));

            let script = script! {
                { UBigIntImpl::<N_BITS>::push_u32_le(&a.to_u32_digits()) }
                { UBigIntImpl::<N_BITS>::push_u32_le(&b.to_u32_digits()) }
                { UBigIntImpl::<N_BITS>::sub(1, 0) }
                { UBigIntImpl::<N_BITS>::push_u32_le(&c.to_u32_digits()) }
                { UBigIntImpl::<N_BITS>::equalverify(1, 0) }
                OP_PUSHNUM_1
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);

            let script = script! {
                { UBigIntImpl::<N_BITS>::push_u32_le(&b.to_u32_digits()) }
                { UBigIntImpl::<N_BITS>::push_u32_le(&a.to_u32_digits()) }
                { UBigIntImpl::<N_BITS>::sub(0, 1) }
                { UBigIntImpl::<N_BITS>::push_u32_le(&c.to_u32_digits()) }
                { UBigIntImpl::<N_BITS>::equalverify(1, 0) }
                OP_PUSHNUM_1
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}
