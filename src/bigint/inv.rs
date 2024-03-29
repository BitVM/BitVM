use crate::bigint::BigIntImpl;
use crate::treepp::*;

impl<const N_BITS: u32> BigIntImpl<N_BITS> {
    pub fn div2() -> Script {
        script! {
            { Self::N_LIMBS - 1 } OP_ROLL
            0
            { u30_shr1_carry(Self::HEAD) }

            for _ in 1..Self::N_LIMBS {
                { Self::N_LIMBS } OP_ROLL
                OP_SWAP
                { u30_shr1_carry(30) }
            }
            OP_DROP
        }
    }
}

pub fn u30_shr1_carry(num_bits: u32) -> Script {
    script! {
        2                           // 2^1
        for _ in 0..num_bits - 2 {
            OP_DUP OP_DUP OP_ADD
        }                           // 2^2 to 2^{num_bits - 1}
        { num_bits - 1 } OP_ROLL
        OP_IF
            OP_DUP
        OP_ELSE
            0
        OP_ENDIF
        OP_TOALTSTACK

        { num_bits - 1 } OP_ROLL

        for _ in 0..num_bits - 2 {
            OP_2DUP OP_LESSTHANOREQUAL
            OP_IF
                OP_SWAP OP_SUB OP_SWAP OP_DUP OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_SWAP
            OP_ELSE
                OP_NIP
            OP_ENDIF
        }

        OP_2DUP OP_LESSTHANOREQUAL
        OP_IF
            OP_SWAP OP_SUB OP_FROMALTSTACK OP_1ADD
        OP_ELSE
            OP_NIP OP_FROMALTSTACK
        OP_ENDIF
        OP_SWAP
    }
}

#[cfg(test)]
mod test {
    use crate::bigint::inv::u30_shr1_carry;
    use crate::bigint::U254;
    use crate::treepp::*;
    use core::ops::Shr;
    use num_bigint::{BigUint, RandomBits};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_u30_shr1_carry() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..100 {
            let mut a: u32 = prng.gen();
            a = a % (1 << 30);

            let script = script! {
                { a }
                { 0 }
                { u30_shr1_carry(30) }
                { a & 1 } OP_EQUALVERIFY
                { a >> 1 } OP_EQUAL
            };

            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }

        for _ in 0..100 {
            let mut a: u32 = prng.gen();
            a = a % (1 << 30);

            let script = script! {
                { a }
                { 1 }
                { u30_shr1_carry(30) }
                { a & 1 } OP_EQUALVERIFY
                { (1 << 29) | (a >> 1) } OP_EQUAL
            };

            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_div2() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        for _ in 0..100 {
            let a: BigUint = prng.sample(RandomBits::new(254));
            let c: BigUint = a.clone().shr(1);

            let script = script! {
                { U254::push_u32_le(&a.to_u32_digits()) }
                { U254::div2() }
                { U254::push_u32_le(&c.to_u32_digits()) }
                { U254::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}
