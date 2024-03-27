use crate::treepp::{script, Script, pushable};
use crate::ubigint::UBigIntImpl;

impl<const N_BITS: u32> UBigIntImpl<N_BITS> {
    pub fn mul() -> Script {

        script! {
            { Self::convert_to_bits_toaltstack() }

            for _ in 0..Self::N_LIMBS {
                0
            }

            OP_FROMALTSTACK
            OP_IF
                { Self::copy(1) }
                { Self::add(1, 0) }
            OP_ENDIF

            for _ in 1..(N_BITS - 1) {
                { Self::bring(1) }
                { Self::double(0) }
                { Self::bring(1) }
                OP_FROMALTSTACK
                OP_IF
                    { Self::copy(1) }
                    { Self::add(1, 0) }
                OP_ENDIF
            }

            { Self::bring(1) }
            { Self::double(0) }
            OP_FROMALTSTACK
            OP_IF
                { Self::add(1, 0) }
            OP_ELSE
                { Self::drop() }
            OP_ENDIF
        }
    }
}

#[cfg(test)]
mod test {
    use core::ops::{Mul, Rem, Shl};
    use crate::treepp::{execute_script, pushable};
    use crate::ubigint::UBigIntImpl;
    use bitcoin_script::script;
    use num_bigint::{BigUint, RandomBits};
    use num_traits::One;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_mul() {
        const N_BITS: u32 = 254;

        for _ in 0..3 {
            let mut prng = ChaCha20Rng::seed_from_u64(0);

            let a: BigUint = prng.sample(RandomBits::new(254));
            let b: BigUint = prng.sample(RandomBits::new(254));
            let c: BigUint = (a.clone().mul(b.clone())).rem(BigUint::one().shl(254));

            let script = script! {
                { UBigIntImpl::<N_BITS>::push_u32_le(&a.to_u32_digits()) }
                { UBigIntImpl::<N_BITS>::push_u32_le(&b.to_u32_digits()) }
                { UBigIntImpl::<N_BITS>::mul() }
                { UBigIntImpl::<N_BITS>::push_u32_le(&c.to_u32_digits()) }
                { UBigIntImpl::<N_BITS>::equalverify(1, 0) }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}