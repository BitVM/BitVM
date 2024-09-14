use crate::bigint::BigIntImpl;
use crate::pseudo::push_to_stack;
use crate::treepp::{script, Script};

impl<const N_BITS: u32, const LIMB_SIZE: u32> BigIntImpl<N_BITS, LIMB_SIZE> {
    pub fn mul() -> Script {
        script! {
            { Self::convert_to_be_bits_toaltstack() }

            { push_to_stack(0,Self::N_LIMBS as usize) }


            OP_FROMALTSTACK
            OP_IF
                { Self::copy(1) }
                { Self::add(1, 0) }
            OP_ENDIF

            for _ in 1..N_BITS - 1 {
                { Self::roll(1) }
                { Self::double(0) }
                { Self::roll(1) }
                OP_FROMALTSTACK
                OP_IF
                    { Self::copy(1) }
                    { Self::add(1, 0) }
                OP_ENDIF
            }

            { Self::roll(1) }
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
    use crate::bigint::{U254, U64};
    use crate::{execute_script_as_chunks, treepp::*};
    use core::ops::{Mul, Rem, Shl};
    use num_bigint::{BigUint, RandomBits};
    use num_traits::One;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_mul() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        for _ in 0..3 {
            let a: BigUint = prng.sample(RandomBits::new(254));
            let b: BigUint = prng.sample(RandomBits::new(254));
            let c: BigUint = (a.clone().mul(b.clone())).rem(BigUint::one().shl(254));

            let script = script! {
                { U254::push_u32_le(&a.to_u32_digits()) }
                { U254::push_u32_le(&b.to_u32_digits()) }
                { U254::mul() }
                { U254::push_u32_le(&c.to_u32_digits()) }
                { U254::equalverify(1, 0) }
                OP_TRUE
            };
            run(script);
        }

        for _ in 0..3 {
            let a: BigUint = prng.sample(RandomBits::new(64));
            let b: BigUint = prng.sample(RandomBits::new(64));
            let c: BigUint = (a.clone().mul(b.clone())).rem(BigUint::one().shl(64));

            let script = script! {
                { U64::push_u32_le(&a.to_u32_digits()) }
                { U64::push_u32_le(&b.to_u32_digits()) }
                { U64::mul() }
                { U64::push_u32_le(&c.to_u32_digits()) }
                { U64::equalverify(1, 0) }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_mul_as_chunks() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let a: BigUint = prng.sample(RandomBits::new(254));
        let b: BigUint = prng.sample(RandomBits::new(254));
        let c: BigUint = (a.clone().mul(b.clone())).rem(BigUint::one().shl(254));

        let script = script! {
            { U254::push_u32_le(&a.to_u32_digits()) }
            { U254::push_u32_le(&b.to_u32_digits()) }
            { U254::mul() }
            { U254::push_u32_le(&c.to_u32_digits()) }
            { U254::equalverify(1, 0) }
            OP_TRUE
        };
        println!("compiled size: {:?}", script.clone().compile().len());
        let exec_result = execute_script_as_chunks(script, 20000, 400);
        println!("Execute info: {}", exec_result);
        assert!(exec_result.success);
    }
}
