use crate::bigint::BigIntImpl;
use crate::treepp::*;

impl<const N_BITS: u32, const LIMB_SIZE: u32> BigIntImpl<N_BITS, LIMB_SIZE> {
    pub fn div2() -> Script {
        script! {
            { Self::div2rem() }
            OP_DROP
        }
    }

    pub fn div2rem() -> Script {
        script! {
            { Self::N_LIMBS - 1 } OP_ROLL
            0
            { limb_shr1_carry(Self::HEAD) }

            for _ in 1..Self::N_LIMBS {
                { Self::N_LIMBS } OP_ROLL
                OP_SWAP
                { limb_shr1_carry(LIMB_SIZE) }
            }
        }
    }

    pub fn div3() -> Script {
        script! {
            { Self::div3rem() }
            OP_DROP
        }
    }

    pub fn div3rem() -> Script {
        script! {
            { Self::N_LIMBS - 1 } OP_ROLL
            0
            { limb_div3_carry(Self::HEAD) }

            for _ in 1..Self::N_LIMBS {
                { Self::N_LIMBS } OP_ROLL
                OP_SWAP
                { limb_div3_carry(LIMB_SIZE) }
            }
        }
    }
}

pub fn limb_shr1_carry(num_bits: u32) -> Script {
    let powers_of_2_script = if num_bits < 7 {
        script! {
            for i in 1..num_bits {
                { 2_u32.pow(i) }
            }
        }
    } else {
        script! {
            2 4 8 16 32 64              // 2^1 to 2^6
            for _ in 0..num_bits - 7 {
                OP_DUP OP_DUP OP_ADD
            }                           // 2^7 to 2^{num_bits - 1}
        }
    };

    script! {
        { powers_of_2_script }
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

// divide limb by 3, also remainder
pub fn limb_div3_carry(limb_size: u32) -> Script {
    let max_limb = (1 << limb_size) as i64;

    let x_quotient = max_limb / 3;
    let x_remainder = max_limb % 3;

    let y_quotient = max_limb * 2 / 3;
    let y_remainder = max_limb * 2 % 3;

    let mut k = 0;
    let mut cur = 1;
    while cur < max_limb {
        k += 1;
        cur *= 3;
    }

    script! {
        1 2 3 6 9 18 27 54
        for _ in 0..k - 4 {
            OP_2DUP OP_ADD
            OP_DUP OP_DUP OP_ADD
        }

        { 2 * k } OP_ROLL OP_DUP
        0 OP_GREATERTHAN
        OP_IF
            OP_1SUB
            OP_IF
                { y_remainder } { y_quotient }
            OP_ELSE
                { x_remainder } { x_quotient }
            OP_ENDIF
        OP_ELSE
            0
        OP_ENDIF
        OP_TOALTSTACK

        { 2 * k + 1 } OP_ROLL OP_ADD

        for _ in 0..2 * k - 2 {
            OP_2DUP OP_LESSTHANOREQUAL
            OP_IF
                OP_SWAP OP_SUB 2 OP_PICK OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
            OP_ELSE
                OP_NIP
            OP_ENDIF
        }

        OP_NIP OP_NIP OP_FROMALTSTACK OP_SWAP
    }
}

#[cfg(test)]
mod test {
    use crate::bigint::inv::{limb_div3_carry, limb_shr1_carry};
    use crate::bigint::{U254, U64};
    use crate::treepp::*;

    use core::ops::{Div, Shr};
    use num_bigint::{BigUint, RandomBits};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_limb_shr1_carry() {
        for shift in 2..30 {
            println!("limb_shr1_carry({:?}): {} bytes", shift, limb_shr1_carry(shift).len());
            let mut prng = ChaCha20Rng::seed_from_u64(0);

            for _ in 0..100 {
                let mut a: u32 = prng.gen();
                a %= 1 << shift;

                let script = script! {
                    { a }
                    { 0 }
                    { limb_shr1_carry(shift) }
                    { a & 1 } OP_EQUALVERIFY
                    { a >> 1 } OP_EQUAL
                };

                run(script);
            }

            for _ in 0..100 {
                let mut a: u32 = prng.gen();
                a %= 1 << shift;

                let script = script! {
                    { a }
                    { 1 }
                    { limb_shr1_carry(shift) }
                    { a & 1 } OP_EQUALVERIFY
                    { (1 << (shift - 1)) | (a >> 1) } OP_EQUAL
                };

                run(script);
            }
        }
    }

    #[test]
    fn test_limb_div3_carry() {
        println!("limb_div3_carry: {} bytes", limb_div3_carry(29).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..100 {
            let mut a: u32 = prng.gen();
            a %= 1 << 29;
            let k = 2_u32.pow(29);

            for r in 0..3 {
                let a2 = a + r * k;
                let b = a2 % 3;
                let c = a2 / 3;
                let script = script! {
                    { a }
                    { r }
                    { limb_div3_carry(29) }
                    { b } OP_EQUALVERIFY
                    { c } OP_EQUAL
                };

                run(script);
            }
        }
    }

    #[test]
    fn test_div2() {
        println!("U254.div2: {} bytes", U254::div2().len());
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
            run(script);
        }

        for _ in 0..100 {
            let a: BigUint = prng.sample(RandomBits::new(64));
            let c: BigUint = a.clone().shr(1);

            let script = script! {
                { U64::push_u32_le(&a.to_u32_digits()) }
                { U64::div2() }
                { U64::push_u32_le(&c.to_u32_digits()) }
                { U64::equalverify(1, 0) }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_div3() {
        println!("U254.div3: {} bytes", U254::div3().len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        for _ in 0..100 {
            let a: BigUint = prng.sample(RandomBits::new(254));
            let c: BigUint = a.clone().div(BigUint::from(3_u32));

            let script = script! {
                { U254::push_u32_le(&a.to_u32_digits()) }
                { U254::div3() }
                { U254::push_u32_le(&c.to_u32_digits()) }
                { U254::equalverify(1, 0) }
                OP_TRUE
            };
            run(script);
        }

        for _ in 0..100 {
            let a: BigUint = prng.sample(RandomBits::new(64));
            let c: BigUint = a.clone().div(BigUint::from(3_u32));

            let script = script! {
                { U64::push_u32_le(&a.to_u32_digits()) }
                { U64::div3() }
                { U64::push_u32_le(&c.to_u32_digits()) }
                { U64::equalverify(1, 0) }
                OP_TRUE
            };
            run(script);
        }
    }
}
