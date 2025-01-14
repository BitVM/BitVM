use crate::bigint::BigIntImpl;
use crate::treepp::{script, Script};
use std::cmp::min;

impl<const N_BITS: u32, const LIMB_SIZE: u32> BigIntImpl<N_BITS, LIMB_SIZE> {
    pub fn convert_to_be_bits() -> Script {
        script! {
            for i in 0..Self::N_LIMBS - 1 {
                { limb_to_be_bits(LIMB_SIZE) }
                { LIMB_SIZE * (i + 1) } OP_ROLL
            }
            { limb_to_be_bits(N_BITS - LIMB_SIZE * (Self::N_LIMBS - 1)) }
        }
    }

    pub fn convert_to_le_bits() -> Script {
        script! {
            for _ in 0..Self::N_LIMBS - 1 {
                OP_TOALTSTACK
            }
            { limb_to_le_bits(N_BITS - LIMB_SIZE * (Self::N_LIMBS - 1)) }
            for _ in 0..Self::N_LIMBS - 1 {
                OP_FROMALTSTACK
                { limb_to_le_bits(LIMB_SIZE) }
            }
        }
    }

    pub fn convert_to_be_bits_toaltstack() -> Script {
        script! {
            { Self::N_LIMBS - 1 } OP_ROLL
            { limb_to_be_bits_toaltstack(N_BITS - LIMB_SIZE * (Self::N_LIMBS - 1)) }
            for i in 0..Self::N_LIMBS - 1 {
                { Self::N_LIMBS - 2 - i } OP_ROLL
                { limb_to_be_bits_toaltstack(LIMB_SIZE) }
            }
        }
    }

    pub fn convert_to_le_bits_toaltstack() -> Script {
        script! {
            for _ in 0..Self::N_LIMBS - 1 {
                { limb_to_le_bits_toaltstack(LIMB_SIZE) }
            }
            { limb_to_le_bits_toaltstack(N_BITS - LIMB_SIZE * (Self::N_LIMBS - 1)) }
        }
    }

    pub fn limb_from_bytes() -> Script {
        let bytes_per_limb = (LIMB_SIZE + 7) / 8;

        assert!(LIMB_SIZE > 0, "LIMB_SIZE must not be 0");
        assert!(LIMB_SIZE < 33, "LIMB_SIZE must be less than 33");

        script! {
            // This will be our sum on the stack
            OP_0
            for i in 0..bytes_per_limb {
                // Check that the number is a u8
                OP_SWAP
                OP_DUP
                { 256 }
                OP_LESSTHAN
                OP_VERIFY
                // lshift
                for _ in 0..8*i {
                    OP_DUP
                    OP_ADD
                }
                OP_ADD
            }
        }
    }

    pub fn from_bytes() -> Script {
        script! {
            for _ in 0..Self::N_LIMBS {
                { Self::limb_from_bytes() }
                OP_TOALTSTACK
            }
            for _ in 0..Self::N_LIMBS {
                OP_FROMALTSTACK
            }
        }
    }
}

fn limb_to_be_bits_common(num_bits: u32) -> Script {
    let min_i = min(22, num_bits - 1);
    script! {
        OP_TOALTSTACK

        // Push the powers of 2 onto the stack
        // First, all powers of 2 that we can push as 3-byte numbers
        for i in 0..min_i  {
            { 2 << i }
        }
        // Then, we double powers of 2 to generate the 4-byte numbers
        for _ in min_i..num_bits - 1 {
            OP_DUP
            OP_DUP
            OP_ADD
        }

        OP_FROMALTSTACK

        for _ in 0..num_bits - 2 {
            OP_2DUP OP_LESSTHANOREQUAL
            OP_IF
                OP_SWAP OP_SUB 1
            OP_ELSE
                OP_NIP 0
            OP_ENDIF
            OP_TOALTSTACK
        }

        OP_2DUP OP_LESSTHANOREQUAL
        OP_IF
            OP_SWAP OP_SUB 1
        OP_ELSE
            OP_NIP 0
        OP_ENDIF
    }
}

fn limb_to_le_bits_common(num_bits: u32) -> Script {
    let min_i = min(22, num_bits - 1);
    script! {
        // Push the powers of 2 onto the stack
        // First, all powers of 2 that we can push as 3-byte numbers
        for i in 0..min_i - 1  {
            { 2 << i } OP_TOALTSTACK
        }
        if num_bits - 1 > min_i {
            { 2 << (min_i - 1) } OP_DUP OP_TOALTSTACK

            // Then, we double powers of 2 to generate the 4-byte numbers
            for _ in min_i..num_bits - 2 {
                OP_DUP
                OP_ADD
                OP_DUP OP_TOALTSTACK
            }

            OP_DUP
            OP_ADD OP_TOALTSTACK
        } else {
            { 2 << (min_i - 1) } OP_TOALTSTACK
        }

        for _ in 0..num_bits - 2 {
            OP_FROMALTSTACK
            OP_2DUP OP_GREATERTHANOREQUAL
            OP_IF
                OP_SUB 1
            OP_ELSE
                OP_DROP 0
            OP_ENDIF
            OP_SWAP
        }

        OP_FROMALTSTACK
        OP_2DUP OP_GREATERTHANOREQUAL
        OP_IF
            OP_SUB 1
        OP_ELSE
            OP_DROP 0
        OP_ENDIF

        OP_SWAP
    }
}

pub fn limb_to_le_bits(num_bits: u32) -> Script {
    if num_bits >= 2 {
        script! {
            { limb_to_le_bits_common(num_bits) }
        }
    } else {
        script! {}
    }
}

pub fn limb_to_le_bits_toaltstack(num_bits: u32) -> Script {
    if num_bits >= 2 {
        script! {
            { limb_to_le_bits_common(num_bits) }
            for _ in 0..num_bits {
                OP_TOALTSTACK
            }
        }
    } else {
        script! {}
    }
}

pub fn limb_to_be_bits(num_bits: u32) -> Script {
    if num_bits >= 2 {
        script! {
            { limb_to_be_bits_common(num_bits) }
            for _ in 0..num_bits - 2 {
                OP_FROMALTSTACK
            }
        }
    } else {
        script! {}
    }
}

pub fn limb_to_be_bits_toaltstack(num_bits: u32) -> Script {
    if num_bits >= 2 {
        script! {
            { limb_to_be_bits_common(num_bits) }
            OP_TOALTSTACK
            OP_TOALTSTACK
        }
    } else {
        script! {
            OP_TOALTSTACK
        }
    }
}

#[cfg(test)]
mod test {
    use super::{limb_to_be_bits, limb_to_le_bits};
    use crate::bigint::{U254, U64};
    use crate::run;
    use bitcoin_script::script;
    use core::ops::ShrAssign;
    use num_bigint::{BigUint, RandomBits};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_limb_to_be_bits() {
        println!(
            "limb_to_be_bits(29): {:?} bytes",
            script! { {limb_to_be_bits(29)} }.len()
        );
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..100 {
            let mut a: u32 = prng.gen();
            a %= 1 << 29;

            let mut bits = vec![];
            let mut cur = a;
            for _ in 0..29 {
                bits.push(cur % 2);
                cur /= 2;
            }

            let script = script! {
                { a }
                { limb_to_be_bits(29) }
                for i in 0..29 {
                    { bits[28 - i] }
                    OP_EQUALVERIFY
                }
                OP_TRUE
            };
            run(script);
        }

        for _ in 0..100 {
            let mut a: u32 = prng.gen();
            a %= 1 << 15;

            let mut bits = vec![];
            let mut cur = a;
            for _ in 0..15 {
                bits.push(cur % 2);
                cur /= 2;
            }

            let script = script! {
                { a }
                { limb_to_be_bits(15) }
                for i in 0..15 {
                    { bits[14 - i as usize] }
                    OP_EQUALVERIFY
                }
                OP_TRUE
            };

            run(script);
        }

        for a in 0..4 {
            let script = script! {
                { a }
                { limb_to_be_bits(2) }
                { a >> 1 } OP_EQUALVERIFY
                { a & 1 } OP_EQUAL
            };
            run(script);
        }

        for a in 0..2 {
            let script = script! {
                { a }
                { limb_to_be_bits(1) }
                { a } OP_EQUAL
            };
            run(script);
        }

        let script = script! {
            0 { limb_to_be_bits(0) } 0 OP_EQUAL
        };
        run(script);
    }

    #[test]
    fn test_limb_to_le_bits() {
        println!(
            "limb_to_le_bits(29): {:?} bytes",
            script! { {limb_to_le_bits(29)} }.len()
        );
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..100 {
            let mut a: u32 = prng.gen();
            a %= 1 << 29;

            let mut bits = vec![];
            let mut cur = a;
            for _ in 0..29 {
                bits.push(cur % 2);
                cur /= 2;
            }

            let script = script! {
                { a }
                { limb_to_le_bits(29) }
                for i in 0..29 {
                    { bits[i] }
                    OP_EQUALVERIFY
                }
                OP_TRUE
            };

            run(script);
        }

        for _ in 0..100 {
            let mut a: u32 = prng.gen();
            a %= 1 << 15;

            let mut bits = vec![];
            let mut cur = a;
            for _ in 0..15 {
                bits.push(cur % 2);
                cur /= 2;
            }

            let script = script! {
                { a }
                { limb_to_le_bits(15) }
                for i in 0..15 {
                    { bits[i] }
                    OP_EQUALVERIFY
                }
                OP_TRUE
            };

            run(script);
        }

        for a in 0..4 {
            let script = script! {
                { a }
                { limb_to_le_bits(2) }
                { a & 1 } OP_EQUALVERIFY
                { a >> 1 } OP_EQUAL
            };
            run(script);
        }

        for a in 0..2 {
            let script = script! {
                { a }
                { limb_to_le_bits(1) }
                { a } OP_EQUAL
            };
            run(script);
        }

        let script = script! {
            0 { limb_to_le_bits(0) } 0 OP_EQUAL
        };
        run(script);
    }

    #[test]
    fn test_ubigint_to_be_bits() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..10 {
            let a: BigUint = prng.sample(RandomBits::new(U254::N_BITS as u64));

            let mut bits = vec![];
            let mut cur = a.clone();
            for _ in 0..U254::N_BITS {
                bits.push(if cur.bit(0) { 1 } else { 0 });
                cur.shr_assign(1);
            }

            let script = script! {
                { U254::push_u32_le(&a.to_u32_digits()) }
                { U254::convert_to_be_bits() }
                for i in 0..U254::N_BITS {
                    { bits[(U254::N_BITS - 1 - i) as usize] }
                    OP_EQUALVERIFY
                }
                OP_TRUE
            };
            run(script);
        }

        for _ in 0..10 {
            let a: BigUint = prng.sample(RandomBits::new(U64::N_BITS as u64));

            let mut bits = vec![];
            let mut cur = a.clone();
            for _ in 0..U64::N_BITS {
                bits.push(if cur.bit(0) { 1 } else { 0 });
                cur.shr_assign(1);
            }

            let script = script! {
                { U64::push_u32_le(&a.to_u32_digits()) }
                { U64::convert_to_be_bits() }
                for i in 0..U64::N_BITS {
                    { bits[(U64::N_BITS - 1 - i) as usize] }
                    OP_EQUALVERIFY
                }
                OP_TRUE
            };

            run(script);
        }
    }

    #[test]
    fn test_ubigint_to_le_bits() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..10 {
            let a: BigUint = prng.sample(RandomBits::new(U254::N_BITS as u64));

            let mut bits = vec![];
            let mut cur = a.clone();
            for _ in 0..U254::N_BITS {
                bits.push(if cur.bit(0) { 1 } else { 0 });
                cur.shr_assign(1);
            }

            let script = script! {
                { U254::push_u32_le(&a.to_u32_digits()) }
                { U254::convert_to_le_bits() }
                for i in 0..U254::N_BITS {
                    { bits[i as usize] }
                    OP_EQUALVERIFY
                }
                OP_TRUE
            };

            run(script);
        }

        for _ in 0..10 {
            let a: BigUint = prng.sample(RandomBits::new(U64::N_BITS as u64));

            let mut bits = vec![];
            let mut cur = a.clone();
            for _ in 0..U64::N_BITS {
                bits.push(if cur.bit(0) { 1 } else { 0 });
                cur.shr_assign(1);
            }

            let script = script! {
                { U64::push_u32_le(&a.to_u32_digits()) }
                { U64::convert_to_le_bits() }
                for i in 0..U64::N_BITS {
                    { bits[i as usize] }
                    OP_EQUALVERIFY
                }
                OP_TRUE
            };

            run(script);
        }
    }

    #[test]
    fn test_ubigint_to_be_bits_toaltstack() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..10 {
            let a: BigUint = prng.sample(RandomBits::new(U254::N_BITS as u64));

            let mut bits = vec![];
            let mut cur = a.clone();
            for _ in 0..U254::N_BITS {
                bits.push(if cur.bit(0) { 1 } else { 0 });
                cur.shr_assign(1);
            }

            let script = script! {
                { U254::push_u32_le(&a.to_u32_digits()) }
                { U254::convert_to_be_bits_toaltstack() }
                for i in 0..U254::N_BITS {
                    OP_FROMALTSTACK
                    { bits[i as usize] }
                    OP_EQUALVERIFY
                }
                OP_TRUE
            };

            run(script);
        }

        for _ in 0..10 {
            let a: BigUint = prng.sample(RandomBits::new(U64::N_BITS as u64));

            let mut bits = vec![];
            let mut cur = a.clone();
            for _ in 0..U64::N_BITS {
                bits.push(if cur.bit(0) { 1 } else { 0 });
                cur.shr_assign(1);
            }

            let script = script! {
                { U64::push_u32_le(&a.to_u32_digits()) }
                { U64::convert_to_be_bits_toaltstack() }
                for i in 0..U64::N_BITS {
                    OP_FROMALTSTACK
                    { bits[i as usize] }
                    OP_EQUALVERIFY
                }
                OP_TRUE
            };

            run(script);
        }
    }

    #[test]
    fn test_ubigint_to_le_bits_toaltstack() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..10 {
            let a: BigUint = prng.sample(RandomBits::new(U254::N_BITS as u64));

            let mut bits = vec![];
            let mut cur = a.clone();
            for _ in 0..U254::N_BITS {
                bits.push(if cur.bit(0) { 1 } else { 0 });
                cur.shr_assign(1);
            }

            let script = script! {
                { U254::push_u32_le(&a.to_u32_digits()) }
                { U254::convert_to_le_bits_toaltstack() }
                for i in 0..U254::N_BITS {
                    OP_FROMALTSTACK
                    { bits[(U254::N_BITS - 1 - i) as usize] }
                    OP_EQUALVERIFY
                }
                OP_TRUE
            };

            run(script);
        }

        for _ in 0..10 {
            let a: BigUint = prng.sample(RandomBits::new(U64::N_BITS as u64));

            let mut bits = vec![];
            let mut cur = a.clone();
            for _ in 0..U64::N_BITS {
                bits.push(if cur.bit(0) { 1 } else { 0 });
                cur.shr_assign(1);
            }

            let script = script! {
                { U64::push_u32_le(&a.to_u32_digits()) }
                { U64::convert_to_le_bits_toaltstack() }
                for i in 0..U64::N_BITS {
                    OP_FROMALTSTACK
                    { bits[(U64::N_BITS - 1 - i) as usize] }
                    OP_EQUALVERIFY
                }
                OP_TRUE
            };

            run(script);
        }
    }

    #[test]
    fn test_u29_limb_from_bytes() {
        assert_eq!(U254::N_LIMBS, 9);
        let script = script! {
            { 0x01 }
            { 0x12 }
            { 0x13 }
            { 0x14 }
            { U254::limb_from_bytes() }
            { 0x01121314 }
            OP_EQUAL
        };
        run(script);

        let script = script! {
            { 0x00 }
            { 0x01 }
            { 0x13 }
            { 0x14 }
            { U254::limb_from_bytes() }
            { 0x00011314 }
            OP_EQUAL
        };
        run(script);
    }
    #[test]
    fn test_u254_from_bytes() {
        assert_eq!(U254::N_LIMBS, 9);
        let script = script! {
            { 0x00 }
            { 0x01 }
            { 0x13 }
            { 0x14 }

            { 0x01 }
            { 0x22 }
            { 0x23 }
            { 0x24 }

            { 0x01 }
            { 0x32 }
            { 0x33 }
            { 0x34 }

            { 0x01 }
            { 0x42 }
            { 0x43 }
            { 0x44 }

            { 0x01 }
            { 0x52 }
            { 0x53 }
            { 0x54 }

            { 0x01 }
            { 0x62 }
            { 0x63 }
            { 0x64 }

            { 0x01 }
            { 0x72 }
            { 0x73 }
            { 0x74 }

            { 0x01 }
            { 0x82 }
            { 0x83 }
            { 0x84 }

            { 0x01 }
            { 0x92 }
            { 0x93 }
            { 0x94 }

            { U254::from_bytes() }
            { 0x00011314 }
            { 0x01222324 }
            { 0x01323334 }
            { 0x01424344 }
            { 0x01525354 }
            { 0x01626364 }
            { 0x01727374 }
            { 0x01828384 }
            { 0x01929394 }
            { U254::equal(0, 1) }
        };
        run(script);
    }
}
