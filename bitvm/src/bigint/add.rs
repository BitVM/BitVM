use crate::bigint::BigIntImpl;
use crate::pseudo::NMUL;
use crate::treepp::*;

impl<const N_BITS: u32, const LIMB_SIZE: u32> BigIntImpl<N_BITS, LIMB_SIZE> {
    /// Double a BigInt
    pub fn double(a: u32) -> Script {
        script! {
            { Self::dup_zip(a) }

            { 1 << LIMB_SIZE }

            // A0 + B0
            limb_add_carry OP_TOALTSTACK

            // from     A1      + B1        + carry_0
            //   to     A{N-2}  + B{N-2}    + carry_{N-3}
            for _ in 0..Self::N_LIMBS - 2 {
                OP_ROT
                OP_ADD
                OP_SWAP
                limb_add_carry OP_TOALTSTACK
            }

            // A{N-1} + B{N-1} + carry_{N-2}
            OP_NIP
            OP_ADD
            { limb_add_nocarry(Self::HEAD_OFFSET) }

            for _ in 0..Self::N_LIMBS - 1 {
                OP_FROMALTSTACK
            }
        }
    }

    /// Compute the sum of two BigInts
    pub fn add(a: u32, b: u32) -> Script {
        script! {
            { Self::zip(a, b) }

            { 1 << LIMB_SIZE }

            // A0 + B0
            limb_add_carry OP_TOALTSTACK

            // from     A1      + B1        + carry_0
            //   to     A{N-2}  + B{N-2}    + carry_{N-3}
            for _ in 0..Self::N_LIMBS - 2 {
                OP_ROT
                OP_ADD
                OP_SWAP
                limb_add_carry OP_TOALTSTACK
            }

            // A{N-1} + B{N-1} + carry_{N-2}
            OP_NIP
            OP_ADD
            { limb_add_nocarry(Self::HEAD_OFFSET) }

            for _ in 0..Self::N_LIMBS - 1 {
                OP_FROMALTSTACK
            }
        }
    }

    pub fn add1() -> Script {
        script! {
            1
            { 1 << LIMB_SIZE }

            // A0 + 1
            limb_add_carry OP_TOALTSTACK

            // from     A1        + carry_0
            //   to     A{N-2}    + carry_{N-3}
            for _ in 0..Self::N_LIMBS - 2 {
                OP_SWAP
                limb_add_carry OP_TOALTSTACK
            }

            // A{N-1} + carry_{N-2}
            OP_NIP
            { limb_add_nocarry(Self::HEAD_OFFSET) }

            for _ in 0..Self::N_LIMBS - 1 {
                OP_FROMALTSTACK
            }
        }
    }

    /// Double the BigInt on top of the stack
    /// 
    /// # Note
    ///
    /// This function allows overflow of the underlying integer types during
    /// doubling operation.
    pub fn double_allow_overflow() -> Script {
        script! {
            { 1 << LIMB_SIZE }

            // Double the limb, take the result to the alt stack, and add initial carry
            OP_SWAP limb_double_without_carry OP_TOALTSTACK


            for _ in 0..Self::N_LIMBS - 2 {
                OP_ROT limb_double_with_carry OP_TOALTSTACK
            }

            // When we got {limb} {base} {carry} on the stack, we drop the base
            OP_NIP // {limb} {carry}
            OP_SWAP { limb_double_with_carry_allow_overflow(Self::HEAD_OFFSET) }

            // Take all limbs from the alt stack to the main stack
            for _ in 0..Self::N_LIMBS - 1 {
                OP_FROMALTSTACK
            }
        }
    }

    pub fn double_allow_overflow_keep_element(n: u32) -> Script {
        script! {
            // OP_DEPTH OP_1SUB OP_PICK
            { 1 << LIMB_SIZE }

            // Double the limb, take the result to the alt stack, and add initial carry
            { n + 1 } OP_PICK limb_double_without_carry OP_TOALTSTACK

            for i in 0..Self::N_LIMBS - 2 {
                { n + i +  3 } OP_PICK limb_double_with_carry OP_TOALTSTACK
            }

            // When we got {limb} {base} {carry} on the stack, we drop the base
            OP_NIP // {limb} {carry}
            { n + 9 } OP_PICK { limb_double_with_carry_allow_overflow(Self::HEAD_OFFSET) } 

            // Take all limbs from the alt stack to the main stack
            for _ in 0..Self::N_LIMBS - 1 {
                OP_FROMALTSTACK
            }
        }
    }

    /// Double the BigInt on top of the stack
    /// 
    /// # Note
    ///
    /// This function prevents overflow of the underlying integer types during
    /// doubling operation.
    pub fn double_prevent_overflow() -> Script {
        script! {
            { 1 << LIMB_SIZE }

            // Double the limb, take the result to the alt stack, and add initial carry
            OP_SWAP limb_double_without_carry OP_TOALTSTACK


            for _ in 0..Self::N_LIMBS - 2 {
                OP_ROT limb_double_with_carry OP_TOALTSTACK
            }

            // When we got {limb} {base} {carry} on the stack, we drop the base
            OP_NIP // {limb} {carry}
            { limb_double_with_carry_prevent_overflow(Self::HEAD_OFFSET) }

            // Take all limbs from the alt stack to the main stack
            for _ in 0..Self::N_LIMBS - 1 {
                OP_FROMALTSTACK
            }
        }
    }

    /// Left shift the BigInt on top of the stack by `bits`
    /// 
    /// # Note
    ///
    /// This function prevents overflow of the underlying integer types during
    /// left shift operation.
    pub fn lshift_prevent_overflow(bits: u32) -> Script {
        script! {
            // stack: {limb}
            { 1 << LIMB_SIZE } // {limb} {base}

            { limb_lshift_without_carry(bits) } // {limb} {carry..} {base}

            for _ in 0..Self::N_LIMBS - 2 {
                { limb_lshift_with_carry(bits) } // {limb} {carry..} {base}
            }
            // When we got {limb} {base} {carry} on the stack, we drop the base
            OP_DROP // {limb} {carry..}
            { limb_lshift_with_carry_prevent_overflow(bits, Self::HEAD) }

            // Take all limbs from the alt stack to the main stack
            for _ in 1..Self::N_LIMBS {
                OP_FROMALTSTACK
            }
        }
    }

    pub fn add_ref_with_top(b: u32) -> Script {
        let b_depth = b * Self::N_LIMBS;
        assert_ne!(b, 0);
        script! {
            { b_depth } OP_PICK
            OP_OVER
            OP_ADD

            // OP_DEPTH OP_1SUB OP_PICK 
            { 1 << LIMB_SIZE }
            OP_SWAP

            { limb_add_create_carry() } 
            OP_TOALTSTACK

            for i in 0..Self::N_LIMBS - 2 {
                { i + 3 } OP_PICK
                OP_ADD
                { b_depth + i + 3 } OP_PICK
                OP_ADD { limb_add_create_carry() } OP_TOALTSTACK
            }

            OP_NIP
            { b_depth + Self::N_LIMBS } OP_PICK
            { Self::N_LIMBS + 1 } OP_PICK
            OP_ROT
            { limb_add_with_carry_prevent_overflow(Self::HEAD_OFFSET) }

            for _ in 0..Self::N_LIMBS - 1 {
                OP_FROMALTSTACK
            }
        }
    }


    
    /// Add BigInt on top of the stack to a BigInt at `b` depth in the stack
    ///
    /// # Note
    ///
    /// This function consumes the BigInt on top of the stack while not consuming
    /// the referenced BigInt
    pub fn add_ref(b: u32) -> Script {
        let b_depth = b * Self::N_LIMBS;
        assert_ne!(b, 0);
        script! {
            { b_depth } OP_PICK
            OP_ADD

            // OP_DEPTH OP_1SUB OP_PICK 
            { 1 << LIMB_SIZE }
            OP_SWAP

            { limb_add_create_carry() } 
            OP_TOALTSTACK

            for _ in 0..Self::N_LIMBS - 2 {
                OP_ROT
                { b_depth + 2 } OP_PICK
                OP_ADD
                OP_ADD { limb_add_create_carry() } OP_TOALTSTACK
            }

            OP_NIP
            { b_depth + 1 } OP_PICK
            OP_ROT
            { limb_add_with_carry_prevent_overflow(Self::HEAD_OFFSET) }

            for _ in 0..Self::N_LIMBS - 1 {
                OP_FROMALTSTACK
            }
        }
    }

    /// Add BigInt referenced by the integer (depth) on top of the stack to the BigInt at
    /// the top the stack below the depth
    ///
    /// # Note
    ///
    /// This function consumes the BigInt on top of the stack below the depth while not
    /// consuming the referenced BigInt
    /// This does not support addition to self, depth=0
    pub fn add_ref_stack() -> Script {
        script! {
            { NMUL(Self::N_LIMBS) }
            { Self::_add_ref_inner() }
        }
    }

    // Underlying add_ref implementation used by both `add_ref` and `add_ref_stack`
    // functions. The commented section is supposed to handle depth=0, which fails.
    // This adds to the script size, henced we assume that the caller ensures that
    // the depth > 0
    fn _add_ref_inner() -> Script {
        script! {
            // OP_DUP OP_NOT OP_NOT OP_VERIFY // fail on {0} stack
            // OP_DUP OP_NOT
            // OP_IF
            //     OP_DROP
            //     { Self::topadd_new(0) }
            // OP_ELSE
                3 OP_ADD
                { 1 << LIMB_SIZE }
                for i in 0..Self::N_LIMBS-1 {
                    if i == 0 {
                        OP_OVER OP_1SUB
                        OP_PICK
                    } else {
                        2 OP_PICK
                        OP_PICK
                        OP_ADD
                    }
                    3 OP_ROLL
                    OP_ADD
                    OP_2DUP
                    OP_LESSTHANOREQUAL
                    OP_TUCK
                    OP_IF 2 OP_PICK OP_SUB OP_ENDIF
                    OP_TOALTSTACK
                }
                OP_NIP OP_SWAP
                2 OP_SUB OP_PICK

                OP_SWAP { limb_add_with_carry_prevent_overflow(Self::HEAD_OFFSET) }

                for _ in 0..Self::N_LIMBS-1 {
                    OP_FROMALTSTACK
                }
            // OP_ENDIF
        }
    }
}

pub fn limb_add_create_carry() -> Script {
    script! {
        OP_2DUP
        OP_LESSTHANOREQUAL
        OP_TUCK
        OP_IF
            2 OP_PICK OP_SUB
        OP_ENDIF
    }
}

/// Compute the sum of two limbs, including the carry bit
///
/// Optimized by: @stillsaiko
pub fn limb_add_carry() -> Script {
    script! {
        OP_ROT OP_ROT
        OP_ADD OP_2DUP
        OP_LESSTHANOREQUAL
        OP_TUCK
        OP_IF
            2 OP_PICK OP_SUB
        OP_ENDIF
    }
}

/// Compute the sum of two limbs, dropping the carry bit
///
/// Optimized by: @wz14
pub fn limb_add_nocarry(head_offset: u32) -> Script {
    script! {
        OP_ADD { head_offset } OP_2DUP
        OP_GREATERTHANOREQUAL
        OP_IF
            OP_SUB
        OP_ELSE
            OP_DROP
        OP_ENDIF
    }
}

fn limb_add_with_carry_prevent_overflow(head_offset: u32) -> Script {
    script!{
        // {a} {b} {c:carry}
        OP_3DUP OP_ADD OP_ADD OP_NIP                         // {a} {b} {a+b+c}
        { head_offset >> 1 }                                 // {a} {b} {a+b+c} {x}
        OP_TUCK OP_DUP OP_ADD                                // {a} {b} {x} {a+b+c} {2x}
        OP_2DUP                                              // {a} {b} {x} {a+b+c} {2x} {a+b+c} {2x}
        OP_GREATERTHANOREQUAL                                // {a} {b} {x} {a+b+c} {2x} {L:0/1}
        OP_NOTIF OP_NOT OP_ENDIF                             // {a} {b} {x} {a+b+c} {0/2x}
        OP_SUB                                               // {a} {b} {x} {a+b+c_nlo}
        OP_SWAP                                              // {a} {b} {a+b+c_nlo} {x}
        OP_2DUP                                              // {a} {b} {a+b+c_nlo} {x} {a+b+c_nlo} {x}
        OP_2ROT                                              // {a+b+c_nlo} {x} {a+b+c_nlo} {x} {a} {b}
        2 OP_PICK                                            // {a+b+c_nlo} {x} {a+b+c_nlo} {x} {a} {b} {x}
        OP_LESSTHAN                                          // {a+b+c_nlo} {x} {a+b+c_nlo} {x} {a} {sign_b}
        OP_2SWAP                                             // {a+b+c_nlo} {x} {a} {sign_b} {a+b+c_nlo} {x}
        OP_GREATERTHANOREQUAL                                // {a+b+c_nlo} {x} {a} {sign_b} {I:0/1}
        OP_2SWAP                                             // {a+b+c_nlo} {sign_b} {I:0/1} {x} {a}
        OP_GREATERTHANOREQUAL                                // {a+b+c_nlo} {sign_b} {I:0/1} {sign_a}
        OP_ADD OP_ADD 1 3 OP_WITHIN OP_VERIFY                // verify (sign_a, sign_b, I) is not (0, 0, 0) or (1, 1, 1) which would mean overflow
    }
}

fn limb_double_without_carry() -> Script {
    script! {
        // {base} {limb}
        { NMUL(2) } // {base} {2*limb}
        OP_2DUP // {base} {2*limb} {base} {2*limb}
        OP_LESSTHANOREQUAL // {base} {2*limb} {base<=2*limb}
        OP_TUCK // {base} {base<=2*limb} {2*limb} {base<=2*limb}
        OP_IF
            2 OP_PICK OP_SUB
        OP_ENDIF
    }
}

fn limb_double_with_carry() -> Script {
    script! {
        // {base} {carry} {limb}
        { NMUL(2) } // {base} {carry} {2*limb}
        OP_ADD // {base} {2*limb + carry}
        OP_2DUP // {base} {2*limb + carry} {base} {2*limb + carry}
        OP_LESSTHANOREQUAL // {base} {2*limb + carry} {base<=2*limb + carry}
        OP_TUCK // {base} {base<=2*limb+carry} {2*limb+carry} {base<=2*limb+carry}
        OP_IF
            2 OP_PICK OP_SUB
        OP_ENDIF
    }
}

fn limb_double_with_carry_allow_overflow(head_offset: u32) -> Script {
    script! {
        // {carry} {limb}
        { NMUL(2) } // {carry} {2*limb}
        OP_ADD // {carry + 2*limb}
        { head_offset } OP_2DUP
        OP_GREATERTHANOREQUAL
        OP_IF
            OP_SUB
        OP_ELSE
            OP_DROP
        OP_ENDIF
    }
}

fn limb_double_with_carry_prevent_overflow(head_offset: u32) -> Script {
    script! {
        // {a} {c:carry}
        OP_OVER                                          // {a} {c} {a}
        OP_DUP OP_ADD OP_ADD                             // {a} {2a+c}
        { head_offset >> 1 }                             // {a} {2a+c} {x}
        OP_TUCK OP_DUP OP_ADD                            // {a} {x} {2a+c} {2x}
        OP_2DUP OP_GREATERTHANOREQUAL                    // {a} {x} {2a+c} {2x} {L:0/1}
        OP_NOTIF OP_NOT OP_ENDIF OP_SUB                  // {a} {x} {2a+c_nlo}
        OP_2DUP OP_LESSTHAN                              // {a} {x} {2a+c_nlo} {I:0/1}
        OP_2SWAP                                         // {2a+c_nlo} {I:0/1} {a} {x}
        OP_LESSTHAN                                      // {2a+c_nlo} {I:0/1} {sign_a}

        OP_NUMNOTEQUAL OP_VERIFY                         // sign_a must be different than I
    }
}

fn limb_lshift_without_carry(bits: u32) -> Script {
    script! {
        OP_SWAP                  // {base} {limb}
        for i in 1..=bits {
            { NMUL(2) }          // {base} {2*limb}
            OP_2DUP              // {base} {2*limb} {base} {2*limb}
            OP_LESSTHANOREQUAL   // {base} {2*limb} {carry:base<=2*limb}
            OP_TUCK              // {base} {carry} {2*limb} {carry}
            OP_IF                // {base} {carry} {2*limb}
                2 OP_PICK OP_SUB // {base} {carry} {2*limb-base}
            OP_ENDIF
            if i < bits { OP_ROT OP_SWAP } // {carry...} {base} {2*limb-base}
            else { OP_TOALTSTACK OP_SWAP } // {carry...} {base} -> {2*limb-base}
        }
    }
}

fn limb_lshift_with_carry(bits: u32) -> Script {
    script! {
        // {limb} {p_carry..} {base}
        { 1 + bits } OP_ROLL     // {p_carry..} {base} {limb}
        for i in 1..=bits {
            { NMUL(2) }                     // {p_carry..} {base} {2*limb}
            { 1 + bits } OP_ROLL OP_ADD     // {p_carry..} {base} {2*limb+c0}
            OP_2DUP                         // {p_carry..} {base} {2*limb+c0} {base} {2*limb+c0}
            OP_LESSTHANOREQUAL              // {p_carry..} {base} {2*limb+c0} {carry:base<=2*limb+c0}
            OP_TUCK                         // {p_carry..} {base} {carry} {2*limb+c0} {carry}
            OP_IF                           // {p_carry..} {base} {carry} {2*limb+c0}
                2 OP_PICK OP_SUB            // {p_carry..} {base} {carry} {2*limb+c0-base}
            OP_ENDIF
            if i < bits { OP_ROT OP_SWAP } // {p_carry..} {carry..} {base} {2*limb-base}
            else { OP_TOALTSTACK OP_SWAP } // {carry..} {base} -> {2*limb-base}
        }
    }
}

fn limb_lshift_with_carry_prevent_overflow(bits: u32, head: u32) -> Script {
    script! {
        // {a} {c..}
        { bits } OP_ROLL                                     // {c..} {a}
        { 1 << (head - 1) }                                  // {c..} {a} {x}
        OP_DUP OP_TOALTSTACK                                 // {c..} {a} {x} | {x}
        OP_2DUP OP_LESSTHAN                                  // {c..} {a} {x} {sign_a} | {x}
        OP_IF OP_NOT OP_ENDIF                                // {c..} {a} {0/x} | {x}
        OP_DUP OP_ADD OP_SUB                                 // {c..} {a/a-2x} | {x}

        for i in 0..bits {
            { NMUL(2) }
            if i < bits - 1 {
                { bits - i } OP_ROLL
            }
            OP_ADD
        }                                                    // {result_signed} | {x}
        
        OP_FROMALTSTACK                                      // {result_signed} {x}
        OP_OVER                                              // {result_signed} {x} {result_signed}
        OP_2DUP OP_SWAP                                      // {result_signed} {x} {result_signed} {result_signed} {x}
        OP_DUP OP_NEGATE OP_SWAP                             // {result_signed} {x} {result_signed} {result_signed} {-x} {x}
        OP_WITHIN OP_VERIFY                                  // {result_signed} {x} {result_signed}
        0 OP_GREATERTHANOREQUAL                              // {result_signed} {x} {sign_result}
        OP_IF OP_NOT OP_ENDIF                                // {result_signed} {0/x}
        OP_DUP OP_ADD OP_ADD                                 // {result}
    }
}

#[cfg(test)]
mod test {
    use crate::bigint::{U254, U64};
    use crate::treepp::*;
    use core::ops::{Add, Rem, Shl};
    use num_bigint::{BigUint, RandomBits};
    use num_traits::One;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_add() {
        println!("U254.add: {} bytes", U254::add(1, 0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        for _ in 0..100 {
            let a: BigUint = prng.sample(RandomBits::new(254));
            let b: BigUint = prng.sample(RandomBits::new(254));
            let c: BigUint = (a.clone() + b.clone()).rem(BigUint::one().shl(254));

            let script = script! {
                { U254::push_u32_le(&a.to_u32_digits()) }
                { U254::push_u32_le(&b.to_u32_digits()) }
                { U254::add(1, 0) }
                { U254::push_u32_le(&c.to_u32_digits()) }
                { U254::equalverify(1, 0) }
                OP_TRUE
            };
            run(script);
        }

        for _ in 0..100 {
            let a: u64 = prng.gen();
            let b: u64 = prng.gen();
            let c = a.wrapping_add(b);

            let script = script! {
                { U64::push_u64_le(&[a]) }
                { U64::push_u64_le(&[b]) }
                { U64::add(1, 0) }
                { U64::push_u64_le(&[c]) }
                { U64::equalverify(1, 0) }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_double() {
        println!("U254.double: {} bytes", U254::double(0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        for _ in 0..100 {
            let a: BigUint = prng.sample(RandomBits::new(254));
            let c: BigUint = (a.clone() + a.clone()).rem(BigUint::one().shl(254));

            let script = script! {
                { U254::push_u32_le(&a.to_u32_digits()) }
                { U254::double(0) }
                { U254::push_u32_le(&c.to_u32_digits()) }
                { U254::equalverify(1, 0) }
                OP_TRUE
            };
            run(script);
        }

        for _ in 0..100 {
            let a: u64 = prng.gen();
            let c = a.wrapping_add(a);

            let script = script! {
                { U64::push_u64_le(&[a]) }
                { U64::double(0) }
                { U64::push_u64_le(&[c]) }
                { U64::equalverify(1, 0) }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_1add() {
        println!("U254.add1: {} bytes", U254::add1().len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        for _ in 0..100 {
            let a: BigUint = prng.sample(RandomBits::new(254));
            let c: BigUint = (a.clone().add(BigUint::one())).rem(BigUint::one().shl(254));

            let script = script! {
                { U254::push_u32_le(&a.to_u32_digits()) }
                { U254::add1() }
                { U254::push_u32_le(&c.to_u32_digits()) }
                { U254::equalverify(1, 0) }
                OP_TRUE
            };
            run(script);
        }

        for _ in 0..100 {
            let a: u64 = prng.gen();
            let c = a.wrapping_add(1u64);

            let script = script! {
                { U64::push_u64_le(&[a]) }
                { U64::add1() }
                { U64::push_u64_le(&[c]) }
                { U64::equalverify(1, 0) }
                OP_TRUE
            };
            run(script);
        }
    }
}
