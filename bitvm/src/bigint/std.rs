use bitcoin::script::read_scriptint;
use num_bigint::BigUint;
use num_traits::Num;
use std::str::FromStr;
use std::cmp::Ordering;

use crate::bigint::BigIntImpl;
use crate::pseudo::{push_to_stack, NMUL};
use crate::treepp::*;

/// Struct to store the information of each step in `transform_limbsize` function.
#[derive(Debug)]
struct TransformStep {
    current_limb_index: u32,
    extract_window: u32,
    drop_currentlimb: bool,
    initiate_targetlimb: bool,
}

impl<const N_BITS: u32, const LIMB_SIZE: u32> BigIntImpl<N_BITS, LIMB_SIZE> {
    pub fn push_u32_le(v: &[u32]) -> Script {
        let mut bits = vec![];
        for elem in v.iter() {
            for i in 0..32 {
                bits.push((elem & (1 << i)) != 0);
            }
        }
        bits.resize(N_BITS as usize, false);

        let mut limbs = vec![];
        for chunk in bits.chunks(LIMB_SIZE as usize) {
            let mut chunk_vec = chunk.to_vec();
            chunk_vec.resize(LIMB_SIZE as usize, false);

            let mut elem = 0u32;
            for (i, chunk_i) in chunk_vec.iter().enumerate() {
                if *chunk_i {
                    elem += 1 << i;
                }
            }

            limbs.push(elem);
        }

        limbs.reverse();

        script! {
            for limb in &limbs {
                { *limb }
            }
            { push_to_stack(0,Self::N_LIMBS as usize - limbs.len()) }
        }
    }

    pub fn read_u32_le(mut witness: Vec<Vec<u8>>) -> Vec<u32> {
        assert_eq!(witness.len() as u32, Self::N_LIMBS);

        witness.reverse();

        let mut bits: Vec<bool> = vec![];
        for element in witness.iter() {
            let limb = read_scriptint(element).unwrap();
            for i in 0..LIMB_SIZE {
                bits.push((limb & (1 << i)) != 0);
            }
        }

        bits.resize(N_BITS as usize, false);

        let mut u32s = vec![];

        for chunk in bits.chunks(32) {
            let mut chunk_vec = chunk.to_vec();
            chunk_vec.resize(32, false);

            let mut elem = 0u32;
            for i in 0..32 as usize {
                if chunk_vec[i] {
                    elem += 1 << i;
                }
            }

            u32s.push(elem);
        }

        u32s
    }

    pub fn push_u64_le(v: &[u64]) -> Script {
        let v = v
            .iter()
            .flat_map(|v| {
                [
                    (v & 0xffffffffu64) as u32,
                    ((v >> 32) & 0xffffffffu64) as u32,
                ]
            })
            .collect::<Vec<u32>>();

        Self::push_u32_le(&v)
    }

    /// Zip the top two u{16N} elements
    /// input:  a0 ... a{N-1} b0 ... b{N-1}
    /// output: a0 b0 ... ... a{N-1} b{N-1}
    pub fn zip(mut a: u32, mut b: u32) -> Script {
        a = (a + 1) * Self::N_LIMBS - 1;
        b = (b + 1) * Self::N_LIMBS - 1;

        assert_ne!(a, b);
        if a < b {
            script! {
                for i in 0..Self::N_LIMBS {
                    { a + i }
                    OP_ROLL
                    { b }
                    OP_ROLL
                }
            }
        } else {
            script! {
                for i in 0..Self::N_LIMBS {
                    { a }
                    OP_ROLL
                    { b + i + 1 }
                    OP_ROLL
                }
            }
        }
    }

    pub fn copy_zip(mut a: u32, mut b: u32) -> Script {
        a = (a + 1) * Self::N_LIMBS - 1;
        b = (b + 1) * Self::N_LIMBS - 1;

        script! {
            for i in 0..Self::N_LIMBS {
                { a + i } OP_PICK { b + 1 + i } OP_PICK
            }
        }
    }

    pub fn dup_zip(mut a: u32) -> Script {
        a = (a + 1) * Self::N_LIMBS - 1;

        script! {
            for i in 0..Self::N_LIMBS {
                { a + i } OP_ROLL OP_DUP
            }
        }
    }

    pub fn copy(mut a: u32) -> Script {
        a = (a + 1) * Self::N_LIMBS - 1;

        script! {
            if a < 134 {
                for _ in 0..Self::N_LIMBS {
                    { a } OP_PICK
                }
            } else {
                { a + 1 }
                for _ in 0..Self::N_LIMBS - 1 {
                    OP_DUP OP_PICK OP_SWAP
                }
                OP_1SUB OP_PICK
            }
        }
        .add_stack_hint(-(Self::N_LIMBS as i32), Self::N_LIMBS as i32)
    }

    pub fn roll(mut a: u32) -> Script {
        if a == 0 {
            return script! {};
        }
        a = (a + 1) * Self::N_LIMBS - 1;

        script! {
            for _ in 0..Self::N_LIMBS {
                { a } OP_ROLL
            }
        }
    }

    pub fn drop() -> Script {
        script! {
            for _ in 0..Self::N_LIMBS / 2 {
                OP_2DROP
            }
            if Self::N_LIMBS & 1 == 1 {
                OP_DROP
            }
        }
    }

    pub fn push_dec(dec_string: &str) -> Script {
        Self::push_u32_le(&BigUint::from_str(dec_string).unwrap().to_u32_digits())
    }

    pub fn push_hex(hex_string: &str) -> Script {
        Self::push_u32_le(
            &BigUint::from_str_radix(hex_string, 16)
                .unwrap()
                .to_u32_digits(),
        )
    }

    #[inline]
    pub fn push_zero() -> Script {
        push_to_stack(0, Self::N_LIMBS as usize)
    }

    #[inline]
    pub fn push_one() -> Script {
        script! {
            { push_to_stack(0,(Self::N_LIMBS - 1) as usize) }
            1
        }
    }

    pub fn is_zero_keep_element(a: u32) -> Script {
        let a = Self::N_LIMBS * a;
        script! {
            1
            for i in 0..Self::N_LIMBS {
                { a + i+1 } OP_PICK
                OP_NOT
                OP_BOOLAND
            }
        }
    }

    pub fn is_zero(a: u32) -> Script {
        let a = Self::N_LIMBS * a;
        script! {
            1
            for _ in 0..Self::N_LIMBS {
                { a +1 } OP_ROLL
                OP_NOT
                OP_BOOLAND
            }
        }
    }

    pub fn is_one_keep_element(a: u32) -> Script {
        let a = Self::N_LIMBS * a;
        script! {
            1
            { a + 1 } OP_PICK
            1 OP_EQUAL OP_BOOLAND
            for i in 1..Self::N_LIMBS {
                { a + i + 1 } OP_PICK
                OP_NOT
                OP_BOOLAND
            }
        }
    }

    pub fn is_one(a: u32) -> Script {
        let a = Self::N_LIMBS * a;
        script! {
            1
            { a + 1 } OP_ROLL
            1 OP_EQUAL OP_BOOLAND
            for _ in 1..Self::N_LIMBS {
                { a + 1 } OP_ROLL
                OP_NOT
                OP_BOOLAND
            }
        }
    }

    pub fn toaltstack() -> Script {
        script! {
            for _ in 0..Self::N_LIMBS {
                OP_TOALTSTACK
            }
        }
    }

    pub fn fromaltstack() -> Script {
        script! {
            for _ in 0..Self::N_LIMBS {
                OP_FROMALTSTACK
            }
        }
    }

    pub fn is_negative(depth: u32) -> Script {
        script! {
            { (1 + depth) * Self::N_LIMBS - 1 } OP_PICK
            { Self::HEAD_OFFSET >> 1 }
            OP_GREATERTHANOREQUAL
        }
    }

    pub fn is_positive(depth: u32) -> Script {
        script! {
            { Self::is_zero_keep_element(depth) } OP_NOT
            { (1 + depth) * Self::N_LIMBS } OP_PICK
            { Self::HEAD_OFFSET >> 1 }
            OP_LESSTHAN OP_BOOLAND
        }
    }

    /// Resize positive numbers
    ///
    /// # Note
    ///
    /// Does not work for negative numbers
    pub fn resize<const T_BITS: u32>() -> Script {
        let n_limbs_self = N_BITS.div_ceil(LIMB_SIZE);
        let n_limbs_target = T_BITS.div_ceil(LIMB_SIZE);

        match n_limbs_target.cmp(&n_limbs_self) {
            Ordering::Equal => script! {},
            Ordering::Greater => {
                let n_limbs_to_add = n_limbs_target - n_limbs_self;
                script! {
                    if n_limbs_to_add > 0 {
                        {0} {crate::pseudo::OP_NDUP((n_limbs_to_add - 1) as usize)} // Pushing zeros to the stack
                    }
                    for _ in 0..n_limbs_self {
                        { n_limbs_target - 1 } OP_ROLL
                    }
                }
            },
            Ordering::Less => {
                let n_limbs_to_remove = n_limbs_self - n_limbs_target;
                script! {
                    for _ in 0..n_limbs_to_remove {
                        { n_limbs_target } OP_ROLL OP_DROP
                    }
                }
            }
        }
    }

    /// Doesn't do input validation
    /// All the bits before start_index must be 0 for the extract to work properly
    /// doesnot work when start_index is 32
    /// Properties to test for Property based testing:
    /// - if window == start_index, the entire thing should be copied.
    ///
    ///
    pub fn extract_digits(start_index: u32, window: u32) -> Script {
        // doesnot work if start_index is 32
        assert!(start_index != 32, "start_index mustn't be 32");

        //panics if the window exceeds the number of bits on the left of start_index
        assert!(
            start_index >= window,
            "not enough bits left of start_index to fill the window!"
        );

        script! {
            0
            OP_SWAP
            for i in 0..window {
                OP_TUCK
                { 1 << (start_index - i - 1) }
                OP_GREATERTHANOREQUAL
                OP_TUCK
                OP_ADD
                if i < window - 1 { { NMUL(2) } }
                OP_ROT OP_ROT
                OP_IF
                    { 1 << (start_index - i - 1) }
                    OP_SUB
                OP_ENDIF
            }
        }
    }

    /// Generates a vector of TransformStep struct that encodes all the information needed to
    /// convert BigInt form one limbsize represention (source) to another (target).
    /// used as a helper function for `transform_limbsize`

    fn get_trasform_steps(source_limb_size: u32, target_limb_size: u32) -> Vec<TransformStep> {

        //define an empty vector to store Transform steps
        let mut transform_steps: Vec<TransformStep> = Vec::new();

        // compute the number of limbs for target and source
        let target_n_limbs = N_BITS.div_ceil(target_limb_size);
        let mut target_limb_remaining_bits = Self::N_BITS - (target_n_limbs - 1) * target_limb_size;
        let source_n_limbs = N_BITS.div_ceil(source_limb_size);
        let source_head = Self::N_BITS - (source_n_limbs - 1) * source_limb_size;

        // define a vector of limbsizes of source
        let mut limb_sizes: Vec<u32> = Vec::new();
        let mut first_iter_flag = true;
        limb_sizes.push(source_head);
        for _ in 0..(source_n_limbs - 1) {
            limb_sizes.push(source_limb_size);
        }

        //iterate until all limbs of source are processed
        while limb_sizes.len() > 0 {
            //iterate until the target limb is filled completely
            while target_limb_remaining_bits > 0 {
                let source_limb_remaining_bits = limb_sizes.get(0).unwrap();

                match source_limb_remaining_bits.cmp(&target_limb_remaining_bits) {
                    Ordering::Less => {
                        transform_steps.push(TransformStep {
                            current_limb_index: source_limb_remaining_bits.clone(),
                            extract_window: source_limb_remaining_bits.clone(),
                            drop_currentlimb: true,
                            initiate_targetlimb: first_iter_flag,
                        });
                        target_limb_remaining_bits -= source_limb_remaining_bits.clone();
                        limb_sizes.remove(0);
                    }
                    Ordering::Equal => {
                        transform_steps.push(TransformStep {
                            current_limb_index: source_limb_remaining_bits.clone(),
                            extract_window: target_limb_remaining_bits,
                            drop_currentlimb: true,
                            initiate_targetlimb: first_iter_flag,
                        });
                        target_limb_remaining_bits = 0;
                        limb_sizes.remove(0);
                    }
                    Ordering::Greater => {
                        transform_steps.push(TransformStep {
                            current_limb_index: source_limb_remaining_bits.clone(),
                            extract_window: target_limb_remaining_bits,
                            drop_currentlimb: false,
                            initiate_targetlimb: first_iter_flag,
                        });
                        limb_sizes[0] = source_limb_remaining_bits - target_limb_remaining_bits;
                        target_limb_remaining_bits = 0;
                    }
                }
                first_iter_flag = false;
            }
            target_limb_remaining_bits = target_limb_size;
            first_iter_flag = true;
        }
        transform_steps
    }

    /// Transform Limbsize for BigInt
    /// This function changes the representation of BigInt present on stack as multiple limbs of source limbsize to 
    /// any another limbsize within 1 and 31 (inclusive). 
    /// Specifically, This can be used to transform limbs into nibbles, limbs into bits ans vice-versa to aid optimizetions.
    /// 
    /// ## Assumptions:
    /// - Does NOT do input validation.
    /// - The message is placed such that LSB is on top of stack. (MSB pushed first)
    ///
    /// ## Stack Effects:
    /// The original BigInt which that was in stack is dropped
    /// The same BigInt with target_limbsize is left on stack
    ///  
    /// ## Panics:
    /// - If the source or target limb size lies outside of 0 to 31 (inclusive), fails with assertion error.
    /// - If the source or target limb size is greater than number of bits, fails with assertion error
    pub fn transform_limbsize(source_limb_size: u32, target_limb_size: u32) -> Script {
        // ensure that source and target limb sizes are between 0 and 31 inclusive
        assert!(
            source_limb_size < 32 && source_limb_size > 0,
            "source limb size must lie between 0 and 31 inclusive"
        );
        assert!(
            target_limb_size < 32 && source_limb_size > 0,
            "target limb size must lie between 0 and 31 inclusive"
        );

        //ensure that source and target limb size aren't greater than N_BITS
        assert!(
            source_limb_size <= Self::N_BITS,
            "source limb size mustn't be greater than number of bits in bigInt"
        );
        assert!(
            target_limb_size <= Self::N_BITS,
            "target limb size mustn't be greater than number of bits in bigInt"
        );

        // if both source and target limb size are same, do nothing
        if source_limb_size == target_limb_size {
            script!()
        } else {
            let steps = Self::get_trasform_steps(source_limb_size, target_limb_size);

            let source_n_limbs = N_BITS.div_ceil(source_limb_size);
            script!(
            // send all limbs except the first to alt stack so that the MSB is handled first
            for _ in 0..(source_n_limbs - 1){OP_TOALTSTACK}

            for step in steps{
                    {Self::extract_digits(step.current_limb_index, step.extract_window)}

                    if !step.initiate_targetlimb{
                        OP_ROT
                        for _ in 0..step.extract_window {OP_DUP OP_ADD} //left shift by extract window
                        OP_ROT
                        OP_ADD
                        OP_SWAP
                    }

                    if step.drop_currentlimb{
                        OP_DROP
                        OP_FROMALTSTACK
                    }
                }
            )
        }
    }
}

#[cfg(test)]
mod test {
    use crate::bigint::{BigIntImpl, U254};
    use crate::run;
    
    use bitcoin_script::script;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_zip() {
        const N_BITS: u32 = 1450;
        const N_U30_LIMBS: u32 = 50;

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let mut v = vec![];
            for _ in 0..N_U30_LIMBS {
                v.push(prng.gen::<i32>());
            }
            for _ in 0..N_U30_LIMBS {
                v.push(prng.gen::<i32>());
            }

            let mut expected = vec![];
            for i in 0..N_U30_LIMBS {
                expected.push(v[i as usize]);
                expected.push(v[(N_U30_LIMBS + i) as usize]);
            }

            let script = script! {
                for i in 0..N_U30_LIMBS * 2 {
                    { v[i as usize] }
                }
                { BigIntImpl::<N_BITS, 29>::zip(1, 0) }
                for i in 0..N_U30_LIMBS * 2 {
                    { expected[(N_U30_LIMBS * 2 - 1 - i) as usize] }
                    OP_EQUALVERIFY
                }
                OP_TRUE
            };
            run(script);
        }

        for _ in 0..50 {
            let mut v = vec![];
            for _ in 0..N_U30_LIMBS {
                v.push(prng.gen::<i32>());
            }
            for _ in 0..N_U30_LIMBS {
                v.push(prng.gen::<i32>());
            }

            let mut expected = vec![];
            for i in 0..N_U30_LIMBS {
                expected.push(v[(N_U30_LIMBS + i) as usize]);
                expected.push(v[i as usize]);
            }

            let script = script! {
                for i in 0..N_U30_LIMBS * 2 {
                    { v[i as usize] }
                }
                { BigIntImpl::<N_BITS, 29>::zip(0, 1) }
                for i in 0..N_U30_LIMBS * 2 {
                    { expected[(N_U30_LIMBS * 2 - 1 - i) as usize] }
                    OP_EQUALVERIFY
                }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_copy() {
        println!("U254.copy(0): {} bytes", U254::copy(0).len());
        println!("U254.copy(13): {} bytes", U254::copy(13).len());
        println!("U254.copy(14): {} bytes", U254::copy(14).len());
        const N_U30_LIMBS: u32 = 9;

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let mut v = vec![];
            for _ in 0..N_U30_LIMBS {
                v.push(prng.gen::<i32>());
            }
            for _ in 0..N_U30_LIMBS {
                v.push(prng.gen::<i32>());
            }

            let mut expected = vec![];
            for i in 0..N_U30_LIMBS {
                expected.push(v[i as usize]);
            }

            let script = script! {
                for i in 0..N_U30_LIMBS * 2 {
                    { v[i as usize] }
                }
                { U254::copy(1) }
                for i in 0..N_U30_LIMBS {
                    { expected[(N_U30_LIMBS - 1 - i) as usize] }
                    OP_EQUALVERIFY
                }
                { U254::drop() }
                { U254::drop() }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_roll() {
        const N_U30_LIMBS: u32 = 9;

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let mut v = vec![];
            for _ in 0..N_U30_LIMBS {
                v.push(prng.gen::<i32>());
            }
            for _ in 0..N_U30_LIMBS {
                v.push(prng.gen::<i32>());
            }

            let mut expected = vec![];
            for i in 0..N_U30_LIMBS {
                expected.push(v[i as usize]);
            }

            let script = script! {
                for i in 0..N_U30_LIMBS * 2 {
                    { v[i as usize] }
                }
                { U254::roll(1) }
                for i in 0..N_U30_LIMBS {
                    { expected[(N_U30_LIMBS - 1 - i) as usize] }
                    OP_EQUALVERIFY
                }
                { U254::drop() }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_copy_zip() {
        const N_U30_LIMBS: u32 = 9;

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let mut v = vec![];
            for _ in 0..N_U30_LIMBS {
                v.push(prng.gen::<i32>());
            }
            for _ in 0..N_U30_LIMBS {
                v.push(prng.gen::<i32>());
            }

            let mut expected = vec![];
            for i in 0..N_U30_LIMBS {
                expected.push(v[i as usize]);
                expected.push(v[(N_U30_LIMBS + i) as usize]);
            }

            let script = script! {
                for i in 0..N_U30_LIMBS * 2 {
                    { v[i as usize] }
                }
                { U254::copy_zip(1, 0) }
                for i in 0..N_U30_LIMBS * 2 {
                    { expected[(N_U30_LIMBS * 2 - 1 - i) as usize] }
                    OP_EQUALVERIFY
                }
                { U254::drop() }
                { U254::drop() }
                OP_TRUE
            };
            run(script);

            let mut expected = vec![];
            for i in 0..N_U30_LIMBS {
                expected.push(v[(N_U30_LIMBS + i) as usize]);
                expected.push(v[i as usize]);
            }

            let script = script! {
                for i in 0..N_U30_LIMBS * 2 {
                    { v[i as usize] }
                }
                { U254::copy_zip(0, 1) }
                for i in 0..N_U30_LIMBS * 2 {
                    { expected[(N_U30_LIMBS * 2 - 1 - i) as usize] }
                    OP_EQUALVERIFY
                }
                { U254::drop() }
                { U254::drop() }
                OP_TRUE
            };
            run(script);

            let mut expected = vec![];
            for i in 0..N_U30_LIMBS {
                expected.push(v[i as usize]);
                expected.push(v[i as usize]);
            }

            let script = script! {
                for i in 0..N_U30_LIMBS * 2 {
                    { v[i as usize] }
                }
                { U254::copy_zip(1, 1) }
                for i in 0..N_U30_LIMBS * 2 {
                    { expected[(N_U30_LIMBS * 2 - 1 - i) as usize] }
                    OP_EQUALVERIFY
                }
                { U254::drop() }
                { U254::drop() }
                OP_TRUE
            };
            run(script);

            let script = script! {
                for i in 0..N_U30_LIMBS * 2 {
                    { v[i as usize] }
                }
                { U254::dup_zip(1) }
                for i in 0..N_U30_LIMBS * 2 {
                    { expected[(N_U30_LIMBS * 2 - 1 - i) as usize] }
                    OP_EQUALVERIFY
                }
                { U254::drop() }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn push_hex() {
        run(script! {
            { U254::push_hex("30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47") }
            { 0x187cfd47 } OP_EQUALVERIFY // 410844487
            { 0x10460b6 } OP_EQUALVERIFY // 813838427
            { 0x1c72a34f } OP_EQUALVERIFY // 119318739
            { 0x2d522d0 } OP_EQUALVERIFY // 542811226
            { 0x1585d978 } OP_EQUALVERIFY // 22568343
            { 0x2db40c0 } OP_EQUALVERIFY // 18274822
            { 0xa6e141 } OP_EQUALVERIFY // 436378501
            { 0xe5c2634 } OP_EQUALVERIFY // 329037900
            { 0x30644e } OP_EQUAL // 12388
        });
    }
}
