use crate::treepp::*;
use crate::ubigint::UBigIntImpl;

impl<const N_BITS: u32> UBigIntImpl<N_BITS> {
    pub fn push_u32_le(v: &[u32]) -> Script {
        let n_limbs = (N_BITS + 30 - 1) / 30;

        let mut bits = vec![];
        for elem in v.iter() {
            for i in 0..32 {
                bits.push((elem & (1 << i)) != 0);
            }
        }
        bits.resize(N_BITS as usize, false);

        let mut limbs = vec![];
        for chunk in bits.chunks(30) {
            let mut chunk_vec = chunk.to_vec();
            chunk_vec.resize(30, false);

            let mut elem = 0u32;
            for i in 0..30 {
                if chunk_vec[i] {
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
            for _ in 0..(n_limbs - limbs.len() as u32) {
                0
            }
        }
    }

    /// Zip the top two u{16N} elements
    /// input:  a0 ... a{N-1} b0 ... b{N-1}
    /// output: a0 b0 ... ... a{N-1} b{N-1}
    pub fn zip(mut a: u32, mut b: u32) -> Script {
        let n_limbs: u32 = (N_BITS + 30 - 1) / 30;
        a = (a + 1) * n_limbs - 1;
        b = (b + 1) * n_limbs - 1;

        assert_ne!(a, b);
        if a < b {
            script! {
                for i in 0..n_limbs {
                    { a + i }
                    OP_ROLL
                    { b }
                    OP_ROLL
                }
            }
        } else {
            script! {
                for i in 0..n_limbs {
                    { a }
                    OP_ROLL
                    { b + (i as u32) + 1 }
                    OP_ROLL
                }
            }
        }
    }

    pub fn copy(mut a: u32) -> Script {
        let n_limbs: u32 = (N_BITS + 30 - 1) / 30;
        a = (a + 1) * (n_limbs) - 1;

        script! {
            { a + 1 }
            for _ in 0..(n_limbs - 1) {
                OP_DUP OP_PICK OP_SWAP
            }
            OP_1SUB OP_PICK
        }
    }

    pub fn bring(mut a: u32) -> Script {
        let n_limbs: u32 = (N_BITS + 30 - 1) / 30;
        a = (a + 1) * (n_limbs) - 1;

        script! {
            { a + 1 }
            for _ in 0..(n_limbs - 1) {
                OP_DUP OP_ROLL OP_SWAP
            }
            OP_1SUB OP_ROLL
        }
    }

    pub fn drop() -> Script {
        let n_limbs: u32 = (N_BITS + 30 - 1) / 30;

        script! {
            for _ in 0..n_limbs {
                OP_DROP
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::treepp::{execute_script, pushable};
    use crate::ubigint::UBigIntImpl;
    use bitcoin_script::script;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_zip() {
        const N_BITS: u32 = 1500;
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
                for i in 0..(N_U30_LIMBS * 2) {
                    { v[i as usize] }
                }
                { UBigIntImpl::<N_BITS>::zip(1, 0) }
                for i in 0..(N_U30_LIMBS * 2) {
                    { expected[(N_U30_LIMBS * 2 - 1 - i) as usize] }
                    OP_EQUALVERIFY
                }
                OP_PUSHNUM_1
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
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
                { UBigIntImpl::<N_BITS>::zip(0, 1) }
                for i in 0..N_U30_LIMBS * 2 {
                    { expected[(N_U30_LIMBS * 2 - 1 - i) as usize] }
                    OP_EQUALVERIFY
                }
                OP_PUSHNUM_1
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_copy() {
        const N_BITS: u32 = 254;
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
                for i in 0..(N_U30_LIMBS * 2) {
                    { v[i as usize] }
                }
                { UBigIntImpl::<N_BITS>::copy(1) }
                for i in 0..N_U30_LIMBS {
                    { expected[(N_U30_LIMBS - 1 - i) as usize] }
                    OP_EQUALVERIFY
                }
                { UBigIntImpl::<N_BITS>::drop() }
                { UBigIntImpl::<N_BITS>::drop() }
                OP_PUSHNUM_1
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_bring() {
        const N_BITS: u32 = 254;
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
                for i in 0..(N_U30_LIMBS * 2) {
                    { v[i as usize] }
                }
                { UBigIntImpl::<N_BITS>::bring(1) }
                for i in 0..N_U30_LIMBS {
                    { expected[(N_U30_LIMBS - 1 - i) as usize] }
                    OP_EQUALVERIFY
                }
                { UBigIntImpl::<N_BITS>::drop() }
                OP_PUSHNUM_1
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}
