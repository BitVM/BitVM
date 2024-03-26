use crate::treepp::{pushable, script, Script};
use crate::ubigint::UBigIntImpl;

impl<const N_BITS: usize> UBigIntImpl<N_BITS> {
    pub fn push_u32_le(v: &[u32]) -> Script {
        let n_limbs: usize = (N_BITS + 30 - 1) / 30;

        let mut bits = vec![];
        for elem in v.iter() {
            for i in 0..32 {
                bits.push((elem & (1 << i)) != 0);
            }
        }

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
            for _ in 0..(n_limbs - limbs.len()) as u32 {
                0
            }
        }
    }

    /// Copy and zip the top two u{16N} elements
    /// input:  a0 ... a{N-1} b0 ... b{N-1}
    /// output: a0 b0 ... ... a{N-1} b{N-1}
    pub fn zip(mut a: u32, mut b: u32) -> Script {
        let n_limbs: usize = (N_BITS + 30 - 1) / 30;
        a = (a + 1) * (n_limbs as u32) - 1;
        b = (b + 1) * (n_limbs as u32) - 1;

        assert_ne!(a, b);
        if a < b {
            script! {
                for i in 0..n_limbs as u32 {
                    { a + i }
                    OP_ROLL
                    { b }
                    OP_ROLL
                }
            }
        } else {
            script! {
                for i in 0..n_limbs as u32 {
                        { a }
                        OP_ROLL
                        { b + i + 1 }
                        OP_ROLL
                    }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use rand_chacha::ChaCha20Rng;
    use rand::{Rng, SeedableRng};
    use bitcoin_script::script;
    use crate::treepp::{execute_script, pushable};
    use crate::ubigint::UBigIntImpl;

    #[test]
    fn test_zip() {
        const N_BITS: usize = 1500;
        const N_U30_LIMBS: usize = 50;

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
                expected.push(v[i]);
                expected.push(v[N_U30_LIMBS + i]);
            }

            let script = script! {
                for i in 0..(N_U30_LIMBS * 2) {
                    { v[i as usize] }
                }
                { UBigIntImpl::<N_BITS>::zip(1, 0) }
                for i in 0..(N_U30_LIMBS * 2) as u32 {
                    { expected[N_U30_LIMBS * 2 - 1 - (i as usize)] }
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
                expected.push(v[N_U30_LIMBS + i]);
                expected.push(v[i]);
            }

            let script = script! {
                for i in 0..N_U30_LIMBS * 2 {
                    { v[i] }
                }
                { UBigIntImpl::<N_BITS>::zip(0, 1) }
                for i in 0..N_U30_LIMBS * 2 {
                    { expected[N_U30_LIMBS * 2 - 1 - (i)] }
                    OP_EQUALVERIFY
                }
                OP_PUSHNUM_1
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}