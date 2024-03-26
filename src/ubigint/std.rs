use crate::treepp::{unroll, pushable, script, Script};
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
            { unroll(limbs.len() as u32, |i| script! {
                { limbs[i as usize] }
            })}
            { unroll((n_limbs - limbs.len()) as u32, |_| script! {
                { 0 }
            })}
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
            unroll(n_limbs as u32, |i| script! {
                { a + i } OP_ROLL { b } OP_ROLL
            })
        } else {
            unroll(n_limbs as u32, |i| script! {
                { a } OP_ROLL { b + i + 1 } OP_ROLL
            })
        }
    }
}