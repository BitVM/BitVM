
pub use crate::hash::blake3_u32::blake3_var_length;
use crate::{treepp::*, ExecuteInfo};

pub type Witness = Vec<Vec<u8>>;

pub fn witness_size(witness: &Witness) -> usize {
    let mut sum = 0;
    for x in witness {
        sum += x.len();
    }
    sum
}

pub type BLAKE3HASH = [u8; 32];

pub fn not_equal(n: usize) -> Script {
    if n == 0 {
        return script! {OP_FALSE};
    }

    script!(
        for i in 0..n {
            {i + n}
            OP_PICK
            {i + 1}
            OP_PICK
            OP_EQUAL
            OP_TOALTSTACK
        }

        for _ in 0..2*n {
            OP_DROP
        }

        OP_FROMALTSTACK

        for _ in 0..n-1 {
            OP_FROMALTSTACK
            OP_BOOLAND
        }

        OP_NOT
    )
}

pub fn witness_to_array(witness: Vec<Vec<u8>>) -> BLAKE3HASH {
    assert_eq!(witness.len(), 32);
    let mut res = [0; 32];
    for (idx, byte) in witness.iter().enumerate() {
        if byte.len() == 0 {
            res[idx] = 0;
        } else {
            res[idx] = byte[0];
        }
    }
    res
}

pub fn extract_witness_from_stack(res: ExecuteInfo) -> Vec<Vec<u8>> {
    res.final_stack.0.iter_str().fold(vec![], |mut vector, x| {
        vector.push(x);
        vector
    })
}

pub fn equalverify(n: usize) -> Script {
    script!(
        for _ in 0..n {
            OP_TOALTSTACK
        }

        for i in 1..n {
            {i}
            OP_ROLL
        }

        for _ in 0..n {
            OP_FROMALTSTACK
            OP_EQUALVERIFY
        }
    )
}
