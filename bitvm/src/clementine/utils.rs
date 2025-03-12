use crate::treepp::*;
use bitcoin::Witness;

pub fn roll_constant(d : usize) -> Script {
    script! {
        if d == 0 {

        } else if d == 1 {
            OP_SWAP
        } else if d == 2 {
            OP_ROT
        } else {
            { d } OP_ROLL
        }
    }
}

pub fn extend_witness(w: &mut Witness, add: Witness) {
    for x in &add {
        w.push(x)
    }
}
