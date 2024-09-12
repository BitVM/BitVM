use crate::treepp::{script, Script};

use crate::bn254::fq::Fq;
use crate::bn254::fp254impl::Fp254Impl;

pub fn G1Projective_equal() -> Script {
    script! {
        OP_1 OP_TOALTSTACK // initialize result stack

        { Fq::copy(3) }
        { Fq::square() }
        { Fq::roll(4) }
        { Fq::copy(1) }
        { Fq::mul() }

        { Fq::copy(2) }
        { Fq::square() }
        { Fq::roll(3) }
        { Fq::copy(1) }
        { Fq::mul() }

        { Fq::roll(7) }
        { Fq::roll(2) }
        { Fq::mul() }
        { Fq::roll(5) }
        { Fq::roll(4) }
        { Fq::mul() }
        { Fq::equal(1, 0) }
        OP_FROMALTSTACK OP_BOOLAND OP_TOALTSTACK // and the output of equal with the result

        { Fq::roll(3) }
        { Fq::roll(1) }
        { Fq::mul() }
        { Fq::roll(2) }
        { Fq::roll(2) }
        { Fq::mul() }
        { Fq::equal(1, 0) }
        OP_FROMALTSTACK OP_BOOLAND // and the output of equal with the result, and leave result on the stack
    }
}