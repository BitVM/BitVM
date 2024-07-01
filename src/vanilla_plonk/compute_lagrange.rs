use crate::treepp::*;
use num_bigint::BigUint;
use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::fr::Fr;

pub fn compute_lagrange() {

    // for now hardcoding xi
    let xi = "9539499652122301619680560867461437153480631573357135330838514610439758374055";
    let n = "2048";
    let w  = "1";
    let w1 = "19540430494807482326159819597004422086093766032135589407132600596362845576832";

    let script = script! {
        { Fr::push_dec(n) }

        { Fr::push_dec(w) }

        { Fr::push_dec(xi) }

        { Fr::sub(0, 1) }

        // n * (xi - w)
        // pEval_l1
        { Fr::mul() }

        { Fr::toaltstack() }

        { Fr::push_dec(w) }

        { Fr::push_dec(w1) }

        // w * w1
        { Fr::sub(0, 1) }

        // { Fr::equalverify(1, 0) }

        // OP_TRUE
    };
}