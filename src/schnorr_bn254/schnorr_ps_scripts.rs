use crate::schnorr_bn254::g1projective_equal::G1Projective_equal;
use crate::schnorr_bn254::utility::{serialize_fr, serialize_g1affine};
use crate::treepp::{script, Script};

use crate::hash::blake3::blake3_var_length;

use crate::bn254::curves::{G1Affine, G1Projective};
use crate::bn254::fq::Fq;
use crate::bn254::fr::Fr;
use crate::bn254::fp254impl::Fp254Impl;
use crate::bigint::U254;

// inputs are e, data, R.x <- top of the stack
// alll the fields with their 0th byte closest to the top of the stack
pub fn verify_e(data_size : usize) -> Script {
    script! {
        { blake3_var_length(data_size + 36) } // hash (Rx || data)

        // the below Fr::from_hash call requires us to reverse the output of the blake3_var_length
        for i in 0..32 {
            {i} OP_ROLL
        }
        { Fr::from_hash() }

        { Fr::toaltstack() } // push generated e to the stack

        { U254::from_bytes() } // convert input e to its Fr form

        { Fr::fromaltstack() } // now both the e (generated and the input) are on the stack

        { Fr::equal(1, 0) } // compare them both

        OP_NOT
    }
}

const input_point_size_on_stack : usize = 36 * 2;
fn convert_to_G1Projective_from_top_bytes() -> Script {
    script! {
        { U254::from_bytes() }
        { Fq::toaltstack() }
        { U254::from_bytes() }
        { Fq::fromaltstack() }
        { G1Affine::into_projective() }
    }
}

// inputs are serialized form of (Ri, Pi, i, s, Ri-1)
// Ri being at the top of the stack
// evaulates (Ri != Ri-1 + s[i] * Pi)
pub fn verify_bit_product() -> Script {
    script! {
        // Ri to its G1Projective form and push it to alt stack
        { convert_to_G1Projective_from_top_bytes() }
        { G1Projective::toaltstack() }

        // Pi to its G1Projective form and push it to alt stack
        { convert_to_G1Projective_from_top_bytes() }
        { G1Projective::toaltstack() }

        // now the top of the stack are i and then s and then Ri-1
        OP_TOALTSTACK
        { U254::from_bytes() }
        { Fr::decode_montgomery() } // need to decode montgomery for the scalar, for scalar multiplication
        { Fr::convert_to_le_bits() }
        OP_FROMALTSTACK
        OP_ROLL // fetch the ith bit
        // drop the rest of the 253 bits
        OP_TOALTSTACK
        for _ in 0..253 {
            OP_DROP
        }

        // now the top of the alt stack is s[i]
        // and top of the stack is Ri-1 in bytes

        // convert Ri-1 into its projective from
        { convert_to_G1Projective_from_top_bytes() }

        OP_FROMALTSTACK // bring s[i] to the stack
        OP_IF
            { G1Projective::fromaltstack() }
            { G1Projective::add() }
        OP_ELSE
            { G1Projective::fromaltstack() }
            { G1Projective::drop() }
        OP_ENDIF

        // bring Ri from its affine from, from the altstack
        { G1Projective::fromaltstack() }

        // compare
        { G1Projective_equal() }
        OP_NOT
    }
}

// inputs are serialized form of (Pi+1, Pi)
// Pi+1 being at the top of the stack
// evaulates (Pi+1 != 2 * Pi)
pub fn verify_double() -> Script {
    script!{
        // Pi+1 into its G1Projective form and push it to alt stack
        { convert_to_G1Projective_from_top_bytes() }
        { G1Projective::toaltstack() }

        // Pi into its G1Projective form
        { convert_to_G1Projective_from_top_bytes() }

        // double Pi
        { G1Projective::double() }

        // bring Pi+1 to the stack
        { G1Projective::fromaltstack() }

        // compare both Pi+1 and Pi * 2
        { G1Projective_equal() }
        OP_NOT
    }
}

// inputs are serialized form of (R, s*G, e*P)
// R at the top of the stack
// evauates R - s * G != e * P
pub fn verify_result() -> Script {
    script!{
        // convert R into into its G1Projective from, and push it to altstack
        { convert_to_G1Projective_from_top_bytes() }
        { G1Projective::toaltstack() }

        // convert s * G into its G1Projective form, and then negate it
        { convert_to_G1Projective_from_top_bytes() }
        { G1Projective::neg() }

        // add the R + (-s*G)
        { G1Projective::fromaltstack() }
        { G1Projective::add() }
        { G1Projective::toaltstack() }

        // convert e*P into its G1Projective form
        { convert_to_G1Projective_from_top_bytes() }

        // now move the addition result to the stack and compare it
        { G1Projective::fromaltstack() }

        // compare them
        { G1Projective_equal() }
        OP_NOT
    }
}