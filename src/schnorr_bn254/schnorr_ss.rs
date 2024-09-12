use crate::schnorr_bn254::g1projective_equal::G1Projective_equal;
use crate::treepp::{script, Script};

use crate::hash::blake3::blake3_var_length;

use crate::bn254::curves::{G1Affine, G1Projective};
use crate::bn254::fq::Fq;
use crate::bn254::fr::Fr;
use crate::bn254::fp254impl::Fp254Impl;
use crate::bigint::U254;

// stack contents == s, R, data, public_key <- top of the stack
// here public_key, R and s are represented similar to the output of the functions serialize_G1Affine and serialize_Fr,
// with their 0th bytes closest to the top of the stack
// data should be in the byte order with 0th byte closest to the top of the stack
// refer to the testcase for more understanding
pub fn verify_schnorr_ss(data_size : usize) -> Script {
    script! {
        // generate P
        // public_key, convert it to G1Affine, then to G1Projective and then push it to the alt stack, as is
        { U254::from_bytes() } // for y
        { Fq::toaltstack() } // push y to alt stack
        { U254::from_bytes() } // for x
        { Fq::fromaltstack() } // pop y from alt stack, now we have G1Affine form of P on the stack
        { G1Affine::into_projective() } // convert G1Affine P to G1Projective P
        { G1Projective::toaltstack() } // push P back to alt stack
        
        // generate e = h(Rx || M)
        for _ in (0..36) {// copy Rx to the top of ths stack giving us Rx || tx on the top of the stack
            {data_size + 36 + 35} OP_PICK
        }
        { blake3_var_length(data_size + 36) } // hash (Rx || tx-without the signature attributes)

        // the below Fr::from_hash call requires us to reverse the output of the blake3_var_length, only due to its byte ordering requirements
        for i in 0..32 {
            {i} OP_ROLL
        }
        { Fr::from_hash() }

        // now e is at the top if the stack
        { G1Projective::fromaltstack() } // pop G1Projective P to the top of the stack
        { Fr::roll(3) } // bring e to the top of the stack, and P right under it
        { G1Projective::scalar_mul() } // generate eP = e * P
        { G1Projective::toaltstack() } // push eP to alt stack

        // now the top of the stack is signature component R, we will convert it to G1Projective R
        { U254::from_bytes() } // for y
        { Fq::toaltstack() } // push y to alt stack
        { U254::from_bytes() } // for x
        { Fq::fromaltstack() } // pop y from alt stack, now we have G1Affine form of R on the stack
        { G1Affine::into_projective() } // convert G1Affine R to G1Projective R
        { G1Projective::toaltstack() } // push R back to alt stack

        // now the top of the stack is signature s
        { U254::from_bytes() } // s into its Fr form
        { Fr::toaltstack() } // push s to alt stack

        // push generator on the stack G
        { G1Projective::push_generator() }
        { Fr::fromaltstack() } // bring s back to the stack

        // produce Rv = s * G
        { G1Projective::scalar_mul() }

        // produce R - Rv
        { G1Projective::neg() } // top of the stack is Rv, so first negate it
        { G1Projective::fromaltstack() } // now the stack contains :: -Rv Rv <- top
        { G1Projective::add() } // add them

        // move eP to the stack
        { G1Projective::fromaltstack() }

        // compare top 2 elements of the stack
        { G1Projective_equal() }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{execute_script, execute_script_without_stack_limit, run};
    use crate::schnorr_bn254::{schnorr_ss::*, utility::*};

    #[test]
    fn test_schnorr_ss() {
        #[rustfmt::skip]

        let (private_key, public_key) = generate_key_pair(0);

        // generate some deterministic data
        const data_size : usize = 64;
        let mut data : [u8; data_size] = [0; data_size];
        for i in 0..data_size {
            data[i] = ((i * 13) as u8);
        }

        // sign the data promducing (R,s)
        let (R, s) = sign(&data, &private_key, 1);        
        assert!(verify(&data, &public_key, &R, &s), "test failed signature logic (signing or verification) incorrect");

        let ss = verify_schnorr_ss(data_size);
        println!("script size for schnorr_ss = {}, hence advised to, switch to using schnorr_ps", ss.len());

        let exec_result = execute_script_without_stack_limit(script! {
            for x in serialize_fr(&s).iter().rev() {
                {(*x)}
            }
            for x in serialize_g1affine(&R).iter().rev() {
                {(*x)}
            }
            for x in (&data).iter().rev() {
                {(*x)}
            }
            for x in serialize_g1affine(&public_key).iter().rev() {
                {(*x)}
            }

            { verify_schnorr_ss(data_size) }
        });
        if !exec_result.success {
            println!(
                "ERROR: {:?} <--- \n STACK: {:4} ",
                exec_result.last_opcode, exec_result.final_stack
            );
        }
        assert!(exec_result.success);
    }
}