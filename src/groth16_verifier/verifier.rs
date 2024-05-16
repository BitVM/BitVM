use crate::{
    groth16_verifier::{miller_loop::MillerLoop, pairing::Pairing},
    treepp::{pushable, script, Script},
};

#[derive(Clone, Copy, Debug)]
struct Verifier {}

impl Verifier {
    pub fn verify_proof() -> Script {
        script! {
            { Self::prepare_inputs() }
            { Self::verify_proof_with_prepared_inputs() }
        }
    }

    pub fn verify_proof_with_prepared_inputs() -> Script {
        script! {
            { Self::get_proof() }
            { MillerLoop::multi_miller_loop() }
            { Pairing::final_exponentiation() }
        }
    }

    pub fn prepare_inputs() -> Script {
        script! {
            { prepare_verifying_key() }
            { Self::get_public_inputs() }
        }
    }

    pub fn get_proof() -> Script {
        script! {
            3
        }
    }

    pub fn get_public_inputs() -> Script {
        script! {
            1
        }
    }
}

pub fn prepare_verifying_key() -> Script {
    script! {
        1
    }
}
