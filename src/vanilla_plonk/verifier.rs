use crate::treepp::{pushable, script, Script};
use ark_bn254::{Bn254, G1Projective};
use ark_ec::pairing::Pairing as ark_Pairing;
use crate::vanilla_plonk::types::PlonkProof;

#[derive(Clone, Copy, Debug)]
pub struct Verifier;

impl Verifier {
    pub fn verify_proof(
        public_inputs: &Vec<<Bn254 as ark_Pairing>::ScalarField>,
        proof: &PlonkProof,
        // vk: &VerifyingKey<Bn254>,
    ) -> Script {
        // add proof verification here
        panic!("Proof verification not implemented yet")
    }
}