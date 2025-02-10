use ark_groth16::{Proof, VerifyingKey};
use bitcoin_script::script;
use itertools::Itertools;
use std::{collections::BTreeMap, rc::Rc};
use crate::{chunk::assigner::{get_assertions, get_intermediates, get_proof, hint_to_data}, groth16::g16::{Assertions, PublicKeys, Signatures}, signatures::{signing_winternitz::{generate_winternitz_witness, WinternitzPublicKey, WinternitzSecret, WinternitzSigningInputs}, wots::wots256}, treepp::Script};
use super::{assigner::{InputProof, Intermediates},  elements::{CompressedStateObject, ElementTrait, RawWitness}, primitives::HashBytes, segment::Segment};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

#[derive(Clone, Debug, PartialEq, CanonicalDeserialize, CanonicalSerialize)]
pub struct RawProof {
    pub proof: Proof<ark_bn254::Bn254>,
    pub public: Vec<<ark_bn254::Bn254 as ark_ec::pairing::Pairing>::ScalarField>,
    pub vk: VerifyingKey<ark_bn254::Bn254>,
}

/// Implement `BCAssinger` to adapt with bridge.
#[allow(clippy::borrowed_box)]
pub trait BCAssigner {
    fn all_intermediate_witnesses(
        &self,
        segments: Vec<Segment>,
    ) -> Assertions;

    /// recover hashes from witnesses
    fn recover_from_witnesses(
        &mut self,
        witnesses: Signatures,
    ) -> (Intermediates, InputProof);
}

pub struct BridgeAssigner {
}

impl BridgeAssigner {
    pub fn new_operator() -> Self {
        Self {
        }
    }
}
impl BCAssigner for BridgeAssigner {
     /// output witness for all elements, used by assert transaction
     fn all_intermediate_witnesses(
         &self,
         segments: Vec<Segment>,
     ) -> Assertions {
        let filtered_segments: Vec<&Segment> = segments.iter().filter(|f| !f.is_validation).collect();
        hint_to_data(segments)
     }

     /// recover hashes from witnesses
     fn recover_from_witnesses(
         &mut self,
         signed_asserts: Signatures,
     ) -> (Intermediates, InputProof) {

        let asserts = get_assertions(signed_asserts);
        let proof = get_proof(&asserts);
        let intermediates = get_intermediates(&asserts);
        (intermediates, proof)
     }
}