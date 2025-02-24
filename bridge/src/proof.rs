use ark_bn254::{g1::G1Affine, Bn254};
use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_groth16::Groth16;
use ark_relations::lc;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::{test_rng, UniformRand};

use bitvm::chunker::disprove_execution::RawProof;
use rand::{RngCore, SeedableRng};

// TODO: replace with actual implementation
pub fn get_proof() -> RawProof {
    type E = Bn254;
    let k = 6;
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
    let circuit = DummyCircuit::<<E as Pairing>::ScalarField> {
        a: Some(<E as Pairing>::ScalarField::rand(&mut rng)),
        b: Some(<E as Pairing>::ScalarField::rand(&mut rng)),
        num_variables: 10,
        num_constraints: 1 << k,
    };
    let (pk, vk) = Groth16::<E>::setup(circuit, &mut rng).unwrap();

    let c = circuit.a.unwrap() * circuit.b.unwrap();

    let proof = Groth16::<E>::prove(&pk, circuit, &mut rng).unwrap();

    RawProof {
        proof,
        public: vec![c],
        vk,
    }
}

// DO NOT USE IN PRODUCTION! This is a test function.
pub fn invalidate_proof(valid_proof: &RawProof) -> RawProof {
    let mut invalid_proof = valid_proof.clone();
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
    invalid_proof.proof.a = G1Affine::rand(&mut rng);

    invalid_proof
}

// TODO: Consider importing `gen_correct_proof` fn from bitvm/src/chunker/disprove_execution.rs
// It requires refactoring bitvm crate
// Copied from bitvm/src/chunker/disprove_execution.rs
#[derive(Copy)]
pub struct DummyCircuit<F: PrimeField> {
    pub a: Option<F>,
    pub b: Option<F>,
    pub num_variables: usize,
    pub num_constraints: usize,
}

impl<F: PrimeField> Clone for DummyCircuit<F> {
    fn clone(&self) -> Self {
        DummyCircuit {
            a: self.a,
            b: self.b,
            num_variables: self.num_variables,
            num_constraints: self.num_constraints,
        }
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for DummyCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| {
            let a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
            let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

            Ok(a * b)
        })?;

        for _ in 0..(self.num_variables - 3) {
            let _ = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        }

        for _ in 0..self.num_constraints - 1 {
            cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        }

        cs.enforce_constraint(lc!(), lc!(), lc!())?;

        Ok(())
    }
}
