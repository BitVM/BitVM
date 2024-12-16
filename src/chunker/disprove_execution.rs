use super::{
    assigner::BCAssigner, chunk_groth16_verifier::groth16_verify_to_segments, common::RawWitness,
    elements::dummy_element,
};
use crate::groth16::{constants::LAMBDA, offchain_checker::compute_c_wi};
use ark_bn254::{Bn254, G1Projective};
use ark_ec::pairing::Pairing;
use ark_ec::pairing::Pairing as ark_Pairing;
use ark_ec::{AffineRepr as _, CurveGroup as _, VariableBaseMSM as _};
use ark_ff::Field as _;
use ark_groth16::{Proof, VerifyingKey};
use std::ops::Neg;
use std::rc::Rc;

#[derive(Clone)]
pub struct RawProof {
    pub proof: Proof<ark_bn254::Bn254>,
    pub public: Vec<<ark_bn254::Bn254 as ark_ec::pairing::Pairing>::ScalarField>,
    pub vk: VerifyingKey<ark_bn254::Bn254>,
}

impl RawProof {
    pub fn valid_proof(&self) -> bool {
        let scalars = [
            vec![<Bn254 as ark_Pairing>::ScalarField::ONE],
            self.public.clone(),
        ]
        .concat();
        let msm_g1 =
            G1Projective::msm(&self.vk.gamma_abc_g1, &scalars).expect("failed to calculate msm");
        let (p1, p2, p3, p4) = (
            msm_g1.into_affine(),
            self.proof.c,
            self.vk.alpha_g1,
            self.proof.a,
        );
        let (q1, q2, q3, q4) = (
            self.vk.gamma_g2.into_group().neg().into_affine(),
            self.vk.delta_g2.into_group().neg().into_affine(),
            -self.vk.beta_g2,
            self.proof.b,
        );
        let _t4 = q4;

        // hint from arkworks
        let mut f: ark_ff::QuadExtField<ark_ff::Fp12ConfigWrapper<ark_bn254::Fq12Config>> =
            Bn254::multi_miller_loop_affine([p1, p2, p3, p4], [q1, q2, q3, q4]).0;
        let (c, wi) = compute_c_wi(f);
        let c_inv = c.inverse().unwrap();
        let exp = &*LAMBDA;
        f = f * wi * (c_inv.pow((exp).to_u64_digits()));
        f == ark_ff::QuadExtField::ONE
    }
}

pub fn disprove_exec<A: BCAssigner>(
    assigner: &mut A,
    assert_witness: Vec<Vec<RawWitness>>,
    wrong_proof: RawProof,
) -> Option<(usize, RawWitness)> {
    // 0. if 'wrong_proof' is correct, return none
    if wrong_proof.valid_proof() {
        return None;
    }

    // 1. derive assigner from wrong proof
    let mut wrong_proof_assigner = A::default();
    let mut segments = groth16_verify_to_segments(
        &mut wrong_proof_assigner,
        &wrong_proof.public,
        &wrong_proof.proof,
        &wrong_proof.vk,
    );
    let _segment_length = segments.len();

    // 2. recover assigner from witness
    let hash_map = assigner.recover_from_witness(assert_witness);

    // 3. find which chunk is unconsistent
    for (idx, segment) in segments.iter_mut().enumerate() {
        let mut is_param_equal = true;
        for param in segment.parameter_list.iter() {
            if param.to_hash().unwrap() != *hash_map.get(param.id()).unwrap() {
                is_param_equal = false;
            }
        }
        let mut is_result_equal = true;
        for result in segment.result_list.iter_mut() {
            if result.to_hash().unwrap() != *hash_map.get(result.id()).unwrap() {
                is_result_equal = false;
                // replace the result to hash_map
                *result = Rc::new(Box::new(dummy_element(
                    result.id(),
                    *hash_map.get(result.id()).unwrap(),
                )));
            }
        }

        if is_param_equal && !is_result_equal {
            let disprove_witness = segment.witness(assigner);
            return Some((idx, disprove_witness));
        }
    }

    // if all intermediate values is identical, then return the final chunk
    for (idx, segment) in segments.iter().enumerate() {
        if segment.is_final() {
            let disprove_witness = segment.witness(assigner);
            return Some((idx, disprove_witness));
        }
    }

    println!("Shouldn't happend, some chunk must can be available with a wrong proof");
    None
}

#[cfg(test)]
mod tests {
    use crate::chunker::assigner::*;
    use crate::chunker::chunk_groth16_verifier::groth16_verify_to_segments;
    use crate::chunker::disprove_execution::RawProof;
    use crate::chunker::elements::Fq12Type;
    use crate::chunker::elements::ElementTrait;
    use crate::execute_script_with_inputs;

    use ark_bn254::g1::G1Affine;
    use ark_bn254::{Bn254, Fq12};
    use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
    use ark_ec::pairing::Pairing;
    use ark_ff::{Field, PrimeField};
    use ark_groth16::Groth16;
    use ark_relations::lc;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
    use ark_std::{test_rng, UniformRand};
    use rand::{RngCore, SeedableRng};
    use std::collections::BTreeMap;
    use std::rc::Rc;

    use super::disprove_exec;

    #[derive(Copy)]
    struct DummyCircuit<F: PrimeField> {
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
                let _ =
                    cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
            }

            for _ in 0..self.num_constraints - 1 {
                cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
            }

            cs.enforce_constraint(lc!(), lc!(), lc!())?;

            Ok(())
        }
    }

    fn gen_right_proof() -> RawProof {
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
            proof: proof,
            public: vec![c],
            vk: vk,
        }
    }

    /// test wrong proof, doesn't modify any intermediate value
    /// diprove exec will return the final chunk
    #[test]
    fn test_wrong_proof() {
        let mut right_proof = gen_right_proof();

        // make it wrong
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        right_proof.proof.a = G1Affine::rand(&mut rng);
        let wrong_proof = right_proof;

        // assert witness
        let mut assigner = DummyAssigner::default();
        let segments = groth16_verify_to_segments(
            &mut assigner,
            &wrong_proof.public,
            &wrong_proof.proof,
            &wrong_proof.vk,
        );

        println!("segments length: {}", segments.len());

        // get all elements
        let mut elements: BTreeMap<String, std::rc::Rc<Box<dyn ElementTrait>>> = BTreeMap::new();
        for segment in segments.iter() {
            for parameter in segment.parameter_list.iter() {
                elements.insert(parameter.id().to_owned(), parameter.clone());
            }
            for result in segment.result_list.iter() {
                elements.insert(result.id().to_owned(), result.clone());
            }
        }

        // get all witnesses
        let assert_witnesses = assigner.all_intermediate_witnesses(elements);

        // must find some avalible chunk
        let (id, witness) = disprove_exec(&mut assigner, assert_witnesses, wrong_proof).unwrap();

        // println!("segment: {:?}", segments[id].parameter_list);
        let script = segments[id].script(&assigner);
        let res = execute_script_with_inputs(script, witness);
        assert!(res.success, "{:?}, {:?}", res.error, res.final_stack);
    }

    /// test wrong proof and modify some intermediate value
    /// diprove exec will return the final chunk
    #[test]
    fn test_wrong_proof_and_modify_intermediates() {
        let mut right_proof = gen_right_proof();

        // make it wrong
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        right_proof.proof.a = G1Affine::rand(&mut rng);
        let wrong_proof = right_proof;

        // assert witness
        let mut assigner = DummyAssigner::default();
        let segments = groth16_verify_to_segments(
            &mut assigner,
            &wrong_proof.public,
            &wrong_proof.proof,
            &wrong_proof.vk,
        );

        println!("segments length: {}", segments.len());

        // get all elements
        let mut elements: BTreeMap<String, std::rc::Rc<Box<dyn ElementTrait>>> = BTreeMap::new();
        for segment in segments.iter() {
            for parameter in segment.parameter_list.iter() {
                elements.insert(parameter.id().to_owned(), parameter.clone());
            }
            for result in segment.result_list.iter() {
                elements.insert(result.id().to_owned(), result.clone());
            }
        }

        // note: assume malicious operator modify some witnesses
        let modify_id = "F_final_2p3c";
        assert!(elements.contains_key(modify_id));
        let mut new_element = Fq12Type::new(&mut assigner, modify_id);
        new_element.fill_with_data(crate::chunker::elements::DataType::Fq12Data(Fq12::ONE));
        elements.insert(modify_id.to_string(), Rc::new(Box::new(new_element)));

        // get all witnesses
        let assert_witnesses = assigner.all_intermediate_witnesses(elements);

        // must find some avalible chunk
        let (id, witness) = disprove_exec(&mut assigner, assert_witnesses, wrong_proof).unwrap();

        // println!("segment: {:?}", segments[id].parameter_list);
        let script = segments[id].script(&assigner);
        let res = execute_script_with_inputs(script, witness);
        assert!(res.success);
    }

    #[test]
    fn offchain_check_wrong_proof() {
        let mut right_proof = gen_right_proof();
        assert_eq!(right_proof.valid_proof(), true);

        // make it wrong
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        right_proof.proof.a = G1Affine::rand(&mut rng);
        let wrong_proof = right_proof;

        assert_eq!(wrong_proof.valid_proof(), false);
    }
}
