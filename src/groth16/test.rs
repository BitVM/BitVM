#[cfg(test)]
mod test {
    use crate::groth16::verifier::Verifier;
    use crate::{execute_script, execute_script_no_stack_limit};
    use ark_bn254::Bn254;
    use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
    use ark_ec::pairing::Pairing;
    use ark_ff::Field;
    use ark_groth16::{prepare_verifying_key, Groth16};
    use ark_relations::lc;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
    use ark_std::{end_timer, start_timer, test_rng, UniformRand};
    use rand::{RngCore, SeedableRng};

    struct MySillyCircuit<F: Field> {
        a: Option<F>,
        b: Option<F>,
    }

    impl<ConstraintF: Field> ConstraintSynthesizer<ConstraintF> for MySillyCircuit<ConstraintF> {
        fn generate_constraints(
            self,
            cs: ConstraintSystemRef<ConstraintF>,
        ) -> Result<(), SynthesisError> {
            let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
            let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
            let c = cs.new_input_variable(|| {
                let mut a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
                let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

                a *= &b;
                Ok(a)
            })?;

            cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
            cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
            cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
            cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
            cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
            cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;

            Ok(())
        }
    }

    #[test]
    fn test_verify_proof() {
        type E = Bn254;
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let (pk, vk) = Groth16::<E>::setup(MySillyCircuit { a: None, b: None }, &mut rng).unwrap();
        let pvk = prepare_verifying_key::<E>(&vk);

        let a = <E as Pairing>::ScalarField::rand(&mut rng);
        let b = <E as Pairing>::ScalarField::rand(&mut rng);
        let mut c = a;
        c *= b;

        let proof = Groth16::<E>::prove(
            &pk,
            MySillyCircuit {
                a: Some(a),
                b: Some(b),
            },
            &mut rng,
        )
        .unwrap();
        assert!(Groth16::<E>::verify_with_processed_vk(&pvk, &[c], &proof).unwrap());

        let start = start_timer!(|| "collect_script");
        let script = Verifier::verify_proof(&vec![c], &proof, &vk);
        end_timer!(start);

        // println!("groth16::test_verify_proof = {} bytes", script.len());

        // let start = start_timer!(|| "execute_script");
        // let exec_result = execute_script_no_stack_limit(script);
        // end_timer!(start);

        // assert!(exec_result.success);
    }
}
