use crate::bn254::ell_coeffs::G2Prepared;
use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::fq::Fq;
use crate::bn254::fq12::Fq12;
use crate::bn254::msm::{
    hinted_msm_with_constant_bases, hinted_msm_with_constant_bases_affine, msm_with_constant_bases,
    msm_with_constant_bases_affine,
};
use crate::bn254::pairing::Pairing;
use crate::bn254::utils::{
    fq12_push, fq12_push_not_montgomery, fq2_push, fq2_push_not_montgomery, from_eval_point,
    hinted_from_eval_point, Hint,
};
use crate::chunker::check_q4::check_q4;
use crate::chunker::elements::{DataType::G1PointData, ElementTrait, FrType, G2PointType};
use crate::chunker::msm::chunk_hinted_msm_with_constant_bases_affine;
use crate::chunker::p::p;
use crate::chunker::{calc_f, verify_f};
use crate::groth16::constants::{LAMBDA, P_POW3};
use crate::groth16::offchain_checker::compute_c_wi;
use crate::treepp::{script, Script};
use ark_bn254::{Bn254, G1Projective};
use ark_ec::pairing::Pairing as ark_Pairing;
use ark_ec::short_weierstrass::Projective;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::Field;
use ark_groth16::{Proof, VerifyingKey};
use core::ops::Neg;

use super::assigner::BCAssigner;
use super::elements::G1PointType;
use super::segment::Segment;

pub fn generate_p1<T: BCAssigner>(
    assigner: &mut T,
    public_inputs: &Vec<<Bn254 as ark_Pairing>::ScalarField>,
    vk: &VerifyingKey<Bn254>,
) -> (ark_bn254::G1Affine, G1PointType) {
    let scalars = [
        vec![<Bn254 as ark_Pairing>::ScalarField::ONE],
        public_inputs.clone(),
    ]
    .concat();
    let msm_g1 = G1Projective::msm(&vk.gamma_abc_g1, &scalars).expect("failed to calculate msm");

    let g1a = msm_g1.into_affine();
    let mut g1p = G1PointType::new(assigner, &format!("{}", "test"));
    g1p.fill_with_data(G1PointData(g1a));

    (g1a, g1p)
}

pub fn generate_f_arg(
    public_inputs: &Vec<<Bn254 as ark_Pairing>::ScalarField>,
    proof: &Proof<Bn254>,
    vk: &VerifyingKey<Bn254>,
) -> (
    Vec<G2Prepared>,
    ark_bn254::Fq12,
    ark_bn254::Fq12,
    ark_bn254::Fq12,
    Vec<ark_bn254::G1Affine>,
    ark_bn254::G2Affine,
) {
    // constants: Vec<G2Prepared>,
    // c: ark_bn254::Fq12,
    // c_inv: ark_bn254::Fq12,
    // wi: ark_bn254::Fq12,
    // p_lst: Vec<ark_bn254::G1Affine>,
    // q4: ark_bn254::G2Affine,

    let scalars = [
        vec![<Bn254 as ark_Pairing>::ScalarField::ONE],
        public_inputs.clone(),
    ]
    .concat();
    let msm_g1 = G1Projective::msm(&vk.gamma_abc_g1, &scalars).expect("failed to calculate msm");

    let (exp, sign) = if LAMBDA.gt(&P_POW3) {
        (&*LAMBDA - &*P_POW3, true)
    } else {
        (&*P_POW3 - &*LAMBDA, false)
    };

    // G1/G2 points for pairings
    let (p1, p2, p3, p4) = (msm_g1.into_affine(), proof.c, vk.alpha_g1, proof.a);
    let (q1, q2, q3, q4) = (
        vk.gamma_g2.into_group().neg().into_affine(),
        vk.delta_g2.into_group().neg().into_affine(),
        -vk.beta_g2,
        proof.b,
    );
    let t4 = q4;

    // hint from arkworks
    let f = Bn254::multi_miller_loop_affine([p1, p2, p3, p4], [q1, q2, q3, q4]).0;
    let (c, wi) = compute_c_wi(f);
    let c_inv = c.inverse().unwrap();
    let q_prepared = vec![
        G2Prepared::from_affine(q1),
        G2Prepared::from_affine(q2),
        G2Prepared::from_affine(q3),
        G2Prepared::from_affine(q4),
    ];

    let p_lst = vec![p1, p2, p3, p4];
    (q_prepared.to_vec(), c, c_inv, wi, p_lst, q4)
}

fn verify_to_chunks<T: BCAssigner>(
    assigner: &mut T,
    public_inputs: &Vec<<Bn254 as ark_Pairing>::ScalarField>,
    proof: &Proof<Bn254>,
    vk: &VerifyingKey<Bn254>,
) -> Vec<Segment> {
    let mut hints = Vec::new();

    let scalars = [
        vec![<Bn254 as ark_Pairing>::ScalarField::ONE],
        public_inputs.clone(),
    ]
    .concat();
    let msm_g1 = G1Projective::msm(&vk.gamma_abc_g1, &scalars).expect("failed to calculate msm");
    //let (hinted_msm, hint_msm) = hinted_msm_with_constant_bases(&vk.gamma_abc_g1, &scalars);
    let (hinted_msm, hint_msm) = hinted_msm_with_constant_bases_affine(&vk.gamma_abc_g1, &scalars);
    hints.extend(hint_msm);

    let (exp, sign) = if LAMBDA.gt(&P_POW3) {
        (&*LAMBDA - &*P_POW3, true)
    } else {
        (&*P_POW3 - &*LAMBDA, false)
    };

    // G1/G2 points for pairings
    let (p1, p2, p3, p4) = (msm_g1.into_affine(), proof.c, vk.alpha_g1, proof.a);
    let (q1, q2, q3, q4) = (
        vk.gamma_g2.into_group().neg().into_affine(),
        vk.delta_g2.into_group().neg().into_affine(),
        -vk.beta_g2,
        proof.b,
    );
    let t4 = q4;

    // hint from arkworks
    let f = Bn254::multi_miller_loop_affine([p1, p2, p3, p4], [q1, q2, q3, q4]).0;
    let (c, wi) = compute_c_wi(f);
    let c_inv = c.inverse().unwrap();
    let hint = if sign {
        f * wi * (c_inv.pow((exp).to_u64_digits()))
    } else {
        f * wi * (c_inv.pow((exp).to_u64_digits()).inverse().unwrap())
    };
    assert_eq!(hint, c.pow(P_POW3.to_u64_digits()), "hint isn't correct!");

    let q_prepared = vec![
        G2Prepared::from_affine(q1),
        G2Prepared::from_affine(q2),
        G2Prepared::from_affine(q3),
        G2Prepared::from_affine(q4),
    ];

    let p_lst = vec![p1, p2, p3, p4];

    let mut segments = vec![];

    let mut scalar_types = vec![];
    for (idx, scalar) in scalars.iter().enumerate() {
        let mut scalar_type = FrType::new(assigner, &format!("scalar_{}", idx));
        scalar_type.fill_with_data(crate::chunker::elements::DataType::FrData(scalar.clone()));
        scalar_types.push(scalar_type);
    }

    // calculate p1
    let (segment, p1_type) = chunk_hinted_msm_with_constant_bases_affine(
        assigner,
        &vk.gamma_abc_g1,
        &scalars,
        &scalar_types,
    );

    segments.extend(segment);

    let (segment, tp_lst) = p(assigner, p1_type, p1, &proof, &vk);
    segments.extend(segment);

    let (constants, c, c_inv, wi, p_lst, q4) = generate_f_arg(&public_inputs, &proof, &vk);
    let (segment, fs, f) = calc_f::calc_f(assigner, tp_lst, constants, c, c_inv, wi, p_lst, q4);
    segments.extend(segment);

    let (segment, _) = verify_f::verify_f(assigner, "verify_f", fs, public_inputs, proof, vk);
    segments.extend(segment);

    let mut q4_input = G2PointType::new(assigner, "q4");
    q4_input.fill_with_data(crate::chunker::elements::DataType::G2PointData(q4));
    let segment = check_q4(q_prepared.to_vec(), q4, q4_input, assigner);

    segments.extend(segment);

    segments
}

#[cfg(test)]
mod tests {
    use crate::chunker::assigner::DummyAssinger;
    use crate::chunker::segment;
    use crate::chunker::verifier::verify_to_chunks;
    use crate::groth16::verifier::Verifier;
    use crate::{
        execute_script_as_chunks, execute_script_with_inputs, execute_script_without_stack_limit,
    };
    use ark_bn254::Bn254;
    use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
    use ark_ec::pairing::Pairing;
    use ark_ff::{BigInteger, PrimeField};
    use ark_groth16::Groth16;
    use ark_relations::lc;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
    use ark_std::{end_timer, start_timer, test_rng, UniformRand};
    use bitcoin_script::script;
    use rand::{RngCore, SeedableRng};

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

    #[test]
    fn test_hinted_groth16_verifier() {
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

        let mut assigner = DummyAssinger {};
        let segments = verify_to_chunks(&mut assigner, &vec![c], &proof, &vk);

        println!("segments number: {}", segments.len());

        for (_, segment) in tqdm::tqdm(segments.iter().enumerate()) {
            let witness = segment.witness(&assigner);
            let script = segment.script(&assigner);

            let mut lenw = 0;
            for w in witness.iter() {
                lenw += w.len();
            }
            assert!(
                script.len() + lenw < 4000000,
                "script and witness len is over 4M {}",
                segment.name
            );

            let res = execute_script_with_inputs(script, witness);
            let zero: Vec<u8> = vec![];
            assert_eq!(res.final_stack.len(), 1, "{}", segment.name); // only one element left
            assert_eq!(res.final_stack.get(0), zero, "{}", segment.name);
            assert!(
                res.stats.max_nb_stack_items < 1000,
                "{} in {}",
                res.stats.max_nb_stack_items,
                segment.name
            );
        }
    }
}
