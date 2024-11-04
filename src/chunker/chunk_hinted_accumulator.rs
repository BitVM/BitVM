use super::elements::Fq12Type;
use super::{assigner::BCAssigner, segment::Segment};

use crate::bn254::fq12::Fq12;
use crate::bn254::utils::fq12_push_not_montgomery;
use crate::groth16::constants::{LAMBDA, P_POW3};
use crate::groth16::offchain_checker::compute_c_wi;
use crate::treepp::*;

use ark_bn254::{Bn254, G1Projective};
use ark_ec::pairing::Pairing as ark_Pairing;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::Field;
use ark_groth16::{Proof, VerifyingKey};
use core::ops::Neg;

pub fn verify_accumulator<T: BCAssigner>(
    assigner: &mut T,
    prefix: &str,
    pa: Fq12Type,
    public_inputs: &Vec<<Bn254 as ark_Pairing>::ScalarField>,
    proof: &Proof<Bn254>,
    vk: &VerifyingKey<Bn254>,
) -> (Vec<Segment>, ark_bn254::Fq12) {
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
    let script_lines = [
        // Input stack: [final_f]
        // check final_f == hint
        fq12_push_not_montgomery(hint),
        Fq12::equalverify(),
        // script! {OP_TRUE},
    ];
    let mut script = script! {};
    for script_line in script_lines {
        script = script.push_script(script_line.compile());
    }

    let mut segments = vec![];
    let segment = Segment::new_with_name(format!("{}verify_f", prefix), script).add_parameter(&pa);

    segments.push(segment);
    (segments, hint)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::bn254::fq::Fq;
    use crate::bn254::msm::hinted_msm_with_constant_bases_affine;
    use crate::bn254::utils::g1_affine_push_not_montgomery;
    use crate::bn254::utils::hinted_from_eval_point;
    use crate::bn254::{curves::G1Affine, utils::g1_affine_push};
    use crate::chunker::assigner::*;
    use crate::chunker::chunk_accumulator::*;
    use crate::chunker::chunk_g1_points::*;
    use crate::chunker::elements::DataType::G1PointData;
    use crate::{execute_script, execute_script_with_inputs, execute_script_without_stack_limit};

    use ark_ff::Field;
    use ark_std::UniformRand;
    use num_bigint::BigUint;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use crate::bn254::utils::Hint;
    use ark_ec::{CurveGroup, VariableBaseMSM};
    use ark_std::{end_timer, start_timer, test_rng};

    use crate::bn254::ell_coeffs::{mul_by_char, G2Prepared};
    use crate::chunker::elements::{DataType::Fq12Data, ElementTrait, FqType, G1PointType};
    use crate::execute_script_as_chunks;
    use crate::groth16::verifier::Verifier;
    use ark_bn254::Bn254;
    use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
    use ark_ec::pairing::Pairing;
    use ark_ff::{BigInteger, PrimeField};
    use ark_groth16::Groth16;
    use ark_relations::lc;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
    use bitcoin_script::script;
    use rand::RngCore;

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
        let msm_g1 =
            G1Projective::msm(&vk.gamma_abc_g1, &scalars).expect("failed to calculate msm");

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
        let msm_g1 =
            G1Projective::msm(&vk.gamma_abc_g1, &scalars).expect("failed to calculate msm");

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

    #[test]
    fn test_p() {
        let mut assigner = DummyAssinger {};

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

        // let (hinted_groth16_verifier, hints) = Verifier::hinted_verify(&vec![c], &proof, &vk);
        let (g1a, g1p) = generate_p1(&mut assigner, &vec![c], &vk);
        let (segments, plist) = g1_points(&mut assigner, g1p, g1a, &proof, &vk);

        println!("segments len {}", segments.len());
        for segment in segments {
            let witness = segment.witness(&assigner);
            let script = segment.script(&assigner);

            let res = execute_script_with_inputs(script.clone(), witness.clone());
            println!("segment exec_result: {}", res);

            let zero: Vec<u8> = vec![];
            assert_eq!(res.final_stack.len(), 1, "{}", segment.name); // only one element left
            assert_eq!(res.final_stack.get(0), zero, "{}", segment.name);
            assert!(
                res.stats.max_nb_stack_items < 1000,
                "{}",
                res.stats.max_nb_stack_items
            );

            let mut lenw = 0;
            for w in witness {
                lenw += w.len();
            }
            assert!(script.len() + lenw < 4000000, "script and witness len");
        }
    }

    #[test]
    fn test_calc_f() {
        let mut assigner = DummyAssinger {};

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

        let mut prng: ChaCha20Rng = ChaCha20Rng::seed_from_u64(0);
        let rc = ark_bn254::Fq12::rand(&mut prng);
        let mut tc = Fq12Type::new(&mut assigner, &format!("{}{}", "test".to_owned(), "c"));
        tc.fill_with_data(Fq12Data(rc));
        let (segments, tf) = verify_accumulator(&mut assigner, "test", tc, &vec![c], &proof, &vk);
        let mut tc = Fq12Type::new(&mut assigner, &format!("{}{}", "test".to_owned(), "c1"));
        tc.fill_with_data(Fq12Data(tf));

        // let (hinted_groth16_verifier, hints) = Verifier::hinted_verify(&vec![c], &proof, &vk);
        let (g1a, g1p) = generate_p1(&mut assigner, &vec![c], &vk);
        let (segments, tp_lst) = g1_points(&mut assigner, g1p, g1a, &proof, &vk);

        let (constants, c, c_inv, wi, p_lst, q4) = generate_f_arg(&vec![c], &proof, &vk);
        let (segments, fs, f) =
            chunk_accumulator(&mut assigner, tp_lst, constants, c, c_inv, wi, p_lst, q4);
        println!("tf: {} \n f: {}", tf, f);
        println!("tc: {:?} \n fs: {:?}", tc, fs);

        println!("segments len {}", segments.len());
        for segment in segments {
            let witness = segment.witness(&assigner);
            let script = segment.script(&assigner);

            let res = execute_script_with_inputs(script.clone(), witness.clone());
            println!("segment exec_result: {}", res);

            let zero: Vec<u8> = vec![];
            assert_eq!(res.final_stack.len(), 1, "{}", segment.name); // only one element left
            assert_eq!(res.final_stack.get(0), zero, "{}", segment.name);
            assert!(
                res.stats.max_nb_stack_items < 1000,
                "{}",
                res.stats.max_nb_stack_items
            );

            let mut lenw = 0;
            for w in witness {
                lenw += w.len();
            }
            assert!(script.len() + lenw < 4000000, "script and witness len");
        }
    }

    #[test]
    fn test_verify_f() {
        let mut assigner = DummyAssinger {};

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

        let mut prng: ChaCha20Rng = ChaCha20Rng::seed_from_u64(0);
        let rc = ark_bn254::Fq12::rand(&mut prng);
        let mut tc = Fq12Type::new(&mut assigner, &format!("{}{}", "test".to_owned(), "c"));
        tc.fill_with_data(Fq12Data(rc));
        let (segments, f) = verify_accumulator(&mut assigner, "test", tc, &vec![c], &proof, &vk);
        let mut tc1 = Fq12Type::new(&mut assigner, &format!("{}{}", "test".to_owned(), "c1"));
        tc1.fill_with_data(Fq12Data(f));

        let (segments, f1) = verify_accumulator(&mut assigner, "test", tc1, &vec![c], &proof, &vk);
        println!("segments len {}", segments.len());
        for segment in segments {
            let witness = segment.witness(&assigner);
            let script = segment.script(&assigner);

            let res = execute_script_with_inputs(script.clone(), witness.clone());
            println!("segment exec_result: {}", res);

            let zero: Vec<u8> = vec![];
            assert_eq!(res.final_stack.len(), 1, "{}", segment.name); // only one element left
            assert_eq!(res.final_stack.get(0), zero, "{}", segment.name);
            assert!(
                res.stats.max_nb_stack_items < 1000,
                "{}",
                res.stats.max_nb_stack_items
            );

            let mut lenw = 0;
            for w in witness {
                lenw += w.len();
            }
            assert!(script.len() + lenw < 4000000, "script and witness len");
        }
    }

    #[test]
    fn test_all() {
        let mut assigner = DummyAssinger {};
        let mut segments: Vec<Segment> = vec![];

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

        let cx = circuit.a.unwrap() * circuit.b.unwrap();

        let proof = Groth16::<E>::prove(&pk, circuit, &mut rng).unwrap();

        let mut prng: ChaCha20Rng = ChaCha20Rng::seed_from_u64(0);
        let rc = ark_bn254::Fq12::rand(&mut prng);
        let mut tc = Fq12Type::new(&mut assigner, &format!("{}{}", "test".to_owned(), "c"));
        tc.fill_with_data(Fq12Data(rc));
        // target f = tc, tf
        let (s, tf) = verify_accumulator(&mut assigner, "test", tc, &vec![cx], &proof, &vk);
        let mut tc = Fq12Type::new(&mut assigner, &format!("{}{}", "test".to_owned(), "c1"));
        tc.fill_with_data(Fq12Data(tf));

        // let (hinted_groth16_verifier, hints) = Verifier::hinted_verify(&vec![c], &proof, &vk);
        let (g1a, g1p) = generate_p1(&mut assigner, &vec![cx], &vk);
        let (s, tp_lst) = g1_points(&mut assigner, g1p, g1a, &proof, &vk);
        println!("segments p len {}", s.len());
        segments.extend(s);
        // calc f = fs,f
        let (constants, c, c_inv, wi, p_lst, q4) = generate_f_arg(&vec![cx], &proof, &vk);
        let (s, fs, f) =
            chunk_accumulator(&mut assigner, tp_lst, constants, c, c_inv, wi, p_lst, q4);
        println!("segments calc_f len {}", s.len());
        segments.extend(s);
        //verify f
        let (s, f1) = verify_accumulator(&mut assigner, "test", fs, &vec![cx], &proof, &vk);
        println!("segments verify_f len {}", s.len());
        segments.extend(s);
        println!("segments total len {}", segments.len());

        for segment in segments {
            let witness = segment.witness(&assigner);
            let script = segment.script(&assigner);

            let res = execute_script_with_inputs(script.clone(), witness.clone());
            // println!("segment exec_result: {}", res);

            let zero: Vec<u8> = vec![];
            assert_eq!(res.final_stack.len(), 1, "{}", segment.name); // only one element left
            assert_eq!(res.final_stack.get(0), zero, "{}", segment.name);
            assert!(
                res.stats.max_nb_stack_items < 1000,
                "{}",
                res.stats.max_nb_stack_items
            );

            let mut lenw = 0;
            for w in witness {
                lenw += w.len();
            }
            assert!(script.len() + lenw < 4000000, "script and witness len");
        }
    }
}
