use std::str::FromStr;

use ark_bn254::{Bn254, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::{
    pairing::{Pairing, PairingOutput},
    short_weierstrass::{Projective, SWCurveConfig},
    AffineRepr, CurveGroup, Group, VariableBaseMSM,
};
use ark_ff::{Field, One, QuadExtField, Zero};
use ark_groth16::{Proof, VerifyingKey};
use num_bigint::BigUint;
use num_traits::Num;

use crate::{
    bn254::{
        ell_coeffs::G2Prepared, fp254impl::Fp254Impl, fq::Fq, fq12::Fq12, msm::msm,
        pairing::Pairing as Pairing2,
    },
    groth16::checkpairing_with_c_wi_groth16::{compute_c_wi, fq12_push},
    treepp::{pushable, script, Script},
};

#[derive(Clone, Copy, Debug)]
pub struct Verifier;

impl Verifier {
    pub fn verify_proof(
        public_inputs: &Vec<<Bn254 as Pairing>::ScalarField>,
        proof: &Proof<Bn254>,
        vk: &VerifyingKey<Bn254>,
    ) -> Script {
        let (msm_script, msm_g1) = Self::prepare_inputs(public_inputs, vk);
        script! {
            { Self::verify_proof_with_prepared_inputs(proof, vk, msm_script, msm_g1) }
        }
    }

    pub fn prepare_inputs(
        public_inputs: &Vec<<Bn254 as Pairing>::ScalarField>,
        vk: &VerifyingKey<Bn254>,
    ) -> (Script, Projective<ark_bn254::g1::Config>) {
        let bases = vk
            .gamma_abc_g1
            .get(1..public_inputs.len() + 1)
            .expect("invalid public inputs");
        println!("public inputs: {:?}", &public_inputs);
        println!("bases: {:?}", &bases);
        println!("gamma_abc_g1: {:?}", &vk.gamma_abc_g1);
        let sum_ai_abc_gamma =
            G1Projective::msm(bases, &public_inputs).expect("failed to calculate msm");
        println!("sum_ai_abc_gamma = {}", sum_ai_abc_gamma.to_string());
        (msm(bases, &public_inputs), sum_ai_abc_gamma)
    }

    pub fn verify_proof_with_prepared_inputs(
        proof: &Proof<Bn254>,
        vk: &VerifyingKey<Bn254>,
        msm_script: Script,
        msm_g1: Projective<ark_bn254::g1::Config>,
    ) -> Script {
        let p_pow3 = &BigUint::from_str_radix(Fq::MODULUS, 16).unwrap().pow(3_u32);
        let lambda = BigUint::from_str(
                    "10486551571378427818905133077457505975146652579011797175399169355881771981095211883813744499745558409789005132135496770941292989421431235276221147148858384772096778432243207188878598198850276842458913349817007302752534892127325269"
                ).unwrap();
        let (exp, sign) = if lambda > *p_pow3 {
            (lambda - p_pow3, true)
        } else {
            (p_pow3 - lambda, false)
        };

        let q_prepared = [
            G2Prepared::from(vk.gamma_g2),
            G2Prepared::from(vk.beta_g2),
            G2Prepared::from(vk.delta_g2),
        ]
        .to_vec();

        let sum_ai_abc_gamma: G1Affine = msm_g1.into();
        println!("sum_ai_abc_gamma2 = {}", sum_ai_abc_gamma.to_string());
        let neg_a = (-proof.a.into_group()).into_affine();
        assert_eq!(neg_a + proof.a, G1Affine::zero());

        let new_f = Bn254::multi_pairing(
            &[sum_ai_abc_gamma, vk.alpha_g1, proof.c, neg_a],
            &[vk.gamma_g2, vk.beta_g2, vk.delta_g2, proof.b],
        );

        let one_g1 = <<Bn254 as Pairing>::G1 as Group>::generator();
        let one_g2 = <<Bn254 as Pairing>::G2 as Group>::generator();
        let a = -one_g1.mul_bigint([8]).into_affine();
        let b = one_g2.mul_bigint([10]).into_affine();
        let c = one_g1.mul_bigint([2]).into_affine();
        let d = one_g2.mul_bigint([3]).into_affine();
        let e = one_g1.mul_bigint([4]).into_affine();
        let f = one_g2.mul_bigint([5]).into_affine();
        let g = one_g1.mul_bigint([6]).into_affine();
        let h = one_g2.mul_bigint([9]).into_affine();
        let ans1 = Bn254::multi_pairing(&[a, c, e, g], &[b, d, f, h]);
        assert_eq!(ans1, PairingOutput::<Bn254>::zero());

        // assert_eq!(new_f, PairingOutput::<Bn254>::zero());

        let q_prepared = [d.into(), f.into(), h.into()].to_vec();

        // let f = Bn254::multi_miller_loop(
        //     [sum_ai_abc_gamma, vk.alpha_g1, proof.c, neg_a],
        //     [vk.gamma_g2, vk.beta_g2, vk.delta_g2, proof.b],
        // );
        let f = Bn254::multi_miller_loop([c, e, g, a], [d, f, h, b]);
        let final_f = Bn254::final_exponentiation(f).unwrap();
        println!("final_f: {}", final_f.to_string());
        let f = f.0;
        let (c, wi) = compute_c_wi(f);
        let c_inv = c.inverse().unwrap();

        let hint = if sign {
            f * wi * (c_inv.pow(exp.to_u64_digits()))
        } else {
            f * wi * (c_inv.pow(exp.to_u64_digits()).inverse().unwrap())
        };

        let quad_miller_loop_with_c_wi = Pairing2::quad_miller_loop_with_c_wi(&q_prepared);

        let p2 = vk.alpha_g1;
        let p3 = proof.c;
        let p4 = neg_a;
        let q4 = proof.b;

        let t4 = q4.into_group();

        script! {
            { Fq::push_u32_le(&BigUint::from_str("21575463638280843010398324269430826099269044274347216827212613867836435027261").unwrap().to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from_str("10307601595873709700152284273816112264069230130616436755625194854815875713954").unwrap().to_u32_digits()) }

            { Fq::push_u32_le(&BigUint::from_str("2821565182194536844548159561693502659359617185244120367078079554186484126554").unwrap().to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from_str("3505843767911556378687030309984248845540243509899259641013678093033130930403").unwrap().to_u32_digits()) }

            { Fq::push_u32_le(&BigUint::from_str("21888242871839275220042445260109153167277707414472061641714758635765020556616").unwrap().to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from_str("0").unwrap().to_u32_digits()) }

            { Fq::push_u32_le(&BigUint::from(ark_bn254::Fq::one().double().inverse().unwrap()).to_u32_digits()) }

            { Fq::push_u32_le(&BigUint::from(ark_bn254::g2::Config::COEFF_B.c0).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(ark_bn254::g2::Config::COEFF_B.c1).to_u32_digits()) }

            // calculate p1 with msm
            { msm_script }
            { Fq::push_u32_le(&BigUint::from(p2.x).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(p2.y).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(p3.x).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(p3.y).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(p4.x).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(p4.y).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(q4.x.c0).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(q4.x.c1).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(q4.y.c0).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(q4.y.c1).to_u32_digits()) }
            { fq12_push(c) }
            { fq12_push(c_inv) }
            { fq12_push(wi) }

            { Fq::push_u32_le(&BigUint::from(t4.x.c0).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(t4.x.c1).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(t4.y.c0).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(t4.y.c1).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(t4.z.c0).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(t4.z.c1).to_u32_digits()) }

            { quad_miller_loop_with_c_wi.clone() }
            { fq12_push(hint) }
            { Fq12::equalverify() }
            OP_TRUE
        }
    }
}

#[cfg(test)]
mod test {
    use crate::execute_script;
    use crate::groth16::verifier::Verifier;
    use ark_bn254::Bn254;
    use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
    use ark_ec::pairing::Pairing;
    use ark_ff::Field;
    use ark_groth16::{prepare_verifying_key, Groth16};
    use ark_relations::lc;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
    use ark_std::{test_rng, UniformRand};
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

        // let a = <E as Pairing>::ScalarField::rand(&mut rng);
        // let b = <E as Pairing>::ScalarField::rand(&mut rng);
        let a = <E as Pairing>::ScalarField::ONE;
        let b = <E as Pairing>::ScalarField::ONE;
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

        let script = Verifier::verify_proof(&vec![c], &proof, &vk);
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }
}
