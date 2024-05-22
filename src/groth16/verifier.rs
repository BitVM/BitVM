use std::str::FromStr;

use ark_bn254::{Bn254, Fq2, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::{
    bn::{Bn, BnConfig, G2Prepared},
    pairing::{Pairing, PairingOutput},
    short_weierstrass::{Projective, SWCurveConfig},
    AffineRepr, CurveGroup, Group, VariableBaseMSM,
};
use ark_ff::{Field, One, QuadExtField, Zero};
use ark_groth16::{PreparedVerifyingKey, Proof, VerifyingKey};
use num_bigint::BigUint;
use num_traits::Num;

use crate::{
    bn254::{
        self, fp254impl::Fp254Impl, fq::Fq, fq12::Fq12, msm::msm, pairing::Pairing as Pairing2,
    },
    groth16::checkpairing_with_c_wi_groth16::{compute_c_wi, fq12_push},
    treepp::{pushable, script, Script},
};

#[derive(Clone, Copy, Debug)]
pub struct Verifier;

fn g1_affine_push(point: ark_bn254::G1Affine) -> Script {
    script! {
        { Fq::push_u32_le(&BigUint::from(point.x).to_u32_digits()) }
        { Fq::push_u32_le(&BigUint::from(point.y).to_u32_digits()) }
    }
}

impl Verifier {
    pub fn verify_proof(
        public_inputs: &Vec<<Bn254 as Pairing>::ScalarField>,
        proof: &Proof<Bn254>,
        vk: &VerifyingKey<Bn254>,
        pvk: &PreparedVerifyingKey<Bn<ark_bn254::Config>>,
    ) -> Script {
        let (msm_script, msm_g1) = Self::prepare_inputs(public_inputs, vk);
        script! {
            { Self::verify_proof_with_prepared_inputs(proof, vk, pvk, msm_script, msm_g1) }
        }
    }

    pub fn verify_proof2(
        proof: &Proof<Bn254>,
        vk: &VerifyingKey<Bn254>,
        pvk: &PreparedVerifyingKey<Bn<ark_bn254::Config>>,
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

        let ell_coeffsss: Vec<(ark_bn254::Fq2, ark_bn254::Fq2, ark_bn254::Fq2)> = pvk
            .delta_g2_neg_pc
            .ell_coeffs
            .iter()
            .map(|f| {
                let f1: ark_bn254::Fq2 = f.0;
                let f2: ark_bn254::Fq2 = f.1;
                let f3: ark_bn254::Fq2 = f.2;
                (f1, f2, f3)
            })
            .collect();
        let delta_g2_neg_pc: crate::bn254::ell_coeffs::G2Prepared =
            crate::bn254::ell_coeffs::G2Prepared {
                ell_coeffs: ell_coeffsss,
            };

        let q_prepared = [delta_g2_neg_pc].to_vec();

        let a = [
            proof.c.into(),
            <G1Affine as Into<<Bn254 as Pairing>::G1Prepared>>::into(proof.a),
        ];

        let b = [pvk.delta_g2_neg_pc.clone(), proof.b.into()];

        let final_hint = Bn254::multi_pairing(a.clone(), b.clone());

        let qap = Bn254::multi_miller_loop(a, b);
        let f = qap.0;
        let (c, wi) = compute_c_wi(f);
        let c_inv = c.inverse().unwrap();

        let hint = if sign {
            f * wi * (c_inv.pow(exp.to_u64_digits()))
        } else {
            f * wi * (c_inv.pow(exp.to_u64_digits()).inverse().unwrap())
        };

        let dual_miller_loop_with_c_wi_non_fixed =
            Pairing2::dual_miller_loop_with_c_wi_with_non_fixed(&q_prepared);

        let p3 = proof.c;
        let p4 = proof.a;
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

            { dual_miller_loop_with_c_wi_non_fixed.clone() }
            // { fq12_push(hint) }
            { fq12_push(final_hint.0) }
            { Fq12::equalverify() }
            OP_TRUE
        }
    }

    pub fn prepare_inputs(
        public_inputs: &Vec<<Bn254 as Pairing>::ScalarField>,
        vk: &VerifyingKey<Bn254>,
    ) -> (Script, Projective<ark_bn254::g1::Config>) {
        let sum_ai_abc_gamma =
            G1Projective::msm(&vk.gamma_abc_g1, &public_inputs).expect("failed to calculate msm");
        (msm(&vk.gamma_abc_g1, &public_inputs), sum_ai_abc_gamma)
    }

    pub fn verify_proof_with_prepared_inputs(
        proof: &Proof<Bn254>,
        vk: &VerifyingKey<Bn254>,
        pvk: &PreparedVerifyingKey<Bn<ark_bn254::Config>>,
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

        let beta_prepared: G2Prepared<ark_bn254::Config> = (-vk.beta_g2).into();
        let ell_coeffsss: Vec<(ark_bn254::Fq2, ark_bn254::Fq2, ark_bn254::Fq2)> = beta_prepared
            .ell_coeffs
            .iter()
            .map(|f| {
                let f1: ark_bn254::Fq2 = f.0;
                let f2: ark_bn254::Fq2 = f.1;
                let f3: ark_bn254::Fq2 = f.2;
                (f1, f2, f3)
            })
            .collect();
        let beta_prepared: crate::bn254::ell_coeffs::G2Prepared =
            crate::bn254::ell_coeffs::G2Prepared {
                ell_coeffs: ell_coeffsss,
            };

        let ell_coeffsss: Vec<(ark_bn254::Fq2, ark_bn254::Fq2, ark_bn254::Fq2)> = pvk
            .gamma_g2_neg_pc
            .ell_coeffs
            .iter()
            .map(|f| {
                let f1: ark_bn254::Fq2 = f.0;
                let f2: ark_bn254::Fq2 = f.1;
                let f3: ark_bn254::Fq2 = f.2;
                (f1, f2, f3)
            })
            .collect();
        let gamma_g2_neg_pc: crate::bn254::ell_coeffs::G2Prepared =
            crate::bn254::ell_coeffs::G2Prepared {
                ell_coeffs: ell_coeffsss,
            };

        let ell_coeffsss: Vec<(ark_bn254::Fq2, ark_bn254::Fq2, ark_bn254::Fq2)> = pvk
            .delta_g2_neg_pc
            .ell_coeffs
            .iter()
            .map(|f| {
                let f1: ark_bn254::Fq2 = f.0;
                let f2: ark_bn254::Fq2 = f.1;
                let f3: ark_bn254::Fq2 = f.2;
                (f1, f2, f3)
            })
            .collect();
        let delta_g2_neg_pc: crate::bn254::ell_coeffs::G2Prepared =
            crate::bn254::ell_coeffs::G2Prepared {
                ell_coeffs: ell_coeffsss,
            };

        let q_prepared = [gamma_g2_neg_pc, delta_g2_neg_pc, beta_prepared].to_vec();

        let sum_ai_abc_gamma: G1Affine = msm_g1.into();

        let a = [
            sum_ai_abc_gamma.into(),
            proof.c.into(),
            vk.alpha_g1.into(),
            <G1Affine as Into<<Bn254 as Pairing>::G1Prepared>>::into(proof.a),
        ];

        let b = [
            pvk.gamma_g2_neg_pc.clone(),
            pvk.delta_g2_neg_pc.clone(),
            (-vk.beta_g2).into(),
            proof.b.into(),
        ];

        let qap = Bn254::multi_miller_loop(a, b);
        let f = qap.0;
        let (c, wi) = compute_c_wi(f);
        let c_inv = c.inverse().unwrap();

        let hint = if sign {
            f * wi * (c_inv.pow(exp.to_u64_digits()))
        } else {
            f * wi * (c_inv.pow(exp.to_u64_digits()).inverse().unwrap())
        };

        assert_eq!(hint, c.pow(p_pow3.to_u64_digits()));

        println!("hint is correct!\n\n");

        // let quad_miller_loop_with_c_wi = Pairing2::quad_miller_loop_with_c_wi(&q_prepared);

        let p2 = proof.c;
        let p3 = vk.alpha_g1;
        let p4 = proof.a;
        let q4 = proof.b;

        let t4 = q4.into_group();

        script! {
            // { Fq::push_u32_le(&BigUint::from_str("21575463638280843010398324269430826099269044274347216827212613867836435027261").unwrap().to_u32_digits()) }
            // { Fq::push_u32_le(&BigUint::from_str("10307601595873709700152284273816112264069230130616436755625194854815875713954").unwrap().to_u32_digits()) }

            // { Fq::push_u32_le(&BigUint::from_str("2821565182194536844548159561693502659359617185244120367078079554186484126554").unwrap().to_u32_digits()) }
            // { Fq::push_u32_le(&BigUint::from_str("3505843767911556378687030309984248845540243509899259641013678093033130930403").unwrap().to_u32_digits()) }

            // { Fq::push_u32_le(&BigUint::from_str("21888242871839275220042445260109153167277707414472061641714758635765020556616").unwrap().to_u32_digits()) }
            // { Fq::push_u32_le(&BigUint::from_str("0").unwrap().to_u32_digits()) }

            // { Fq::push_u32_le(&BigUint::from(ark_bn254::Fq::one().double().inverse().unwrap()).to_u32_digits()) }

            // { Fq::push_u32_le(&BigUint::from(ark_bn254::g2::Config::COEFF_B.c0).to_u32_digits()) }
            // { Fq::push_u32_le(&BigUint::from(ark_bn254::g2::Config::COEFF_B.c1).to_u32_digits()) }

            // calculate p1 with msm
            { msm_script }
            { Fq::push_u32_le(&BigUint::from(msm_g1.x).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(msm_g1.y).to_u32_digits()) }
            { g1_affine_push(msm_g1.into_affine()) }
            { bn254::fq2::Fq2::equalverify() }
            // { Fq::push_u32_le(&BigUint::from(p2.x).to_u32_digits()) }
            // { Fq::push_u32_le(&BigUint::from(p2.y).to_u32_digits()) }
            // { Fq::push_u32_le(&BigUint::from(p3.x).to_u32_digits()) }
            // { Fq::push_u32_le(&BigUint::from(p3.y).to_u32_digits()) }
            // { Fq::push_u32_le(&BigUint::from(p4.x).to_u32_digits()) }
            // { Fq::push_u32_le(&BigUint::from(p4.y).to_u32_digits()) }
            // { Fq::push_u32_le(&BigUint::from(q4.x.c0).to_u32_digits()) }
            // { Fq::push_u32_le(&BigUint::from(q4.x.c1).to_u32_digits()) }
            // { Fq::push_u32_le(&BigUint::from(q4.y.c0).to_u32_digits()) }
            // { Fq::push_u32_le(&BigUint::from(q4.y.c1).to_u32_digits()) }
            // { fq12_push(c) }
            // { fq12_push(c_inv) }
            // { fq12_push(wi) }

            // { Fq::push_u32_le(&BigUint::from(t4.x.c0).to_u32_digits()) }
            // { Fq::push_u32_le(&BigUint::from(t4.x.c1).to_u32_digits()) }
            // { Fq::push_u32_le(&BigUint::from(t4.y.c0).to_u32_digits()) }
            // { Fq::push_u32_le(&BigUint::from(t4.y.c1).to_u32_digits()) }
            // { Fq::push_u32_le(&BigUint::from(t4.z.c0).to_u32_digits()) }
            // { Fq::push_u32_le(&BigUint::from(t4.z.c1).to_u32_digits()) }

            // { quad_miller_loop_with_c_wi.clone() }
            // { fq12_push(hint) }
            // { Fq12::equalverify() }
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

        let start = start_timer!(|| "collect_script");
        let script = Verifier::verify_proof(
            &vec![<E as Pairing>::ScalarField::ONE, c],
            &proof,
            &vk,
            &pvk,
        );
        end_timer!(start);

        println!("groth16::test_verify_proof = {} bytes", script.len());

        let start = start_timer!(|| "execute_script");
        let exec_result = execute_script(script);
        end_timer!(start);

        assert!(exec_result.success);
    }

    #[test]
    fn test_verify_proof2() {
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

        let a = [proof.c, proof.a];
        let b = [pvk.clone().delta_g2_neg_pc, proof.clone().b.into()];
        let ans1 = <E as Pairing>::multi_pairing(a.clone(), b.clone());
        let ans2 =
            <E as Pairing>::final_exponentiation(<E as Pairing>::multi_miller_loop(a, b)).unwrap();
        assert_eq!(ans1, ans2);

        let start = start_timer!(|| "collect_script");
        let script = Verifier::verify_proof2(&proof, &vk, &pvk);
        end_timer!(start);

        println!("groth16::test_verify_proof = {} bytes", script.len());

        let start = start_timer!(|| "execute_script");
        let exec_result = execute_script(script);
        end_timer!(start);

        assert!(exec_result.success);
    }
}
