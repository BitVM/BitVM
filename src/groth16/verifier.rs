use std::str::FromStr;

use ark_bn254::{Bn254, G1Affine, G1Projective, G2Affine};
use ark_ec::{
    bn::{g2::mul_by_char, Bn, BnConfig, G2Prepared},
    pairing::Pairing,
    short_weierstrass::{Projective, SWCurveConfig},
    AffineRepr, CurveGroup, VariableBaseMSM,
};
use ark_ff::{Field, One};
use ark_groth16::{PreparedVerifyingKey, Proof, VerifyingKey};
use num_bigint::BigUint;
use num_traits::Num;

use crate::{
    bn254::{
        ell_coeffs::G2HomProjective, fp254impl::Fp254Impl, fq::Fq, fq12::Fq12, fq6::Fq6, msm::msm,
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
        pvk: &PreparedVerifyingKey<Bn<ark_bn254::Config>>,
    ) -> Script {
        let (msm_script, msm_g1) = Self::prepare_inputs(public_inputs, vk);
        script! {
            { Self::verify_proof_with_prepared_inputs(proof, vk, pvk, msm_script, msm_g1) }
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

        let sum_ai_abc_gamma = msm_g1.into_affine();

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

        println!("before cal hint!!!!\n\n");

        let hint = if sign {
            println!("cal hint in if!!!!\n\n");
            f * wi * (c_inv.pow((exp).to_u64_digits()))
        } else {
            println!("cal hint in else!!!!\n\n");
            f * wi * (c_inv.pow((exp).to_u64_digits()).inverse().unwrap())
        };

        assert_eq!(hint, c.pow(p_pow3.to_u64_digits()));

        println!("hint is correct!\n\n");

        // calculate offchain
        let eval_points = vec![sum_ai_abc_gamma.into(), proof.c.into(), vk.alpha_g1.into()];
        // let p4 = <G1Affine as Into<<Bn254 as Pairing>::G1Prepared>>::into(proof.a);
        let line_beta: G2Prepared<ark_bn254::Config> = (-vk.beta_g2).into();
        let lines = vec![
            pvk.gamma_g2_neg_pc.to_owned(),
            pvk.delta_g2_neg_pc.to_owned(),
            line_beta,
        ];
        let expect_f = Self::quad_miller_loop_with_c_wi_rust(
            eval_points,
            proof.a,
            proof.b.into(),
            &lines,
            c,
            c_inv,
            wi,
        );

        println!("expect_res: {}", expect_f);

        let quad_miller_loop_with_c_wi = Pairing2::quad_miller_loop_with_c_wi(&q_prepared);

        let p2 = proof.c;
        let p3 = vk.alpha_g1;
        let p4 = proof.a;
        let q4 = proof.b;

        let t4 = G2HomProjective {
            x: q4.x,
            y: q4.y,
            z: ark_bn254::Fq2::one(),
        };

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

    pub fn quad_miller_loop_with_c_wi_rust(
        eval_points: Vec<G1Affine>,
        P4: G1Affine,
        Q4: G2Affine,
        // lines: &[Vec<(Fq2, Fq2)>],
        lines: &Vec<G2Prepared<ark_bn254::Config>>,
        c: ark_bn254::Fq12,
        c_inv: ark_bn254::Fq12,
        wi: ark_bn254::Fq12,
        // TODO: What's B in stack
    ) -> ark_bn254::Fq12 {
        assert_eq!(eval_points.len(), 3, "Should contains 4 G1Affine: P1,P2,P3");
        assert_eq!(lines.len(), 3, "Only precompute lines for Q1,Q2,Q3");
        assert_eq!(c * c_inv, ark_bn254::Fq12::ONE, "Check if c·c^−1 = 1");

        // let P4 = eval_points[3].clone();
        // let Q4_projective: G2Projective = Q4.into_group();
        let mut T4 = ark_ec::bn::g2::G2HomProjective::<ark_bn254::Config> {
            x: Q4.x,
            y: Q4.y,
            z: ark_bn254::Fq2::one(),
        };

        // constants
        let two_inv = ark_bn254::Fq::one().double().inverse().unwrap();

        // 1. f = c_inv
        let mut f = c_inv;
        println!("1.f: {:?}", f.to_string());

        let mut lines_iters = lines
            .iter()
            .map(|item| item.ell_coeffs.iter())
            .collect::<Vec<_>>();

        // 2. miller loop part, 6x + 2
        for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
            // for i in 4..9 {
            let bit = ark_bn254::Config::ATE_LOOP_COUNT[i - 1];

            // 2.1 double: f = f * f
            f = f.square();

            // 2.2 mul c
            //  f = f * c_inv, if digit == 1
            //  f = f * c, if digit == -1
            f = if 1 == bit {
                f * c_inv
            } else if bit == -1 {
                f * c
            } else if bit == 0 {
                f
            } else {
                panic!("bit is not in (-1,1), bit={bit}");
            };

            // 2.3 accumulate double lines (fixed and non-fixed)
            // 2.3.1(fixed) f = f * double_line_Q(P). fixed points: P1, P2, P3
            for (line_i, pi) in lines_iters.iter_mut().zip(eval_points.iter()) {
                let line_i_0 = line_i.next().unwrap();
                Bn254::ell(&mut f, line_i_0, pi);
            }

            // 2.3.2(non-fixed) double line with T4 (projective coordinates)
            let double_line = T4.double_in_place(&two_inv); // TODO: check if the param is 1/2

            // 2.3.3(non-fixed) evaluation double_line. non-fixed points: P4
            Bn254::ell(&mut f, &double_line, &P4);

            if bit == 1 || bit == -1 {
                // 2.4 accumulate add lines (fixed and non-fixed)
                // 2.4.1(fixed) f = f * add_line_eval. fixed points: P1, P2, P3
                for (line_i, pi) in lines_iters.iter_mut().zip(eval_points.iter()) {
                    let line_i_1 = line_i.next().unwrap();
                    Bn254::ell(&mut f, line_i_1, pi);
                }
                // 2.4.2(non-fixed) double line with T4 (projective coordinates)
                let add_line = if bit == 1 {
                    T4.add_in_place(&Q4)
                } else {
                    // }else if bit == -1 {
                    let mut neg_q4 = Q4.clone();
                    neg_q4.y.neg_in_place();
                    T4.add_in_place(&neg_q4)
                };

                // 2.4.3(non-fixed) evaluation double_line. non-fixed points: P4
                Bn254::ell(&mut f, &add_line, &P4);
            }
        }
        println!("2.f: {:?}", f.to_string());

        // 3. f = f * c_inv^p * c^{p^2}
        let MODULUS_STR: &str = "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47";
        let MODULUS: BigUint = BigUint::from_str_radix(MODULUS_STR, 16).unwrap();
        f = f * c_inv.pow(MODULUS.to_u64_digits()) * c.pow(MODULUS.pow(2).to_u64_digits());
        println!("3.f: {:?}", f.to_string());

        // // 4. f = f * wi . scale f
        // f = f * wi;
        // println!("4.f: {:?}", f.to_string());

        // // 5 add lines (fixed and non-fixed)
        // // 5.1(fixed) f = f * add_line_eval. fixed points: P1, P2, P3
        // for (line_i, pi) in lines_iters.iter_mut().zip(eval_points.iter()) {
        //     let line_i_1 = line_i.next().unwrap();
        //     Bn254::ell(&mut f, line_i_1, pi);
        // }
        // // 5.2 one-time frobenius map to compute phi_Q
        // //     compute phi(Q) with Q4
        // let phi_Q = mul_by_char::<ark_bn254::Config>(Q4.clone());

        // let add_line = T4.add_in_place(&phi_Q);

        // // 5.4(non-fixed) evaluation add_lin. non-fixed points: P4
        // Bn254::ell(&mut f, &add_line, &P4);
        // println!("5.f: {:?}", f.to_string());

        // // 6. add lines (fixed and non-fixed)
        // // 6.1(fixed) f = f * add_line_eval. fixed points: P1, P2, P3
        // for (line_i, pi) in lines_iters.iter_mut().zip(eval_points.iter()) {
        //     // TODO: where is f?? and where is double line?
        //     let line_i_1 = line_i.next().unwrap();
        //     Bn254::ell(&mut f, line_i_1, pi);
        // }
        // // 6.2 two-time frobenius map to compute phi_Q
        // //     compute phi_Q_2 with phi_Q
        // // mul_by_char: used to q's frob...map.
        // let mut phi_Q_2 = mul_by_char::<ark_bn254::Config>(phi_Q.clone());
        // phi_Q_2.y.neg_in_place();
        // let add_line = T4.add_in_place(&phi_Q_2);
        // println!("6.2.f: {:?}", f.to_string());

        // // 6.3(non-fixed) evaluation add_lin. non-fixed points: P4
        // Bn254::ell(&mut f, &add_line, &P4);
        // println!("6.3.f: {:?}", f.to_string());

        f
    }
}

#[cfg(test)]
mod test {
    use crate::execute_script;
    use crate::groth16::verifier::Verifier;
    use crate::{
        bn254::{fp254impl::Fp254Impl, fq::Fq},
        treepp::{pushable, script},
    };
    use ark_bn254::Bn254;
    use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
    use ark_ec::pairing::Pairing;
    use ark_ff::Field;
    use ark_groth16::{prepare_verifying_key, Groth16};
    use ark_relations::lc;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
    use ark_std::{end_timer, start_timer, test_rng};
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
}
