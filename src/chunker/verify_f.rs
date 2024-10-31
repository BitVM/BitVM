use super::{assigner::BCAssigner, segment::Segment};
use super::elements::Fq12Type;

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


pub fn verify_f<T: BCAssigner>(
    assigner: &mut T,
    prefix: &str,
    pa:Fq12Type,
    public_inputs: &Vec<<Bn254 as ark_Pairing>::ScalarField>,
    proof: &Proof<Bn254>,
    vk: &VerifyingKey<Bn254>,
) -> Vec<Segment> {
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
    let segment = Segment::new_with_name(format!("{}verify_f",prefix), script)
    .add_parameter(&pa);

    segments.push(segment);
    segments
}
