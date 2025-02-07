use std::ops::Neg;

use ark_bn254::{Bn254};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use bitcoin_script::script;

use crate::{chunk::{primitives::HashBytes, segment::*}, groth16::g16::{Assertions, Signatures, N_VERIFIER_FQS, N_VERIFIER_HASHES, N_VERIFIER_PUBLIC_INPUTS}};


use super::{api::nib_to_byte_array, assert::Pubs, compile::{NUM_PUBS, NUM_U160, NUM_U256}, element::*};



pub(crate) fn hint_to_data(segments: Vec<Segment>) -> Assertions {
    let mut vs: Vec<[u8; 64]> = vec![];
    for v in segments {
        if v.is_validation {
            continue;
        }
        let x = v.result.0.hashed_output();
        vs.push(x);
    }
    let mut batch1 = vec![];
    for i in 0..NUM_PUBS {
        let val = vs[i];
        let bal: [u8; 32] = nib_to_byte_array(&val).try_into().unwrap();
        batch1.push(bal);
    }
    let batch1: [[u8; 32]; NUM_PUBS] = batch1.try_into().unwrap();

    let len = batch1.len();
    let mut batch2 = vec![];
    for i in 0..NUM_U256 {
        let val = vs[i + len];
        let bal: [u8; 32] = nib_to_byte_array(&val).try_into().unwrap();
        batch2.push(bal);
    }
    let batch2: [[u8; 32]; N_VERIFIER_FQS] = batch2.try_into().unwrap();

    let len = batch1.len() + batch2.len();
    let mut batch3 = vec![];
    for i in 0..NUM_U160 {
        let val = vs[i+len];
        let bal: [u8; 32] = nib_to_byte_array(&val).try_into().unwrap();
        let bal: [u8; 20] = bal[12..32].try_into().unwrap();
        batch3.push(bal);
    }
    let batch3: [[u8; 20]; N_VERIFIER_HASHES] = batch3.try_into().unwrap();

    (batch1, batch2, batch3)
}

pub(crate) type TypedAssertions = (
    [ark_bn254::Fr; N_VERIFIER_PUBLIC_INPUTS],
    [ark_bn254::Fq; N_VERIFIER_FQS],
    [HashBytes; N_VERIFIER_HASHES],
);

pub(crate) type Intermediates = Vec<HashBytes>;
pub(crate) fn get_proof(asserts: &TypedAssertions) -> InputProof { // EvalIns
    let numfqs = asserts.1;
    let p4 = ark_bn254::G1Affine::new_unchecked(numfqs[1], numfqs[0]);
    let p2 = ark_bn254::G1Affine::new_unchecked(numfqs[3], numfqs[2]);
    let step = 4;
    let c = ark_bn254::Fq6::new(
        ark_bn254::Fq2::new(numfqs[step+0], numfqs[step+1]),
        ark_bn254::Fq2::new(numfqs[step+2], numfqs[step+3]),
        ark_bn254::Fq2::new(numfqs[step+4], numfqs[step+5]),
        );       
    let step = step + 6;
    let s = ark_bn254::Fq6::new(
        ark_bn254::Fq2::new(numfqs[step+0], numfqs[step+1]),
        ark_bn254::Fq2::new(numfqs[step+2], numfqs[step+3]),
        ark_bn254::Fq2::new(numfqs[step+4], numfqs[step+5]),
    );

    let step = step + 6;
    let q4 = ark_bn254::G2Affine::new_unchecked(ark_bn254::Fq2::new(numfqs[step + 0], numfqs[step + 1]), ark_bn254::Fq2::new(numfqs[step + 2], numfqs[step + 3]));

    let eval_ins: InputProof = InputProof { p2, p4, q4, c, s, ks: asserts.0.to_vec() };
    eval_ins
}

pub(crate) fn get_intermediates(asserts: &TypedAssertions) -> Intermediates { // Intermediates
    let mut hashes= asserts.2.to_vec();
    hashes.reverse();
    hashes
}

pub(crate) fn get_assertions(signed_asserts: Signatures) -> TypedAssertions {
    let mut ks: Vec<ark_bn254::Fr> = vec![];
    for i in 0..N_VERIFIER_PUBLIC_INPUTS {
        let sc = signed_asserts.0[i];
        let nibs = sc.map(|(_, digit)| digit);
        let mut nibs = nibs[0..64]
        .chunks(2)
        .rev()
        .map(|bn| (bn[1] << 4) + bn[0])
        .collect::<Vec<u8>>();
        nibs.reverse();
        let fr =  ark_bn254::Fr::from_le_bytes_mod_order(&nibs);
        ks.push(fr);
    }

    let mut numfqs: Vec<ark_bn254::Fq> = vec![];
    for i in 0..N_VERIFIER_FQS {
        let sc = signed_asserts.1[i];
        let nibs = sc.map(|(_, digit)| digit);
        let mut nibs = nibs[0..64]
        .chunks(2)
        .rev()
        .map(|bn| (bn[1] << 4) + bn[0])
        .collect::<Vec<u8>>();
        nibs.reverse();
        let fq =  ark_bn254::Fq::from_le_bytes_mod_order(&nibs);
        numfqs.push(fq);
    }

    let mut numhashes: Vec<HashBytes> = vec![];
    for i in 0..N_VERIFIER_HASHES {
        let sc = signed_asserts.2[i];
        let nibs = sc.map(|(_, digit)| digit);
        let mut nibs = nibs[0..40].to_vec();
        nibs.reverse();
        let nibs: [u8; 40] = nibs.try_into().unwrap();
        let mut padded_nibs = [0u8; 64]; // initialize with zeros
        padded_nibs[24..64].copy_from_slice(&nibs[0..40]);
        numhashes.push(padded_nibs);
    }
    (ks.try_into().unwrap(), numfqs.try_into().unwrap(), numhashes.try_into().unwrap())
}

pub(crate) fn get_pubs(vk: &ark_groth16::VerifyingKey<Bn254>) -> Pubs {
    let mut msm_gs = vk.gamma_abc_g1.clone(); // vk.vk_pubs[0]
    msm_gs.reverse();
    let vky0 = msm_gs.pop().unwrap();

    let (q3, q2, q1) = (
        vk.gamma_g2.into_group().neg().into_affine(),
        vk.delta_g2.into_group().neg().into_affine(),
        -vk.beta_g2,
    );
    let fixed_acc = Bn254::multi_miller_loop_affine([vk.alpha_g1], [q1]).0;
    
    let pubs: Pubs = Pubs { q2, q3, fixed_acc: fixed_acc.c1/fixed_acc.c0, ks_vks: msm_gs.clone(), vky0 };
    pubs
}

pub(crate) fn raw_input_proof_to_segments(eval_ins: InputProofRaw, all_output_hints: &mut Vec<Segment>) -> ([Segment;2], [Segment;2], [Segment;4], [Segment;6], [Segment;6], [Segment;NUM_PUBS]) {
    let pub_scalars: Vec<Segment> = eval_ins.ks.iter().enumerate().map(|(idx, f)| Segment {
        is_validation: false,
        id: (all_output_hints.len() + idx) as u32,
        parameter_ids: vec![],
        result: (Element::U256(*f), ElementType::ScalarElem),
        hints: vec![],
        scr_type: ScriptType::NonDeterministic,
        scr: script!(),
    }).collect();
    all_output_hints.extend_from_slice(&pub_scalars);

    let p4vec: Vec<Segment> = vec![
        eval_ins.p4[1], eval_ins.p4[0], eval_ins.p2[1], eval_ins.p2[0]
    ].iter().enumerate().map(|(idx, f)| Segment {
        id: (all_output_hints.len() + idx) as u32,
        is_validation: false,
        parameter_ids: vec![],
        result: (Element::U256(*f), ElementType::FieldElem),
        hints: vec![],
        scr_type: ScriptType::NonDeterministic,
        scr: script!(),
    }).collect();
    all_output_hints.extend_from_slice(&p4vec);
    let (gp4y, gp4x, gp2y, gp2x) = (&p4vec[0], &p4vec[1], &p4vec[2], &p4vec[3]);

    let gc: Vec<Segment> = eval_ins.c.iter().enumerate().map(|(idx, f)| Segment {
        id: (all_output_hints.len() + idx) as u32,
        is_validation: false,
        parameter_ids: vec![],
        result: (Element::U256(*f), ElementType::FieldElem),
        hints: vec![],
        scr_type: ScriptType::NonDeterministic,
        scr: script!(),
    }).collect();
    all_output_hints.extend_from_slice(&gc);

    let gs: Vec<Segment> = eval_ins.s.iter().enumerate().map(|(idx, f)| Segment {
        id: (all_output_hints.len() + idx) as u32,
        is_validation: false,
        parameter_ids: vec![],
        result: (Element::U256(*f), ElementType::FieldElem),
        hints: vec![],
        scr_type: ScriptType::NonDeterministic,
        scr: script!(),
    }).collect();
    all_output_hints.extend_from_slice(&gs);

    let temp_q4: Vec<Segment> = vec![
        eval_ins.q4[0], eval_ins.q4[1], eval_ins.q4[2], eval_ins.q4[3]
    ].iter().enumerate().map(|(idx, f)| Segment {
        id: (all_output_hints.len() + idx) as u32,
        is_validation: false,
        parameter_ids: vec![],
        result: (Element::U256(*f), ElementType::FieldElem),
        hints: vec![],
        scr_type: ScriptType::NonDeterministic,
        scr: script!(),
    }).collect();
    all_output_hints.extend_from_slice(&temp_q4);

    ([gp2x.clone(), gp2y.clone()], [gp4x.clone(), gp4y.clone()], temp_q4.try_into().unwrap(), gc.try_into().unwrap(), gs.try_into().unwrap(), pub_scalars.try_into().unwrap())
}
