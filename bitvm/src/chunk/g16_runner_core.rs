use crate::chunk::{
    elements::CompressedStateObject, g16_runner_utils::*, taps_point_ops::frob_q_power,
};
use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField};
use bitcoin::ScriptBuf;

use super::{
    api::NUM_PUBS,
    api_compiletime_utils::ATE_LOOP_COUNT,
    elements::{DataType, ElementType, HashBytes},
};

#[derive(Debug)]
pub struct PublicParams {
    pub q2: ark_bn254::G2Affine,
    pub q3: ark_bn254::G2Affine,
    pub fixed_acc: ark_bn254::Fq6, // precomputable fp12 accumulator from fixed pairing arguments
    pub ks_vks: Vec<ark_bn254::G1Affine>,
    pub vky0: ark_bn254::G1Affine,
}

#[derive(Debug)]
pub(crate) struct InputProof {
    pub(crate) p2: ark_bn254::G1Affine,
    pub(crate) p4: ark_bn254::G1Affine,
    pub(crate) q4: ark_bn254::G2Affine,
    pub(crate) c: ark_bn254::Fq6,
    pub(crate) ks: Vec<ark_bn254::Fr>,
}

impl InputProof {
    pub(crate) fn to_raw(&self) -> InputProofRaw {
        let p2x = self.p2.x.into_bigint();
        let p2y = self.p2.y.into_bigint();
        let p4x = self.p4.x.into_bigint();
        let p4y = self.p4.y.into_bigint();
        let q4x0 = self.q4.x.c0.into_bigint();
        let q4x1 = self.q4.x.c1.into_bigint();
        let q4y0 = self.q4.y.c0.into_bigint();
        let q4y1 = self.q4.y.c1.into_bigint();
        let c: Vec<ark_ff::BigInt<4>> = self
            .c
            .to_base_prime_field_elements()
            .map(|f| f.into_bigint())
            .collect();
        let ks: Vec<ark_ff::BigInt<4>> = self.ks.iter().map(|f| f.into_bigint()).collect();

        InputProofRaw {
            p2: [p2x, p2y],
            p4: [p4x, p4y],
            q4: [q4x0, q4x1, q4y0, q4y1],
            c: c.try_into().unwrap(),
            ks: ks.try_into().unwrap(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct InputProofRaw {
    pub(crate) p2: [ark_ff::BigInt<4>; 2],
    pub(crate) p4: [ark_ff::BigInt<4>; 2],
    pub(crate) q4: [ark_ff::BigInt<4>; 4],
    pub(crate) c: [ark_ff::BigInt<4>; 6],
    pub(crate) ks: [ark_ff::BigInt<4>; NUM_PUBS],
}

fn compare(hint_out: &DataType, claimed_assertions: &mut Option<Vec<HashBytes>>) -> Option<bool> {
    if claimed_assertions.is_none() {
        return None;
    }
    assert!(!hint_out.output_is_field_element());

    let hint_out_hash = hint_out.to_hash();
    let matches = if let CompressedStateObject::Hash(hash) = hint_out_hash {
        if let Some(claimed_assertions) = claimed_assertions {
            claimed_assertions.pop().unwrap() == hash
        } else {
            unreachable!(); // verified that claimed_assertions is_some()
        }
    } else {
        unreachable!(); // verified that hint_out is hash above
    };

    Some(matches)
}

pub(crate) fn groth16_generate_segments(
    skip_evaluation: bool,
    all_output_hints: &mut Vec<Segment>,
    eval_ins: InputProofRaw,
    pubs: PublicParams,
    claimed_assertions: &mut Option<Vec<HashBytes>>,
) -> bool {
    macro_rules! push_compare_or_return {
        ($seg:ident) => {{
            all_output_hints.push($seg.clone());
            if $seg.scr_type.is_final_script() {
                if let DataType::U256Data(felem) = $seg.result.0 {
                    if felem != ark_ff::BigInt::<4>::one() {
                        println!("Final validity check failed: {:?}", felem);
                        return false;
                    }
                } else {
                    unreachable!();
                }
            } else if $seg.is_valid_input == false {
                println!("Input validity check failed at segment id: {:?}, type: {:?}", $seg.id, $seg.scr_type);
                return false;
            } else {
                let matches = compare(&$seg.result.0, claimed_assertions);
                if matches.is_some() && matches.unwrap() == false {
                    println!("Output validity check failed at segment id: {:?}, type: {:?}", $seg.id, $seg.scr_type);
                    return false;
                }
            }
        }};
    }
    let vky = pubs.ks_vks;
    let vky0 = pubs.vky0;

    let (gp2, gp4, gq4, gc, pub_scalars) = raw_input_proof_to_segments(eval_ins, all_output_hints);
    let (gp2x, gp2y) = (gp2[0].clone(), gp2[1].clone());
    let (gp4x, gp4y) = (gp4[0].clone(), gp4[1].clone());
    let (q4xc0, q4xc1, q4yc0, q4yc1) = (
        gq4[0].clone(),
        gq4[1].clone(),
        gq4[2].clone(),
        gq4[3].clone(),
    );
    let gc = gc.to_vec();

    let pub_scalars = pub_scalars.to_vec();

    // proof.a
    let p4 = wrap_hints_precompute_p(skip_evaluation, all_output_hints.len(), &gp4y, &gp4x);
    push_compare_or_return!(p4);

    // proof.c
    let p2 = wrap_hints_precompute_p(skip_evaluation, all_output_hints.len(), &gp2y, &gp2x);
    push_compare_or_return!(p2);

    let msms = wrap_hint_msm(
        skip_evaluation,
        all_output_hints.len(),
        pub_scalars.clone(),
        vky.clone(),
    );
    for msm in &msms {
        push_compare_or_return!(msm);
    }

    let p_vk0 = wrap_hint_hash_p(
        skip_evaluation,
        all_output_hints.len(),
        &msms[msms.len() - 1],
        vky0,
    );
    push_compare_or_return!(p_vk0);

    let p3 = wrap_hints_precompute_p_from_hash(skip_evaluation, all_output_hints.len(), &p_vk0);
    push_compare_or_return!(p3);

    let c = wrap_hint_hash_c(skip_evaluation, all_output_hints.len(), gc.clone());
    push_compare_or_return!(c);

    let gcinv = wrap_hint_hash_c_inv(skip_evaluation, all_output_hints.len(), gc);
    push_compare_or_return!(gcinv);

    // proof.b
    let mut t4 = wrap_hint_init_t4(
        skip_evaluation,
        all_output_hints.len(),
        &q4yc1,
        &q4yc0,
        &q4xc1,
        &q4xc0,
    );
    push_compare_or_return!(t4);

    let (mut t2, mut t3) = (pubs.q2, pubs.q3);
    let mut f_acc = gcinv.clone();

    for j in (1..ATE_LOOP_COUNT.len()).rev() {
        if !skip_evaluation {
            println!("Processing {:?}-th iteration of Miller Loop", j);
        }
        let ate = ATE_LOOP_COUNT[j - 1];
        let sq = wrap_hint_squaring(skip_evaluation, all_output_hints.len(), &f_acc);
        push_compare_or_return!(sq);
        f_acc = sq;

        t4 = wrap_chunk_point_ops_and_multiply_line_evals_step_1(
            skip_evaluation,
            all_output_hints.len(),
            true,
            None,
            None,
            &t4,
            &p4,
            None,
            &p3,
            t3,
            None,
            &p2,
            t2,
            None,
        );
        push_compare_or_return!(t4);
        (t2, t3) = ((t2 + t2).into_affine(), (t3 + t3).into_affine());

        let lev = wrap_chunk_point_ops_and_multiply_line_evals_step_2(
            skip_evaluation,
            all_output_hints.len(),
            &t4,
        );
        push_compare_or_return!(lev);

        f_acc = wrap_hints_dense_dense_mul(skip_evaluation, all_output_hints.len(), &f_acc, &lev);
        push_compare_or_return!(f_acc);

        if ate == 0 {
            continue;
        }

        let c_or_cinv = if ate == -1 { c.clone() } else { gcinv.clone() };
        f_acc =
            wrap_hints_dense_dense_mul(skip_evaluation, all_output_hints.len(), &f_acc, &c_or_cinv);
        push_compare_or_return!(f_acc);

        t4 = wrap_chunk_point_ops_and_multiply_line_evals_step_1(
            skip_evaluation,
            all_output_hints.len(),
            false,
            Some(false),
            Some(ate),
            &t4,
            &p4,
            Some(gq4.to_vec()),
            &p3,
            t3,
            Some(pubs.q3),
            &p2,
            t2,
            Some(pubs.q2),
        );
        push_compare_or_return!(t4);
        if ate == 1 {
            (t2, t3) = ((t2 + pubs.q2).into_affine(), (t3 + pubs.q3).into_affine());
        } else {
            (t2, t3) = ((t2 - pubs.q2).into_affine(), (t3 - pubs.q3).into_affine());
        }

        let lev = wrap_chunk_point_ops_and_multiply_line_evals_step_2(
            skip_evaluation,
            all_output_hints.len(),
            &t4,
        );
        push_compare_or_return!(lev);

        f_acc = wrap_hints_dense_dense_mul(skip_evaluation, all_output_hints.len(), &f_acc, &lev);
        push_compare_or_return!(f_acc);
    }

    let cp = wrap_hints_frob_fp12(skip_evaluation, all_output_hints.len(), &gcinv, 1);
    push_compare_or_return!(cp);

    let cp2 = wrap_hints_frob_fp12(skip_evaluation, all_output_hints.len(), &c, 2);
    push_compare_or_return!(cp2);

    let cp3 = wrap_hints_frob_fp12(skip_evaluation, all_output_hints.len(), &gcinv, 3);
    push_compare_or_return!(cp3);

    f_acc = wrap_hints_dense_dense_mul(skip_evaluation, all_output_hints.len(), &f_acc, &cp);
    push_compare_or_return!(f_acc);

    f_acc = wrap_hints_dense_dense_mul(skip_evaluation, all_output_hints.len(), &f_acc, &cp2);
    push_compare_or_return!(f_acc);

    f_acc = wrap_hints_dense_dense_mul(skip_evaluation, all_output_hints.len(), &f_acc, &cp3);
    push_compare_or_return!(f_acc);

    t4 = wrap_chunk_point_ops_and_multiply_line_evals_step_1(
        skip_evaluation,
        all_output_hints.len(),
        false,
        Some(true),
        Some(1),
        &t4,
        &p4,
        Some(gq4.to_vec()),
        &p3,
        t3,
        Some(pubs.q3),
        &p2,
        t2,
        Some(pubs.q2),
    );
    push_compare_or_return!(t4);

    let tmp_q2f = frob_q_power(pubs.q2, 1);
    t2 = (t2 + tmp_q2f).into_affine();
    let tmp_q3f = frob_q_power(pubs.q3, 1);
    t3 = (t3 + tmp_q3f).into_affine();
    let lev = wrap_chunk_point_ops_and_multiply_line_evals_step_2(
        skip_evaluation,
        all_output_hints.len(),
        &t4,
    );
    push_compare_or_return!(lev);

    f_acc = wrap_hints_dense_dense_mul(skip_evaluation, all_output_hints.len(), &f_acc, &lev);
    push_compare_or_return!(f_acc);

    t4 = wrap_chunk_point_ops_and_multiply_line_evals_step_1(
        skip_evaluation,
        all_output_hints.len(),
        false,
        Some(true),
        Some(-1),
        &t4,
        &p4,
        Some(gq4.to_vec()),
        &p3,
        t3,
        Some(pubs.q3),
        &p2,
        t2,
        Some(pubs.q2),
    );
    push_compare_or_return!(t4);

    let lev = wrap_chunk_point_ops_and_multiply_line_evals_step_2(
        skip_evaluation,
        all_output_hints.len(),
        &t4,
    );
    push_compare_or_return!(lev);

    f_acc = wrap_hints_dense_dense_mul(skip_evaluation, all_output_hints.len(), &f_acc, &lev);
    push_compare_or_return!(f_acc);

    let valid_facc = wrap_chunk_final_verify(
        skip_evaluation,
        all_output_hints.len(),
        &f_acc,
        &t4,
        gq4.to_vec(),
        pubs.fixed_acc,
    );
    push_compare_or_return!(valid_facc);

    let is_valid: ark_ff::BigInt<4> = valid_facc.result.0.try_into().unwrap();

    is_valid == ark_ff::BigInt::<4>::one()
}

#[allow(clippy::type_complexity)]
fn raw_input_proof_to_segments(
    eval_ins: InputProofRaw,
    all_output_hints: &mut Vec<Segment>,
) -> (
    [Segment; 2],
    [Segment; 2],
    [Segment; 4],
    [Segment; 6],
    [Segment; NUM_PUBS],
) {
    let pub_scalars: Vec<Segment> = eval_ins
        .ks
        .iter()
        .enumerate()
        .map(|(idx, f)| Segment {
            id: (all_output_hints.len() + idx) as u32,
            parameter_ids: vec![],
            is_valid_input: true,
            result: (DataType::U256Data(*f), ElementType::ScalarElem),
            hints: vec![],
            scr_type: ScriptType::NonDeterministic,
            scr: ScriptBuf::new(),
        })
        .collect();
    all_output_hints.extend_from_slice(&pub_scalars);

    let p4vec: Vec<Segment> = [
        eval_ins.p4[1],
        eval_ins.p4[0],
        eval_ins.p2[1],
        eval_ins.p2[0],
    ]
    .iter()
    .enumerate()
    .map(|(idx, f)| Segment {
        id: (all_output_hints.len() + idx) as u32,
        parameter_ids: vec![],
        is_valid_input: true,
        result: (DataType::U256Data(*f), ElementType::FieldElem),
        hints: vec![],
        scr_type: ScriptType::NonDeterministic,
        scr: ScriptBuf::new(),
    })
    .collect();
    all_output_hints.extend_from_slice(&p4vec);
    let (gp4y, gp4x, gp2y, gp2x) = (&p4vec[0], &p4vec[1], &p4vec[2], &p4vec[3]);

    let gc: Vec<Segment> = eval_ins
        .c
        .iter()
        .enumerate()
        .map(|(idx, f)| Segment {
            id: (all_output_hints.len() + idx) as u32,
            parameter_ids: vec![],
            is_valid_input: true,
            result: (DataType::U256Data(*f), ElementType::FieldElem),
            hints: vec![],
            scr_type: ScriptType::NonDeterministic,
            scr: ScriptBuf::new(),
        })
        .collect();
    all_output_hints.extend_from_slice(&gc);

    let temp_q4: Vec<Segment> = [
        eval_ins.q4[0],
        eval_ins.q4[1],
        eval_ins.q4[2],
        eval_ins.q4[3],
    ]
    .iter()
    .enumerate()
    .map(|(idx, f)| Segment {
        id: (all_output_hints.len() + idx) as u32,
        parameter_ids: vec![],
        is_valid_input: true,
        result: (DataType::U256Data(*f), ElementType::FieldElem),
        hints: vec![],
        scr_type: ScriptType::NonDeterministic,
        scr: ScriptBuf::new(),
    })
    .collect();
    all_output_hints.extend_from_slice(&temp_q4);

    (
        [gp2x.clone(), gp2y.clone()],
        [gp4x.clone(), gp4y.clone()],
        temp_q4.try_into().unwrap(),
        gc.try_into().unwrap(),
        pub_scalars.try_into().unwrap(),
    )
}

#[cfg(test)]
mod test {
    use crate::{bn254::ell_coeffs::AffinePairing, chunk::elements::G1AffineIsomorphic};
    use ark_bn254::Bn254;
    use ark_ec::{bn::BnConfig, AffineRepr, CurveGroup};
    use ark_ff::{AdditiveGroup, Field};
    use ark_serialize::CanonicalDeserialize;
    use bitcoin_script::script;
    use num_bigint::BigUint;
    use std::{ops::Neg, str::FromStr};

    use crate::{
        bn254::ell_coeffs::BnAffinePairing,
        chunk::{
            api::NUM_PUBS,
            taps_point_ops::{chunk_point_ops_and_multiply_line_evals_step_1, frob_q_power},
        },
        groth16::offchain_checker::compute_c_wi,
    };

    use super::{groth16_generate_segments, InputProof, PublicParams, Segment};

    #[test]
    fn test_groth16() {
        let vk_bytes = crate::chunk::api_runtime_utils::test::VK_BYTES.to_vec();
        let proof_bytes: Vec<u8> = crate::chunk::api_runtime_utils::test::PROOF_BYTES.to_vec();
        let scalar = crate::chunk::api_runtime_utils::test::PUBLIC_INPUT_BYTES.to_vec();
        let proof: ark_groth16::Proof<Bn254> =
            ark_groth16::Proof::deserialize_uncompressed(&proof_bytes[..]).unwrap();
        let vk: ark_groth16::VerifyingKey<Bn254> =
            ark_groth16::VerifyingKey::deserialize_uncompressed(&vk_bytes[..]).unwrap();
        let scalar: ark_bn254::Fr = ark_bn254::Fr::deserialize_uncompressed(&scalar[..]).unwrap();
        let scalars = [scalar];

        let mut msm_scalar = scalars.to_vec();
        msm_scalar.reverse();
        let mut msm_gs = vk.gamma_abc_g1.clone(); // vk.vk_pubs[0]
        msm_gs.reverse();
        let vky0 = msm_gs.pop().unwrap();

        let mut pp3 = vky0 * ark_bn254::Fr::ONE;
        for i in 0..NUM_PUBS {
            pp3 += msm_gs[i] * msm_scalar[i];
        }
        let p3 = pp3.into_affine();

        let (p2, p1, p4) = (proof.c, vk.alpha_g1, proof.a);
        let (q3, q2, q1, q4) = (
            vk.gamma_g2.into_group().neg().into_affine(),
            vk.delta_g2.into_group().neg().into_affine(),
            -vk.beta_g2,
            proof.b,
        );
        let pairing = BnAffinePairing;
        let f_fixed = pairing.multi_miller_loop_affine([p1], [q1]).0;
        let f = pairing
            .multi_miller_loop_affine([p1, p2, p3, p4], [q1, q2, q3, q4])
            .0;
        let (c, _s) = compute_c_wi(f);
        let eval_ins: InputProof = InputProof {
            p2,
            p4,
            q4,
            c: c.c1 / c.c0,
            ks: msm_scalar.clone(),
        };

        let eval_ins_raw = eval_ins.to_raw();

        let pubs: PublicParams = PublicParams {
            q2,
            q3,
            fixed_acc: f_fixed.c1 / f_fixed.c0,
            ks_vks: msm_gs,
            vky0,
        };
        let mut segments: Vec<Segment> = vec![];
        let pass = groth16_generate_segments(false, &mut segments, eval_ins_raw, pubs, &mut None);
        assert!(pass);
        // hint_to_data(segments.clone());
    }

    // rust version of pairing verification check with normalized (1 + a. J) representation
    fn verify_pairing(
        ps: Vec<ark_bn254::G1Affine>,
        qs: Vec<ark_bn254::G2Affine>,
        gc: ark_bn254::Fq12,
        _s: ark_bn254::Fq12,
        p1q1: ark_bn254::Fq6,
    ) {
        let mut cinv = gc.inverse().unwrap();
        cinv = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, cinv.c1 / cinv.c0);
        let mut c = gc;
        c = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, c.c1 / c.c0);

        let mut f = cinv;

        let mut ts = qs.clone();
        let ps: Vec<G1AffineIsomorphic> =
            ps.iter().map(|p1| G1AffineIsomorphic::from(*p1)).collect();
        let num_pairings = ps.len();
        for itr in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
            let ate_bit = ark_bn254::Config::ATE_LOOP_COUNT[itr - 1];
            // square
            f = f * f;
            f = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1 / f.c0);

            // double and eval
            for i in 0..num_pairings {
                let t = ts[i];
                let p = ps[i];
                let alpha = (t.x.square() + t.x.square() + t.x.square()) / (t.y + t.y);
                let neg_bias = alpha * t.x - t.y;
                let mut le0 = alpha;
                le0.mul_assign_by_fp(&p.x());
                let mut le1 = neg_bias;
                le1.mul_assign_by_fp(&p.y());
                let mut le = ark_bn254::Fq12::ZERO;
                le.c0.c0 = ark_bn254::fq2::Fq2::ONE;
                le.c1.c0 = le0;
                le.c1.c1 = le1;

                f *= le;
                f = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1 / f.c0);

                ts[i] = (t + t).into_affine();
            }

            if ate_bit == 1 || ate_bit == -1 {
                let c_or_cinv = if ate_bit == -1 { c } else { cinv };
                f *= c_or_cinv;
                f = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1 / f.c0);

                for i in 0..num_pairings {
                    let t = ts[i];
                    let mut q = qs[i];
                    let p = ps[i];

                    if ate_bit == -1 {
                        q = q.neg();
                    };
                    let alpha = (t.y - q.y) / (t.x - q.x);
                    let neg_bias = alpha * t.x - t.y;

                    let mut le0 = alpha;
                    le0.mul_assign_by_fp(&p.x());
                    let mut le1 = neg_bias;
                    le1.mul_assign_by_fp(&p.y());
                    let mut le = ark_bn254::Fq12::ZERO;
                    le.c0.c0 = ark_bn254::fq2::Fq2::ONE;
                    le.c1.c0 = le0;
                    le.c1.c1 = le1;

                    f *= le;
                    f = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1 / f.c0);

                    ts[i] = (t + q).into_affine();
                }
            }
        }
        let cinv_q = cinv.frobenius_map(1);
        let c_q2 = c.frobenius_map(2);
        let cinv_q3 = cinv.frobenius_map(3);

        for mut cq in vec![cinv_q, c_q2, cinv_q3] {
            cq = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, cq.c1 / cq.c0);
            f *= cq;
            f = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1 / f.c0);
        }

        for i in 0..num_pairings {
            let mut q = qs[i];
            let t = ts[i];
            let p = ps[i];

            q = frob_q_power(q, 1);

            let alpha = (t.y - q.y) / (t.x - q.x);
            let neg_bias = alpha * t.x - t.y;
            let mut le0 = alpha;
            le0.mul_assign_by_fp(&p.x());
            let mut le1 = neg_bias;
            le1.mul_assign_by_fp(&p.y());
            let mut le = ark_bn254::Fq12::ZERO;
            le.c0.c0 = ark_bn254::fq2::Fq2::ONE;
            le.c1.c0 = le0;
            le.c1.c1 = le1;

            f *= le;
            f = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1 / f.c0);

            ts[i] = (t + q).into_affine();
        }

        // t + q^3
        for i in 0..num_pairings {
            let mut q = qs[i];
            let t = ts[i];
            let p = ps[i];

            q = frob_q_power(q, -1);

            let alpha = (t.y - q.y) / (t.x - q.x);
            let neg_bias = alpha * t.x - t.y;
            let mut le0 = alpha;
            le0.mul_assign_by_fp(&p.x());
            let mut le1 = neg_bias;
            le1.mul_assign_by_fp(&p.y());
            let mut le = ark_bn254::Fq12::ZERO;
            le.c0.c0 = ark_bn254::fq2::Fq2::ONE;
            le.c1.c0 = le0;
            le.c1.c1 = le1;

            f *= le;
            f = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1 / f.c0);
            ts[i] = (t + q).into_affine();
        }

        // t + q^3
        for i in 0..num_pairings {
            let mut q = qs[i];
            let t = ts[i];
            q = frob_q_power(q, 3);

            ts[i] = (t + q).into_affine();
        }
        assert_eq!(f.c1 + p1q1, ark_bn254::Fq6::ZERO); // final check, f: (a+b == 0 => (1 + a) * (1 + b) == Fq12::ONE)
    }

    // Pairing verification check with normalized (1 + a. J) representation
    // Includes equivalent bitcoin script in for each functions
    pub fn verify_pairing_scripted(
        ps: Vec<ark_bn254::G1Affine>,
        qs: Vec<ark_bn254::G2Affine>,
        gc: ark_bn254::Fq12,
        _s: ark_bn254::Fq12,
        p1q1: ark_bn254::Fq6,
    ) {
        use crate::chunk::{
            taps_ext_miller::chunk_frob_fp12,
            taps_mul::{chunk_dense_dense_mul, chunk_fq12_square},
            taps_point_ops::{
                chunk_init_t4, chunk_point_ops_and_multiply_line_evals_step_2, frob_q_power,
            },
        };

        let beta_12x = BigUint::from_str(
            "21575463638280843010398324269430826099269044274347216827212613867836435027261",
        )
        .unwrap();
        let beta_12y = BigUint::from_str(
            "10307601595873709700152284273816112264069230130616436755625194854815875713954",
        )
        .unwrap();
        let beta_12 = ark_bn254::Fq2::from_base_prime_field_elems([
            ark_bn254::Fq::from(beta_12x.clone()),
            ark_bn254::Fq::from(beta_12y.clone()),
        ])
        .unwrap();
        let beta_13x = BigUint::from_str(
            "2821565182194536844548159561693502659359617185244120367078079554186484126554",
        )
        .unwrap();
        let beta_13y = BigUint::from_str(
            "3505843767911556378687030309984248845540243509899259641013678093033130930403",
        )
        .unwrap();
        let beta_13 = ark_bn254::Fq2::from_base_prime_field_elems([
            ark_bn254::Fq::from(beta_13x.clone()),
            ark_bn254::Fq::from(beta_13y.clone()),
        ])
        .unwrap();
        let beta_22x = BigUint::from_str(
            "21888242871839275220042445260109153167277707414472061641714758635765020556616",
        )
        .unwrap();
        let beta_22y = BigUint::from_str("0").unwrap();
        let beta_22 = ark_bn254::Fq2::from_base_prime_field_elems([
            ark_bn254::Fq::from(beta_22x.clone()),
            ark_bn254::Fq::from(beta_22y.clone()),
        ])
        .unwrap();

        let mut cinv = gc.inverse().unwrap();
        cinv = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, cinv.c1 / cinv.c0);
        let mut c = gc;
        c = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, c.c1 / c.c0);

        let mut f = cinv;
        let mut g = cinv.c1;

        let mut ts = qs.clone();
        let ps: Vec<G1AffineIsomorphic> =
            ps.iter().map(|p1| G1AffineIsomorphic::from(*p1)).collect();
        let num_pairings = ps.len();

        let mut total_script_size = 0;
        #[allow(unused_assignments)] // clippy bug?
        let mut temp_scr = script! {};

        let (mut t4, _, scr, _) = chunk_init_t4([
            qs[2].x.c0.into(),
            qs[2].x.c1.into(),
            qs[2].y.c0.into(),
            qs[2].y.c1.into(),
        ]);
        total_script_size += scr.len();
        let mut t3 = qs[1];
        let mut t2 = qs[0];

        for itr in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
            let ate_bit = ark_bn254::Config::ATE_LOOP_COUNT[itr - 1];
            println!("itr {} ate_bit {}", itr, ate_bit);
            // square
            f = f * f;
            f = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1 / f.c0);
            (g, _, temp_scr, _) = chunk_fq12_square(g);
            total_script_size += temp_scr.len();

            assert_eq!(g, f.c1);

            // double and eval
            for i in 0..num_pairings {
                let t = ts[i];
                let p = ps[i];
                let alpha = (t.x.square() + t.x.square() + t.x.square()) / (t.y + t.y);
                let neg_bias = alpha * t.x - t.y;
                let mut le0 = alpha;
                le0.mul_assign_by_fp(&p.x());
                let mut le1 = neg_bias;
                le1.mul_assign_by_fp(&p.y());
                let mut le = ark_bn254::Fq12::ZERO;
                le.c0.c0 = ark_bn254::fq2::Fq2::ONE;
                le.c1.c0 = le0;
                le.c1.c1 = le1;

                f *= le;
                f = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1 / f.c0);

                ts[i] = (t + t).into_affine();
            }
            (t4, _, temp_scr, _) = chunk_point_ops_and_multiply_line_evals_step_1(
                true, None, None, t4, ps[2], None, ps[1], t3, None, ps[0], t2, None,
            );
            total_script_size += temp_scr.len();

            t3 = (t3 + t3).into_affine();
            t2 = (t2 + t2).into_affine();
            let (lev, _, scr, _) = chunk_point_ops_and_multiply_line_evals_step_2(t4);
            total_script_size += scr.len();
            (g, _, temp_scr, _) = chunk_dense_dense_mul(g, lev);
            total_script_size += temp_scr.len();

            assert_eq!(g, f.c1);

            if ate_bit == 1 || ate_bit == -1 {
                let c_or_cinv = if ate_bit == -1 { c } else { cinv };
                f *= c_or_cinv;
                f = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1 / f.c0);
                (g, _, temp_scr, _) = chunk_dense_dense_mul(g, c_or_cinv.c1);
                total_script_size += temp_scr.len();

                assert_eq!(g, f.c1);

                for i in 0..num_pairings {
                    let t = ts[i];
                    let mut q = qs[i];
                    let p = ps[i];

                    if ate_bit == -1 {
                        q = q.neg();
                    };
                    let alpha = (t.y - q.y) / (t.x - q.x);
                    let neg_bias = alpha * t.x - t.y;

                    let mut le0 = alpha;
                    le0.mul_assign_by_fp(&p.x());
                    let mut le1 = neg_bias;
                    le1.mul_assign_by_fp(&p.y());
                    let mut le = ark_bn254::Fq12::ZERO;
                    le.c0.c0 = ark_bn254::fq2::Fq2::ONE;
                    le.c1.c0 = le0;
                    le.c1.c1 = le1;

                    f *= le;
                    f = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1 / f.c0);

                    ts[i] = (t + q).into_affine();
                    // println!("pair {:?} ts {:?}", i, ts[i]);
                }

                (t4, _, temp_scr, _) = chunk_point_ops_and_multiply_line_evals_step_1(
                    false,
                    Some(false),
                    Some(ate_bit),
                    t4,
                    ps[2],
                    Some(qs[2]),
                    ps[1],
                    t3,
                    Some(qs[1]),
                    ps[0],
                    t2,
                    Some(qs[0]),
                );
                total_script_size += temp_scr.len();

                if ate_bit == 1 {
                    t3 = (t3 + qs[1]).into_affine();
                    t2 = (t2 + qs[0]).into_affine();
                } else {
                    t3 = (t3 + qs[1].neg()).into_affine();
                    t2 = (t2 + qs[0].neg()).into_affine();
                }

                let (lev, _, scr, _) = chunk_point_ops_and_multiply_line_evals_step_2(t4);
                total_script_size += scr.len();

                (g, _, temp_scr, _) = chunk_dense_dense_mul(g, lev);
                total_script_size += temp_scr.len();
            }
            assert_eq!(g, f.c1);
        }

        let cinv_q = cinv.frobenius_map(1);
        let c_q2 = c.frobenius_map(2);
        let cinv_q3 = cinv.frobenius_map(3);

        let (sc_cinv_q, _, scr, _) = chunk_frob_fp12(cinv.c1, 1);
        total_script_size += scr.len();
        let (sc_c_q2, _, scr, _) = chunk_frob_fp12(c.c1, 2);
        total_script_size += scr.len();
        let (sc_cinv_q3, _, scr, _) = chunk_frob_fp12(cinv.c1, 3);
        total_script_size += scr.len();

        for mut cq in vec![cinv_q, c_q2, cinv_q3] {
            cq = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, cq.c1 / cq.c0);
            f *= cq;
            f = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1 / f.c0);
        }
        for sc_cq in vec![sc_cinv_q, sc_c_q2, sc_cinv_q3] {
            (g, _, temp_scr, _) = chunk_dense_dense_mul(g, sc_cq);
            total_script_size += temp_scr.len();
        }
        assert_eq!(g, f.c1);

        for i in 0..num_pairings {
            let mut q = qs[i];
            let t = ts[i];
            let p = ps[i];

            q.x.conjugate_in_place();
            q.x *= beta_12;
            q.y.conjugate_in_place();
            q.y *= beta_13;
            let alpha = (t.y - q.y) / (t.x - q.x);
            let neg_bias = alpha * t.x - t.y;
            let mut le0 = alpha;
            le0.mul_assign_by_fp(&p.x());
            let mut le1 = neg_bias;
            le1.mul_assign_by_fp(&p.y());
            let mut le = ark_bn254::Fq12::ZERO;
            le.c0.c0 = ark_bn254::fq2::Fq2::ONE;
            le.c1.c0 = le0;
            le.c1.c1 = le1;

            f *= le;
            f = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1 / f.c0);

            ts[i] = (t + q).into_affine();
        }
        (t4, _, temp_scr, _) = chunk_point_ops_and_multiply_line_evals_step_1(
            false,
            Some(true),
            Some(1),
            t4,
            ps[2],
            Some(qs[2]),
            ps[1],
            t3,
            Some(qs[1]),
            ps[0],
            t2,
            Some(qs[0]),
        );
        total_script_size += temp_scr.len();

        let (lev, _, scr, _) = chunk_point_ops_and_multiply_line_evals_step_2(t4);
        total_script_size += scr.len();

        (g, _, temp_scr, _) = chunk_dense_dense_mul(g, lev);
        total_script_size += temp_scr.len();
        let tmp_q2f = frob_q_power(qs[0], 1);
        t2 = (t2 + tmp_q2f).into_affine();
        let tmp_q3f = frob_q_power(qs[1], 1);
        t3 = (t3 + tmp_q3f).into_affine();
        assert_eq!(g, f.c1);

        // t + q^3
        for i in 0..num_pairings {
            let mut q = qs[i];
            let t = ts[i];
            let p = ps[i];

            q.x *= beta_22;

            let alpha = (t.y - q.y) / (t.x - q.x);
            let neg_bias = alpha * t.x - t.y;
            let mut le0 = alpha;
            le0.mul_assign_by_fp(&p.x());
            let mut le1 = neg_bias;
            le1.mul_assign_by_fp(&p.y());
            let mut le = ark_bn254::Fq12::ZERO;
            le.c0.c0 = ark_bn254::fq2::Fq2::ONE;
            le.c1.c0 = le0;
            le.c1.c1 = le1;

            f *= le;
            f = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1 / f.c0);

            ts[i] = (t + q).into_affine();
        }
        (t4, _, temp_scr, _) = chunk_point_ops_and_multiply_line_evals_step_1(
            false,
            Some(true),
            Some(-1),
            t4,
            ps[2],
            Some(qs[2]),
            ps[1],
            t3,
            Some(qs[1]),
            ps[0],
            t2,
            Some(qs[0]),
        );
        total_script_size += temp_scr.len();

        let (lev, _, scr, _) = chunk_point_ops_and_multiply_line_evals_step_2(t4);
        total_script_size += scr.len();

        (g, _, temp_scr, _) = chunk_dense_dense_mul(g, lev);
        total_script_size += temp_scr.len();

        println!("total script size {:?}", total_script_size);
        assert_eq!(g, f.c1);

        assert_eq!(g + p1q1, ark_bn254::Fq6::ZERO); // final check, f: (a+b == 0 => (1 + a) * (1 + b) == Fq12::ONE)
        assert_eq!(f.c1 + p1q1, ark_bn254::Fq6::ZERO); // final check, f: (a+b == 0 => (1 + a) * (1 + b) == Fq12::ONE)
    }

    #[test]
    fn test_verify_pairing() {
        let vk_bytes = crate::chunk::api_runtime_utils::test::VK_BYTES.to_vec();
        let proof_bytes: Vec<u8> = crate::chunk::api_runtime_utils::test::PROOF_BYTES.to_vec();
        let scalar = crate::chunk::api_runtime_utils::test::PUBLIC_INPUT_BYTES.to_vec();
        let proof: ark_groth16::Proof<Bn254> =
            ark_groth16::Proof::deserialize_uncompressed(&proof_bytes[..]).unwrap();
        let vk: ark_groth16::VerifyingKey<Bn254> =
            ark_groth16::VerifyingKey::deserialize_uncompressed(&vk_bytes[..]).unwrap();
        let scalar: ark_bn254::Fr = ark_bn254::Fr::deserialize_uncompressed(&scalar[..]).unwrap();
        let scalars = [scalar];

        // compute msm
        let mut msm_scalar = scalars.to_vec();
        msm_scalar.reverse();
        let mut msm_gs = vk.gamma_abc_g1.clone(); // vk.vk_pubs[0]
        msm_gs.reverse();
        let vky0 = msm_gs.pop().unwrap();
        let mut p3 = vky0 * ark_bn254::Fr::ONE;
        for i in 0..NUM_PUBS {
            p3 += msm_gs[i] * msm_scalar[i];
        }
        let p3 = p3.into_affine();

        let (p2, p1, p4) = (proof.c, vk.alpha_g1, proof.a);
        let (q3, q2, q1, q4) = (
            vk.gamma_g2.into_group().neg().into_affine(),
            vk.delta_g2.into_group().neg().into_affine(),
            -vk.beta_g2,
            proof.b,
        );

        // precompute c, s
        let pairing = BnAffinePairing;
        let mut g = pairing
            .multi_miller_loop_affine([p1, p2, p3, p4], [q1, q2, q3, q4])
            .0;
        let fixed_p1q1 = pairing.multi_miller_loop_affine([p1], [q1]).0;
        let fixed_p1q1 = fixed_p1q1.c1 / fixed_p1q1.c0;
        if g.c1 != ark_bn254::Fq6::ZERO {
            g = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, g.c1 / g.c0);
        }
        let (c, wi) = compute_c_wi(g);

        // actual scripted verification
        verify_pairing(vec![p2, p3, p4], vec![q2, q3, q4], c, wi, fixed_p1q1);
        verify_pairing_scripted(vec![p2, p3, p4], vec![q2, q3, q4], c, wi, fixed_p1q1);
    }
}
