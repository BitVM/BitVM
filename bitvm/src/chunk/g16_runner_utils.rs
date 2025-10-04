use crate::{
    bn254::{
        fp254impl::Fp254Impl,
        fr::Fr,
        g2::G2Affine,
        msm::{BATCH_SIZE_PER_CHUNK, WINDOW_G1_MSM},
        utils::Hint,
    },
    chunk::{elements::G1AffineIsomorphic, taps_msm::chunk_msm},
};

use super::{
    elements::{DataType, ElemG2Eval, ElementType},
    taps_ext_miller::*,
    taps_msm::chunk_hash_p,
    taps_mul::{chunk_dense_dense_mul, chunk_fq12_square},
    taps_point_ops::{
        chunk_init_t4, chunk_point_ops_and_multiply_line_evals_step_1,
        chunk_point_ops_and_multiply_line_evals_step_2,
    },
};
use ark_ff::Field;
use bitcoin::ScriptBuf;
use bitcoin_script::script;

use super::taps_ext_miller::{chunk_final_verify, chunk_frob_fp12, chunk_hash_c, chunk_hash_c_inv};

pub type SegmentID = u32;

#[derive(Debug, Clone)]
pub(crate) struct Segment {
    pub id: SegmentID,
    pub parameter_ids: Vec<(SegmentID, ElementType)>,
    pub result: (DataType, ElementType),
    pub hints: Vec<Hint>,
    pub scr_type: ScriptType,
    pub scr: ScriptBuf,
    pub is_valid_input: bool,
}

/// After the returned `script` and `witness` are executed together, only `OP_FALSE` left on the stack.
/// If operator gives a wrong intermediate value, `OP_TRUE` will left on the stack and challenger will finish the slash.

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ScriptType {
    NonDeterministic,
    MSM(u32),
    ValidateG1IsOnCurve,
    ValidateG1HashIsOnCurve,
    ValidateG2IsOnCurve,
    ValidateFq6OnField,

    PreMillerInitT4,
    PreMillerPrecomputeP,
    PreMillerPrecomputePFromHash,
    PreMillerHashC,
    PreMillerHashCInv,

    PreMillerHashP,

    MillerSquaring,
    MillerPointOpsStep1(bool, Option<i8>, Option<bool>),
    MillerPointOpsStep2,
    FoldedFp12Multiply,
    PostMillerFrobFp12(u8),

    PostMillerFinalVerify,
}

impl ScriptType {
    pub fn is_final_script(&self) -> bool {
        matches!(self, ScriptType::PostMillerFinalVerify)
    }
}

// final verify
// sq
pub(crate) fn wrap_hint_squaring(skip: bool, segment_id: usize, in_a: &Segment) -> Segment {
    let input_segment_info: Vec<(SegmentID, ElementType)> = vec![(in_a.id, ElementType::Fp6)];

    let f_acc = in_a.result.0.try_into().unwrap();

    let (mut sq, mut is_valid_input, mut scr, mut op_hints) =
        (ark_bn254::Fq6::ONE, true, script! {}, vec![]);
    if !skip {
        (sq, is_valid_input, scr, op_hints) = chunk_fq12_square(f_acc);
    }

    Segment {
        id: segment_id as u32,
        is_valid_input,
        parameter_ids: input_segment_info,
        result: (DataType::Fp6Data(sq), ElementType::Fp6),
        hints: op_hints,
        scr_type: ScriptType::MillerSquaring,
        scr: scr.compile(),
    }
}

// init_t4
pub(crate) fn wrap_hint_init_t4(
    skip: bool,
    segment_id: usize,
    in_q4yc1: &Segment,
    in_q4yc0: &Segment,
    in_q4xc1: &Segment,
    in_q4xc0: &Segment,
) -> Segment {
    let input_segment_info: Vec<(SegmentID, ElementType)> = vec![
        (in_q4yc1.id, ElementType::FieldElem),
        (in_q4yc0.id, ElementType::FieldElem),
        (in_q4xc1.id, ElementType::FieldElem),
        (in_q4xc0.id, ElementType::FieldElem),
    ];

    let q4xc0: ark_ff::BigInt<4> = in_q4xc0.result.0.try_into().unwrap();
    let q4xc1: ark_ff::BigInt<4> = in_q4xc1.result.0.try_into().unwrap();
    let q4yc0: ark_ff::BigInt<4> = in_q4yc0.result.0.try_into().unwrap();
    let q4yc1: ark_ff::BigInt<4> = in_q4yc1.result.0.try_into().unwrap();

    let (mut tmpt4, mut is_valid_input, mut scr, mut op_hints) =
        (ElemG2Eval::mock(), true, script! {}, vec![]);
    if !skip {
        (tmpt4, is_valid_input, scr, op_hints) = chunk_init_t4([q4xc0, q4xc1, q4yc0, q4yc1]);
    }

    Segment {
        id: segment_id as u32,
        is_valid_input,
        parameter_ids: input_segment_info,
        result: (DataType::G2EvalData(tmpt4), ElementType::G2EvalPoint),
        hints: op_hints,
        scr_type: ScriptType::PreMillerInitT4,
        scr: scr.compile(),
    }
}

// dmul
pub(crate) fn wrap_hints_dense_dense_mul(
    skip: bool,
    segment_id: usize,
    in_a: &Segment,
    in_b: &Segment,
) -> Segment {
    let input_segment_info: Vec<(SegmentID, ElementType)> =
        vec![(in_b.id, ElementType::Fp6), (in_a.id, ElementType::Fp6)];

    let a: ark_bn254::Fq6 = in_a.result.0.try_into().unwrap();
    let b: ark_bn254::Fq6 = in_b.result.0.try_into().unwrap();

    let (mut dmul0, mut is_valid_input, mut scr, mut op_hints) =
        (ark_bn254::Fq6::ONE, true, script! {}, vec![]);
    if !skip {
        (dmul0, is_valid_input, scr, op_hints) = chunk_dense_dense_mul(a, b);
    }

    Segment {
        id: segment_id as u32,
        is_valid_input,
        parameter_ids: input_segment_info,
        result: (DataType::Fp6Data(dmul0), ElementType::Fp6),
        hints: op_hints,
        scr_type: ScriptType::FoldedFp12Multiply,
        scr: scr.compile(),
    }
}

// frob
pub(crate) fn wrap_hints_frob_fp12(
    skip: bool,
    segment_id: usize,
    in_f: &Segment,
    power: usize,
) -> Segment {
    let input_segment_info: Vec<(SegmentID, ElementType)> = vec![(in_f.id, ElementType::Fp6)];
    let f = in_f.result.0.try_into().unwrap();

    let (mut cp, mut is_valid_input, mut scr, mut op_hints) =
        (ark_bn254::Fq6::ONE, true, script! {}, vec![]);
    if !skip {
        (cp, is_valid_input, scr, op_hints) = chunk_frob_fp12(f, power);
        // op_hints.extend_from_slice(&Element::Fp12v0(f).get_hash_preimage_as_hints());
    }

    Segment {
        id: segment_id as u32,
        is_valid_input,
        parameter_ids: input_segment_info,
        result: (DataType::Fp6Data(cp), ElementType::Fp6),
        hints: op_hints,
        scr_type: ScriptType::PostMillerFrobFp12(power as u8),
        scr: scr.compile(),
    }
}

// ops
#[allow(clippy::too_many_arguments)]
pub(crate) fn wrap_chunk_point_ops_and_multiply_line_evals_step_1(
    skip: bool,
    segment_id: usize,
    is_dbl: bool,
    is_frob: Option<bool>,
    ate_bit: Option<i8>,
    in_t4: &Segment,
    in_p4: &Segment,
    in_q4: Option<Vec<Segment>>,
    in_p3: &Segment,
    t3: ark_bn254::G2Affine,
    q3: Option<ark_bn254::G2Affine>,
    in_p2: &Segment,
    t2: ark_bn254::G2Affine,
    q2: Option<ark_bn254::G2Affine>,
) -> Segment {
    let mut input_segment_info: Vec<(SegmentID, ElementType)> = vec![
        (in_p2.id, ElementType::G1),
        (in_p3.id, ElementType::G1),
        (in_p4.id, ElementType::G1),
        (in_t4.id, ElementType::G2EvalPoint),
    ];

    let t4: ElemG2Eval = in_t4.result.0.try_into().unwrap();
    let p4: G1AffineIsomorphic = in_p4.result.0.try_into().unwrap();
    let p3: G1AffineIsomorphic = in_p3.result.0.try_into().unwrap();
    let p2: G1AffineIsomorphic = in_p2.result.0.try_into().unwrap();

    //let p4: ark_bn254::G1Affine = p4.into();
    //let p4 = G1AffineIsomorphic::new(p4.x, p4.y);

    //let p3: ark_bn254::G1Affine = p3.into();
    //let p3 = G1AffineIsomorphic::new(p3.x, p3.y);

    //let p2: ark_bn254::G1Affine = p2.into();
    //let p2 = G1AffineIsomorphic::new(p2.x, p2.y);

    let mut q4: Option<ark_bn254::G2Affine> = None;

    if !is_dbl {
        let in_q4 = in_q4.unwrap();
        for v in in_q4.iter().rev() {
            input_segment_info.push((v.id, ElementType::FieldElem))
        }

        let q4xc0: ark_ff::BigInt<4> = in_q4[0].result.0.try_into().unwrap();
        let q4xc1: ark_ff::BigInt<4> = in_q4[1].result.0.try_into().unwrap();
        let q4yc0: ark_ff::BigInt<4> = in_q4[2].result.0.try_into().unwrap();
        let q4yc1: ark_ff::BigInt<4> = in_q4[3].result.0.try_into().unwrap();
        q4 = Some(ark_bn254::G2Affine::new_unchecked(
            ark_bn254::Fq2::new(q4xc0.into(), q4xc1.into()),
            ark_bn254::Fq2::new(q4yc0.into(), q4yc1.into()),
        ));
        G2Affine::check(&q4.unwrap());
    }

    let (mut dbladd, mut is_valid_input, mut scr, mut op_hints) =
        (ElemG2Eval::mock(), true, script! {}, vec![]);
    if !skip {
        (dbladd, is_valid_input, scr, op_hints) = chunk_point_ops_and_multiply_line_evals_step_1(
            is_dbl, is_frob, ate_bit, t4, p4, q4, p3, t3, q3, p2, t2, q2,
        );
    }

    Segment {
        id: segment_id as u32,
        is_valid_input,
        parameter_ids: input_segment_info,
        result: (DataType::G2EvalData(dbladd), ElementType::G2Eval),
        hints: op_hints,
        scr_type: ScriptType::MillerPointOpsStep1(is_dbl, ate_bit, is_frob),
        scr: scr.compile(),
    }
}

// complete
pub(crate) fn wrap_chunk_point_ops_and_multiply_line_evals_step_2(
    skip: bool,
    segment_id: usize,
    in_f: &Segment,
) -> Segment {
    let input_segment_info: Vec<(SegmentID, ElementType)> = vec![(in_f.id, ElementType::G2EvalMul)];

    let f = in_f.result.0.try_into().unwrap();

    let (mut cp, mut is_valid_input, mut scr, mut op_hints) =
        (ark_bn254::Fq6::ONE, true, script! {}, vec![]);
    if !skip {
        (cp, is_valid_input, scr, op_hints) = chunk_point_ops_and_multiply_line_evals_step_2(f);
        // op_hints.extend_from_slice(&Element::Fp12v0(f).get_hash_preimage_as_hints());
    }

    Segment {
        id: segment_id as u32,
        is_valid_input,
        parameter_ids: input_segment_info,
        result: (DataType::Fp6Data(cp), ElementType::Fp6),
        hints: op_hints,
        scr_type: ScriptType::MillerPointOpsStep2,
        scr: scr.compile(),
    }
}

pub(crate) fn wrap_hint_msm(
    skip: bool,
    segment_id: usize,
    scalars: Vec<Segment>,
    pub_vky: Vec<ark_bn254::G1Affine>,
) -> Vec<Segment> {
    let num_chunks_per_scalar =
        (Fr::N_BITS + WINDOW_G1_MSM - 1) / (WINDOW_G1_MSM * BATCH_SIZE_PER_CHUNK);

    let hint_scalars: Vec<ark_ff::BigInt<4>> = scalars
        .iter()
        .map(|f| f.result.0.try_into().unwrap())
        .collect();

    let mut segments = vec![];
    if !skip {
        let houts = chunk_msm(hint_scalars, pub_vky.clone());
        assert_eq!(houts.len(), num_chunks_per_scalar as usize * scalars.len());
        for (msm_chunk_index, (hout_msm, is_valid_input, scr, op_hints)) in
            houts.into_iter().enumerate()
        {
            let mut input_segment_info: Vec<(SegmentID, ElementType)> = vec![];
            if msm_chunk_index > 0 {
                let prev_msm_id = (segment_id + msm_chunk_index - 1) as u32;
                input_segment_info.push((prev_msm_id, ElementType::G1));
            }

            let sc = &scalars[msm_chunk_index / num_chunks_per_scalar as usize];
            input_segment_info.push((sc.id, ElementType::ScalarElem));

            segments.push(Segment {
                id: (segment_id + msm_chunk_index) as u32,
                is_valid_input,
                parameter_ids: input_segment_info,
                result: (DataType::G1Data(hout_msm.into()), ElementType::G1),
                hints: op_hints,
                scr_type: ScriptType::MSM(msm_chunk_index as u32),
                scr: scr.compile(),
            });
        }
    } else {
        let hout_msm: ark_bn254::G1Affine = ark_bn254::G1Affine::identity();
        for msm_chunk_index in 0..num_chunks_per_scalar * scalars.len() as u32 {
            let mut input_segment_info: Vec<(SegmentID, ElementType)> = vec![];
            if msm_chunk_index > 0 {
                let prev_msm_id = segment_id as u32 + msm_chunk_index - 1;
                input_segment_info.push((prev_msm_id, ElementType::G1));
            }
            let sc = &scalars[(msm_chunk_index / num_chunks_per_scalar) as usize];
            input_segment_info.push((sc.id, ElementType::ScalarElem));

            segments.push(Segment {
                id: (segment_id as u32 + msm_chunk_index),
                is_valid_input: true,
                parameter_ids: input_segment_info,
                result: (DataType::G1Data(hout_msm.into()), ElementType::G1),
                hints: vec![],
                scr_type: ScriptType::MSM(msm_chunk_index),
                scr: ScriptBuf::new(),
            });
        }
    }
    segments
}

pub(crate) fn wrap_hint_hash_p(
    skip: bool,
    segment_id: usize,
    in_t: &Segment,
    pub_vky0: ark_bn254::G1Affine,
) -> Segment {
    let input_segment_info = vec![(in_t.id, ElementType::G1)];

    let t: G1AffineIsomorphic = in_t.result.0.try_into().unwrap();
    let t = t.into();
    let (mut p3, mut is_valid_input, mut scr, mut op_hints) =
        (ark_bn254::G1Affine::identity(), true, script! {}, vec![]);
    if !skip {
        (p3, is_valid_input, scr, op_hints) = chunk_hash_p(t, pub_vky0);
        // op_hints.extend_from_slice(&DataType::G1Data(t).get_hash_preimage_as_hints());
    }
    Segment {
        id: segment_id as u32,
        is_valid_input,
        parameter_ids: input_segment_info,
        result: (DataType::G1Data(p3.into()), ElementType::G1),
        hints: op_hints,
        scr_type: ScriptType::PreMillerHashP,
        scr: scr.compile(),
    }
}

pub(crate) fn wrap_hints_precompute_p(
    skip: bool,
    segment_id: usize,
    in_py: &Segment,
    in_px: &Segment,
) -> Segment {
    let input_segment_info: Vec<(SegmentID, ElementType)> = vec![
        (in_py.id, ElementType::FieldElem),
        (in_px.id, ElementType::FieldElem),
    ];

    let (mut p3d, mut is_valid_input, mut scr, mut op_hints) = (
        ark_bn254::G1Affine::identity().into(),
        true,
        script! {},
        vec![],
    );
    // let mut tap_prex = script! {};
    if !skip {
        let in_py = in_py.result.0.try_into().unwrap();
        let in_px = in_px.result.0.try_into().unwrap();
        (p3d, is_valid_input, scr, op_hints) = chunk_precompute_p(in_py, in_px);
    }

    Segment {
        id: segment_id as u32,
        is_valid_input,
        parameter_ids: input_segment_info,
        result: (DataType::G1Data(p3d), ElementType::G1),
        hints: op_hints,
        scr_type: ScriptType::PreMillerPrecomputeP,
        scr: scr.compile(),
    }
}

pub(crate) fn wrap_hints_precompute_p_from_hash(
    skip: bool,
    segment_id: usize,
    in_p: &Segment,
) -> Segment {
    let input_segment_info = vec![(in_p.id, ElementType::G1)];

    let (mut p3d, mut is_valid_input, mut scr, mut op_hints) = (
        ark_bn254::G1Affine::identity().into(),
        true,
        script! {},
        vec![],
    );
    if !skip {
        let in_p: G1AffineIsomorphic = in_p.result.0.try_into().unwrap();
        (p3d, is_valid_input, scr, op_hints) = chunk_precompute_p_from_hash(in_p.into());
    }

    Segment {
        id: segment_id as u32,
        is_valid_input,
        parameter_ids: input_segment_info,
        result: (DataType::G1Data(p3d.into()), ElementType::G1),
        hints: op_hints,
        scr_type: ScriptType::PreMillerPrecomputePFromHash,
        scr: scr.compile(),
    }
}

pub(crate) fn wrap_hint_hash_c(skip: bool, segment_id: usize, in_c: Vec<Segment>) -> Segment {
    let mut input_segment_info: Vec<(SegmentID, ElementType)> = vec![];
    let fqvec: Vec<ark_ff::BigInt<4>> = in_c
        .iter()
        .map(|f| f.result.0.try_into().unwrap())
        .collect();

    in_c.iter().rev().for_each(|f| {
        input_segment_info.push((f.id, ElementType::FieldElem));
    });

    let (mut c, mut is_valid_input, mut scr, mut op_hints) =
        (ark_bn254::Fq6::ONE, true, script! {}, vec![]);
    if !skip {
        (c, is_valid_input, scr, op_hints) = chunk_hash_c(fqvec);
    }

    Segment {
        id: segment_id as u32,
        is_valid_input,
        parameter_ids: input_segment_info,
        result: (DataType::Fp6Data(c), ElementType::Fp6),
        hints: op_hints,
        scr_type: ScriptType::PreMillerHashC,
        scr: scr.compile(),
    }
}

pub(crate) fn wrap_hint_hash_c_inv(skip: bool, segment_id: usize, in_c: Vec<Segment>) -> Segment {
    let mut input_segment_info: Vec<(SegmentID, ElementType)> = vec![];
    let fqvec: Vec<ark_ff::BigInt<4>> = in_c
        .iter()
        .map(|f| f.result.0.try_into().unwrap())
        .collect();

    in_c.iter().rev().for_each(|f| {
        input_segment_info.push((f.id, ElementType::FieldElem));
    });

    let (mut c, mut is_valid_input, mut scr, mut op_hints) =
        (ark_bn254::Fq6::ONE, true, script! {}, vec![]);
    if !skip {
        (c, is_valid_input, scr, op_hints) = chunk_hash_c_inv(fqvec);
    }

    Segment {
        id: segment_id as u32,
        is_valid_input,
        parameter_ids: input_segment_info,
        result: (DataType::Fp6Data(c), ElementType::Fp6),
        hints: op_hints,
        scr_type: ScriptType::PreMillerHashCInv,
        scr: scr.compile(),
    }
}

pub(crate) fn wrap_chunk_final_verify(
    skip: bool,
    segment_id: usize,
    in_a: &Segment,
    in_t4: &Segment,
    in_q4: Vec<Segment>,
    fixedacc_const: ark_bn254::Fq6,
) -> Segment {
    let mut input_segment_info: Vec<(SegmentID, ElementType)> = vec![
        (in_t4.id, ElementType::G2EvalPoint),
        (in_a.id, ElementType::Fp6),
    ];
    let t4: ElemG2Eval = in_t4.result.0.try_into().unwrap();
    let a: ark_bn254::Fq6 = in_a.result.0.try_into().unwrap();
    for v in in_q4.iter().rev() {
        input_segment_info.push((v.id, ElementType::FieldElem))
    }
    let q4xc0: ark_ff::BigInt<4> = in_q4[0].result.0.try_into().unwrap();
    let q4xc1: ark_ff::BigInt<4> = in_q4[1].result.0.try_into().unwrap();
    let q4yc0: ark_ff::BigInt<4> = in_q4[2].result.0.try_into().unwrap();
    let q4yc1: ark_ff::BigInt<4> = in_q4[3].result.0.try_into().unwrap();
    // We will do on_curve and in_subgroup check before point operation
    let q4 = ark_bn254::G2Affine::new_unchecked(
        ark_bn254::Fq2::new(q4xc0.into(), q4xc1.into()),
        ark_bn254::Fq2::new(q4yc0.into(), q4yc1.into()),
    );
    G2Affine::check(&q4);

    let (mut is_valid, mut scr, mut op_hints) = (true, script! {}, vec![]);
    if !skip {
        (is_valid, scr, op_hints) = chunk_final_verify(a, fixedacc_const, t4.t, q4);

        // op_hints.extend_from_slice(&Element::Fp12v0(a).get_hash_preimage_as_hints());
    }
    let is_valid_fq = if is_valid {
        ark_ff::BigInt::<4>::one()
    } else {
        ark_ff::BigInt::<4>::zero()
    };

    Segment {
        id: segment_id as u32,
        is_valid_input: true,
        parameter_ids: input_segment_info,
        result: (DataType::U256Data(is_valid_fq), ElementType::FieldElem),
        hints: op_hints,
        scr_type: ScriptType::PostMillerFinalVerify,
        scr: scr.compile(),
    }
}
