use std::cmp::min;

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{AdditiveGroup, BigInteger, PrimeField};
use bitcoin_script::script;

use super::assigner::BCAssigner;
use super::elements::FrType;
use super::segment::Segment;
use crate::{
    bn254::{curves::G1Affine, fp254impl::Fp254Impl, fr::Fr},
    chunker::elements::{ElementTrait, G1PointType},
};

/// This function do scalar multiplication in G1 curve group.
/// Return all segements generated and the result of scalar multiplication.
pub fn chunk_hinted_scalar_mul_by_constant<T: BCAssigner>(
    assigner: &mut T,
    prefix: &str,
    scalar: ark_bn254::Fr,
    scalar_type: FrType,
    p: &mut ark_bn254::G1Affine,
    coeff: Vec<(ark_bn254::Fq, ark_bn254::Fq)>,
    step_p: Vec<ark_bn254::G1Affine>,
    trace: Vec<ark_bn254::G1Affine>,
) -> (Vec<Segment>, G1PointType) {
    let mut segments = vec![];
    let mut type_acc = G1PointType::new(assigner, &format!("{}_{}", prefix, 0));

    let mut hints = vec![];
    let mut coeff_iter = coeff.iter();
    let mut step_p_iter = step_p.iter();
    let mut trace_iter = trace.iter();
    let mut loop_scripts = Vec::new();
    let mut i = 0;
    // options: i_step = 2-15
    let i_step = 12;

    // precomputed lookup table (affine)
    let mut p_mul: Vec<ark_bn254::G1Affine> = Vec::new();
    p_mul.push(ark_bn254::G1Affine::zero());
    for _ in 1..(1 << i_step) {
        p_mul.push((p_mul.last().unwrap().clone() + p.clone()).into_affine());
    }
    let mut c: ark_bn254::G1Affine = ark_bn254::G1Affine::zero();
    let scalar_bigint = scalar.into_bigint();

    while i < Fr::N_BITS {
        let depth = min(Fr::N_BITS - i, i_step);
        // double(step-size) point
        if i > 0 {
            let double_coeff = coeff_iter.next().unwrap();
            let step = step_p_iter.next().unwrap();
            let point_after_double = trace_iter.next().unwrap();

            let (double_loop_script, doulbe_hints) =
                G1Affine::hinted_check_add(c, *step, double_coeff.0, double_coeff.1);

            let double_loop = script! {
                // query bucket point through lookup table
                { G1Affine::push_not_montgomery(*step) }
                // check before usage
                { double_loop_script }
            };
            loop_scripts.push(double_loop.clone());
            hints.extend(doulbe_hints);

            c = (c + *step).into_affine();
        }
        // if i == i_step * 2 {
        //     break;
        // }

        // squeeze a bucket scalar
        loop_scripts.push(script! {
            for _ in 0..i {
                OP_FROMALTSTACK OP_DROP
            }
            for _ in 0..depth {
                OP_FROMALTSTACK
            }
            for _ in 0..(Fr::N_BITS - i - depth) {
                OP_FROMALTSTACK
                OP_DROP
            }
        });

        let mut mask = 0;

        for j in 0..depth {
            mask *= 2;
            mask += scalar_bigint.get_bit((Fr::N_BITS - i - j - 1) as usize) as u32;
        }

        // add point
        let add_coeff = if i > 0 {
            *coeff_iter.next().unwrap()
        } else {
            (ark_bn254::Fq::ZERO, ark_bn254::Fq::ZERO)
        };
        let point_after_add = trace_iter.next().unwrap();
        let (add_script, add_hints) =
            G1Affine::hinted_check_add(c, p_mul[mask as usize], add_coeff.0, add_coeff.1);
        let add_loop = script! {
            // query bucket point through lookup table
            { G1Affine::dfs_with_constant_mul_not_montgomery(0, depth - 1, 0, &p_mul) }
            // check before usage
            if i > 0 {
                { add_script }
            }
        };
        loop_scripts.push(add_loop.clone());
        if mask != 0 {
            if i > 0 {
                hints.extend(add_hints);
            }
            c = (c + p_mul[mask as usize]).into_affine();
        }
        // if i == i_step * 21 {
        //     break;
        // }

        let mut segment_script = script! {
            { Fr::convert_to_le_bits_toaltstack() }
        };
        for script in loop_scripts.clone() {
            segment_script = segment_script.push_script(script.compile());
        }
        loop_scripts.clear();

        if i == 0 {
            type_acc.fill_with_data(crate::chunker::elements::DataType::G1PointData(c));
            let segment = Segment::new_with_name(format!("{}_loop_{}", prefix, i), segment_script)
                .add_parameter(&scalar_type)
                .add_result(&type_acc)
                .add_hint(hints.clone());
            hints.clear();
            segments.push(segment);
        } else {
            let mut update = G1PointType::new(assigner, &format!("{}_{}", prefix, i));
            update.fill_with_data(crate::chunker::elements::DataType::G1PointData(c));
            let segment = Segment::new_with_name(format!("{}_loop_{}", prefix, i), segment_script)
                .add_parameter(&type_acc)
                .add_parameter(&scalar_type)
                .add_result(&update)
                .add_hint(hints.clone());
            hints.clear();
            segments.push(segment);

            type_acc = update;
        }

        i += i_step;
    }
    assert!(coeff_iter.next() == None);
    assert!(step_p_iter.next() == None);
    assert!(trace_iter.next() == None);

    println!("debug: c:{:?}", c);
    *p = c;

    (segments, type_acc)
}

#[cfg(test)]
mod tests {
    use crate::{
        bn254::msm::prepare_msm_input,
        chunker::{
            assigner::DummyAssinger,
            chunk_scalar_mul::chunk_hinted_scalar_mul_by_constant,
            elements::{ElementTrait, FrType},
        },
        execute_script_with_inputs,
    };

    use ark_ec::CurveGroup;
    use ark_ff::UniformRand;
    use ark_std::test_rng;
    use std::ops::Mul;

    #[test]
    fn test_hinted_scalar_mul_by_constant_g1_affine() {
        let k = 0;
        let n = 1 << k;
        let rng = &mut test_rng();
        let mut assigner = DummyAssinger {};

        let scalars = (0..n).map(|_| ark_bn254::Fr::rand(rng)).collect::<Vec<_>>();

        let mut bases = (0..n)
            .map(|_| ark_bn254::G1Projective::rand(rng).into_affine())
            .collect::<Vec<_>>();

        let q = bases[0].mul(scalars[0]).into_affine();
        println!("debug: expected res:{:?}", q);
        let (inner_coeffs, _) = prepare_msm_input(&bases, &scalars, 12);

        let mut scalar_type = FrType::new(&mut assigner, "init");
        scalar_type.fill_with_data(crate::chunker::elements::DataType::FrData(scalars[0]));

        let (segments, _) = chunk_hinted_scalar_mul_by_constant(
            &mut assigner,
            "g1_mul",
            scalars[0],
            scalar_type,
            &mut bases[0],
            inner_coeffs[0].0.clone(),
            inner_coeffs[0].1.clone(),
            inner_coeffs[0].2.clone(),
        );

        println!("segments count: {}", segments.len());

        for (_, segment) in segments.iter().enumerate() {
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
                "{}",
                res.stats.max_nb_stack_items
            );
        }
    }
}
