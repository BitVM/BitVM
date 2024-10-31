use std::cmp::min;

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{AdditiveGroup, BigInteger, PrimeField};
use bitcoin_script::script;
use musig2::secp256k1::scalar;
use crate::chunker::elements::DataType::G1PointData;

use crate::chunker::elements::U32Element;
use crate::chunker::segment;
use crate::{bn254::{curves::G1Affine, fp254impl::Fp254Impl, fr::Fr}, chunker::elements::{ElementTrait, G1PointType}};
use crate::chunker::elements::DataType::U32Data;
use super::assigner::BCAssigner;
use super::segment::Segment;


// scalar * G1Affine
fn hinted_scalar_mul_by_constant_g1_affine<T: BCAssigner>(   
    assigner: &mut T,
    prefix: &str,
    scalar: ark_bn254::Fr,     
    p: &mut ark_bn254::G1Affine,
    coeff: Vec<(ark_bn254::Fq, ark_bn254::Fq)>,
    step_p: Vec<ark_bn254::G1Affine>,
) -> (Vec<Segment>, G1PointType) {
    let mut coeff_iter = coeff.iter();
    let mut step_p_iter = step_p.iter();
    let mut i = 0;
    // options: i_step = 2-15
    let i_step = 12;

    // precomputed lookup table (affine)
    let mut p_mul: Vec<ark_bn254::G1Affine> = Vec::new();
    p_mul.push(ark_bn254::G1Affine::zero());
    for _ in 1..(1 << i_step) {
        p_mul.push((p_mul.last().unwrap().clone() + p.clone()).into_affine());
    }

    // prepare intermediate state and hint for segment
    let mut scalar_bucket_state  = vec![];
    let mut step_state = vec![];
    let mut double_loop_script_state = vec![];
    let mut double_loop_hints_state = vec![];
    let mut add_loop_script_state = vec![];
    let mut add_loop_hints_state = vec![];
    let mut intermediate_result = vec![];
    let mut dfs_script_0 = script!();

    let mut c: ark_bn254::G1Affine = ark_bn254::G1Affine::zero();
    let mut step_count = 0;

    let scalar_bigint = scalar.into_bigint();

    while i < Fr::N_BITS {
        let depth = min(Fr::N_BITS - i, i_step);
        // double(step-size) point
        if i > 0 {
            let double_coeff = coeff_iter.next().unwrap();
            let step = step_p_iter.next().unwrap();
            step_state.push(*step);

            let (double_loop_script, doulbe_hints) = G1Affine::hinted_check_add(c, *step, double_coeff.0, double_coeff.1);
            double_loop_script_state.push(double_loop_script);
            double_loop_hints_state.push(doulbe_hints);

            c = (c + *step).into_affine();
        } 

        let mut mask = 0;

        let mut bucket_scalar = vec![];
        for j in 0..depth {
            mask *= 2;
            mask += scalar_bigint.get_bit((Fr::N_BITS - i - j - 1) as usize) as u32;
            bucket_scalar.push(scalar_bigint.get_bit((Fr::N_BITS - i - j - 1) as usize));
        }
        scalar_bucket_state.push(bucket_scalar);

        // add point
        let add_coeff = if i > 0 {
            *coeff_iter.next().unwrap()
        } else {
            (ark_bn254::Fq::ZERO, ark_bn254::Fq::ZERO)
        };

        let (add_script, add_hints) = G1Affine::hinted_check_add(c, p_mul[mask as usize], add_coeff.0, add_coeff.1);
        
        if i == 0 {
            dfs_script_0 = script! {
                for _ in 0..depth {
                    OP_FROMALTSTACK
                }
                { G1Affine::dfs_with_constant_mul_not_montgomery(0, depth - 1, 0, &p_mul) }
            }
        }
        
        if i > 0 {
            let add_loop = script! {
                for _ in 0..depth {
                    OP_FROMALTSTACK
                }
                // query bucket point through lookup table
                { G1Affine::dfs_with_constant_mul_not_montgomery(0, depth - 1, 0, &p_mul) }
                // check before usage
                { add_script }
            
            };
            add_loop_script_state.push(add_loop);
            add_loop_hints_state.push(add_hints);
        }

        if mask != 0  {
            c = (c + p_mul[mask as usize]).into_affine();
        }

        if step_count % 2 != 0 {
            intermediate_result.push(c);
        }

        step_count += 1;
        i += i_step;
    }
    assert!(coeff_iter.next() == None);
    assert!(step_p_iter.next() == None);
    *p = c;

    let mut segment = vec![];

    //construct segment0

    let segment_script0 = script! {
        // query bucket point through lookup table
        { Fr::convert_to_le_bits_toaltstack() }
        { dfs_script_0 }
        {double_loop_script_state[0].clone()}
        {add_loop_script_state[0].clone()}  
    };
    println!("script len:{:?}", segment_script0.len());

    let mut segment_hint0 = vec![];

    segment_hint0.append(&mut double_loop_hints_state[0]);
    segment_hint0.append(&mut add_loop_hints_state[0]);

    let mut scalar_state = vec![];

    for j in 1..(Fr::N_BITS/(2 * i_step) + 1) {
 
        let mut segment_scalar = vec![];
        for i in 0..(Fr::N_BITS - (2 * i_step * j)) {
            let mut bit = U32Element::new(assigner, &format!("scalar_{}_{}", j, i));
            let value = scalar_bigint.get_bit(i as usize) as u32;
            bit.fill_with_data(U32Data(value));
            segment_scalar.push(bit);
        }
        scalar_state.push(segment_scalar);
    }

    let mut step0 = G1PointType::new(assigner, "step0");
    step0.fill_with_data(G1PointData(step_state[0]));
    let mut result0 = G1PointType::new(assigner, "result0");
    result0.fill_with_data(G1PointData(intermediate_result[0]));

    let mut segment0 = Segment::new(segment_script0)
        .add_parameter(&step0)
        .add_result(&result0)
        .add_hint(segment_hint0);

    for scalar_bit in scalar_state[0].iter() {
        segment0 = segment0.add_result(scalar_bit);
    }

    segment.push(segment0);

    let mut prev_result = result0;
    let mut i = 1;

    //construct other segment
    //two (double_loop + add_loop) as a sengment

    while i < 20 {
        let segment_script = script! {
            {double_loop_script_state[i].clone()}
            {add_loop_script_state[i].clone()}
            {double_loop_script_state[i+1].clone()}
            {add_loop_script_state[i+1].clone()}    
        };
        println!("script len:{:?}", segment_script.len());

        let mut segment_hint = vec![];
        segment_hint.append(&mut double_loop_hints_state[i]);
        segment_hint.append(&mut add_loop_hints_state[i]);
        segment_hint.append(&mut double_loop_hints_state[i+1]);
        segment_hint.append(&mut add_loop_hints_state[i+1]);

        let mut step1 = G1PointType::new(assigner, &format!("step{}", i));
        step1.fill_with_data(G1PointData(step_state[i]));
        let mut step2 = G1PointType::new(assigner, &format!("step{}", i + 1));
        step2.fill_with_data(G1PointData(step_state[i+1]));

        let mut result = G1PointType::new(assigner, &format!("result{}", (i+1)/2));
        result.fill_with_data(G1PointData(intermediate_result[(i+1)/2]));

        let mut segment_i = Segment::new(segment_script)
            .add_parameter(&prev_result.clone())
            .add_parameter(&step1)
            .add_parameter(&step2)
            .add_result(&result)
            .add_hint(segment_hint);

        for scalar_bit in scalar_state[i/2].iter() {
                segment_i = segment_i.add_parameter(scalar_bit);
            }
        if i != 19 {
            for scalar_bit in scalar_state[i/2 + 1].iter() {
                segment_i = segment_i.add_result(scalar_bit);
            }
        }

        segment.push(segment_i);

        prev_result = result;

        i+=2;
    }

    (segment, prev_result)
}

#[cfg(test)]
mod test {
    use ark_bn254::{Fr, G1Affine};
    use ark_ec::CurveGroup;
    use ark_ff::UniformRand;
    use ark_std::test_rng;

    use crate::{bn254::msm::prepare_msm_input, chunker::assigner::DummyAssinger};

    use super::hinted_scalar_mul_by_constant_g1_affine;

    #[test]
    fn test_msm_script_len() {
        let mut assigner = DummyAssinger {};
        let k = 0;
        let n = 1 << k;
        let rng = &mut test_rng();

        let scalars = (0..n).map(|_| ark_bn254::Fr::rand(rng)).collect::<Vec<_>>();

        let mut bases = (0..n)
            .map(|_| ark_bn254::G1Projective::rand(rng).into_affine())
            .collect::<Vec<_>>();
        let (inner_coeffs, _) = prepare_msm_input(&bases, &scalars, 12);

        let _ = hinted_scalar_mul_by_constant_g1_affine(    
            &mut assigner,    
            "no_prefix",    
            scalars[0],
            &mut bases[0],
            inner_coeffs[0].0.clone(),
            inner_coeffs[0].1.clone(),
        );
    }
}