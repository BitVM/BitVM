use std::cmp::min;

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{AdditiveGroup, BigInteger, PrimeField};
use bitcoin_script::script;
use crate::chunker::elements::DataType::G1PointData;

use crate::chunker::segment;
use crate::{bn254::{curves::G1Affine, fp254impl::Fp254Impl, fr::Fr}, chunker::elements::{ElementTrait, G1PointType}};

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
    trace: Vec<ark_bn254::G1Affine>,
) -> (Vec<Segment>, G1PointType) {
    let mut coeff_iter = coeff.iter();
    let mut step_p_iter = step_p.iter();
    let mut trace_iter = trace.iter();
    let mut i = 0;
    // options: i_step = 2-15
    let i_step = 12;

    // precomputed lookup table (affine)
    let mut p_mul: Vec<ark_bn254::G1Affine> = Vec::new();
    p_mul.push(ark_bn254::G1Affine::zero());
    for _ in 1..(1 << i_step) {
        p_mul.push((p_mul.last().unwrap().clone() + p.clone()).into_affine());
    }

    // prepare for segment
    let mut double_c_temp = vec![];
    let mut step_temp = vec![];
    let mut double_coeff_temp = vec![];
    let mut add_c_temp = vec![];
    let mut p_mul_mask_temp = vec![];
    let mut add_coeff_temp = vec![];
    let mut double_loop_script_temp = vec![];
    let mut double_loop_hints_temp = vec![];
    let mut add_loop_script_temp = vec![];
    let mut add_loop_hints_temp = vec![];
    let mut intermediate_result = vec![];
    let mut dfs_script_0 = script!();
    
    let mut c: ark_bn254::G1Affine = ark_bn254::G1Affine::zero();

    let scalar_bigint = scalar.into_bigint();
    while i < Fr::N_BITS {
        let depth = min(Fr::N_BITS - i, i_step);
        // double(step-size) point
        if i > 0 {
            let double_coeff = coeff_iter.next().unwrap();
            let step = step_p_iter.next().unwrap();
            
            double_c_temp.push(c);
            step_temp.push(*step);
            double_coeff_temp.push(double_coeff);

            let (double_loop_script, doulbe_hints) = G1Affine::hinted_check_add(c, *step, double_coeff.0, double_coeff.1);
            double_loop_script_temp.push(double_loop_script);
            double_loop_hints_temp.push(doulbe_hints);

            // let double_loop = script! {
            //     // query bucket point through lookup table
            //     { G1Affine::push_not_montgomery(*step) }
            //     // check before usage
            //     { double_loop_script }
            // };

            c = (c + *step).into_affine();
        } 
        // if i == i_step * 2 {
        //     break;
        // }

        // squeeze a bucket scalar
        // loop_scripts.push(script! {
        //     for _ in 0..depth {
        //         OP_FROMALTSTACK
        //     }
        // });

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

        if i > 0 {
            add_c_temp.push(c);
            p_mul_mask_temp.push(p_mul[mask as usize]);
            add_coeff_temp.push(add_coeff);
        }

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
            add_loop_script_temp.push(add_loop);
            add_loop_hints_temp.push(add_hints);
        }

        if mask != 0  {
            c = (c + p_mul[mask as usize]).into_affine();
        }

        if i % 2 != 0 {
            intermediate_result.push(c);
        }

        i += i_step;
    }
    assert!(coeff_iter.next() == None);
    assert!(step_p_iter.next() == None);
    assert!(trace_iter.next() == None);
    *p = c;

    let mut segment = vec![];

    let segment_script0 = script! {
        // query bucket point through lookup table
        { Fr::convert_to_le_bits_toaltstack() }
        { dfs_script_0 }
        {double_loop_script_temp[0].clone()}
        {add_loop_script_temp[0].clone()}  
    };

    let mut segment_hint0 = vec![];

    segment_hint0.append(&mut double_loop_hints_temp[0]);
    segment_hint0.append(&mut add_loop_hints_temp[0]);


    let mut step0 = G1PointType::new(assigner, "step0");
    step0.fill_with_data(G1PointData(step_temp[0]));
    let mut result0 = G1PointType::new(assigner, "result0");
    result0.fill_with_data(G1PointData(intermediate_result[0]));

    let segment0 = Segment::new(segment_script0)
        .add_parameter(&step0)
        .add_result(&result0)
        .add_hint(segment_hint0);

    segment.push(segment0);

    let mut prev_result = result0;
    let mut i = 1;

    //two double_loop + add_loop as a sengment
    while i < 20 {
        let segment_script = script! {
            {double_loop_script_temp[i].clone()}
            {add_loop_script_temp[i].clone()}
            {double_loop_script_temp[i+1].clone()}
            {add_loop_script_temp[i+1].clone()}    
        };

        let mut segment_hint = vec![];
        segment_hint.append(&mut double_loop_hints_temp[i]);
        segment_hint.append(&mut add_loop_hints_temp[i]);
        segment_hint.append(&mut double_loop_hints_temp[i+1]);
        segment_hint.append(&mut add_loop_hints_temp[i+1]);

        let mut step1 = G1PointType::new(assigner, &format!("step{}", i));
        step1.fill_with_data(G1PointData(step_temp[i]));
        let mut step2 = G1PointType::new(assigner, &format!("step{}", i + 1));
        step2.fill_with_data(G1PointData(step_temp[i+1]));

        let mut result = G1PointType::new(assigner, &format!("result{}", (i+1)/2));
        result.fill_with_data(G1PointData(intermediate_result[(i+1)/2]));

        let segment_i = Segment::new(segment_script)
            .add_parameter(&prev_result.clone())
            .add_parameter(&step1)
            .add_parameter(&step2)
            .add_result(&result)
            .add_hint(segment_hint);

        segment.push(segment_i);

        prev_result = result;
        i+=2;
    }

    (segment, prev_result)
}