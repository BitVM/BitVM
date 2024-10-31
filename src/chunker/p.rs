use super::elements::{FqType, G1PointType};
use super::elements::DataType::FqData;

use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::fq::Fq;
use crate::bn254::utils::{hinted_from_eval_point, Hint,};
use crate::chunker::assigner::*;
use crate::chunker::elements::ElementTrait;
use crate::chunker::segment::Segment;
use crate::treepp::{script, Script};

use ark_bn254::Bn254;
use ark_bn254::G1Projective;
use ark_ec::pairing::Pairing as ark_Pairing;
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::Field;
use ark_groth16::{Proof, VerifyingKey};
use core::ops::Neg;

pub fn p<T: BCAssigner>(
    assigner: &mut T,
    g1p: G1PointType,
    g1a: ark_bn254::G1Affine,
    proof: &Proof<Bn254>,
    vk: &VerifyingKey<Bn254>,
) -> (Vec<Segment>, Vec<FqType>) {
    let mut segments = vec![];
    let (s1, a1, b1) = p1(assigner, g1p, g1a);

    let ( p2, p3, p4) = (proof.c, vk.alpha_g1, proof.a);
    let (hinted_script3, hint3) = hinted_from_eval_point(p2);
    let (hinted_script4, hint4) = hinted_from_eval_point(p3);
    let (hinted_script5, hint5) = hinted_from_eval_point(p4);

    let (s2, a2, b2) = make_chunk_p(
        assigner,
        "F_p2".to_owned(),
        p2,
        hinted_script3.clone(),
        hint3.clone(),
    );
    let (s3, a3, b3) = make_chunk_p(
        assigner,
        "F_p3".to_owned(),
        p3,
        hinted_script4.clone(),
        hint4.clone(),
    );
    let (s4, a4, b4) = make_chunk_p(
        assigner,
        "F_p4".to_owned(),
        p4,
        hinted_script5.clone(),
        hint5.clone(),
    );
    segments.extend(s1);
    segments.extend(s2);
    segments.extend(s3);
    segments.extend(s4);

    let im_var_p = vec![a1, b1, a2, b2, a3, b3, a4, b4];
    (segments, im_var_p)
}


pub fn p1<T: BCAssigner>(
    assigner: &mut T,
    g1p: G1PointType,
    g1a: ark_bn254::G1Affine,
) -> (Vec<Segment>, FqType, FqType) {
    let mut segments = vec![];

    let p1 = g1a;
    let (hinted_script1, hint1) = Fq::hinted_inv(p1.y);
    let (hinted_script2, hint2) = Fq::hinted_mul(1, p1.y.inverse().unwrap(), 0, p1.x.neg());
    let script_lines_p1 = [
        hinted_script1, // Fq::inv(),
        Fq::copy(0),
        Fq::roll(2),
        Fq::neg(0),
        hinted_script2, // Fq::mul()
        Fq::roll(1),
    ];
    let mut script_p1 = script! {};
    for script_line in script_lines_p1 {
        script_p1 = script_p1.push_script(script_line.compile());
    }
    let mut hints_p1 = Vec::new();
    hints_p1.extend(hint1);
    hints_p1.extend(hint2);
    
    let fn_name = "F_p1".to_owned();
    let mut result_p_a = FqType::new(assigner, &format!("{}_o_a", fn_name));
    result_p_a.fill_with_data(FqData(-p1.x / p1.y));
    let mut result_p_b = FqType::new(assigner, &format!("{}_o_b", fn_name));
    result_p_b.fill_with_data(FqData(p1.y.inverse().unwrap()));

    segments.push(
        Segment::new_with_name(fn_name, script_p1)
            .add_parameter(&g1p)
            .add_result(&result_p_a.clone())
            .add_result(&result_p_b.clone())
            .add_hint(hints_p1),
    );

    (segments, result_p_a, result_p_b)

}

pub fn make_chunk_p<T: BCAssigner>(
    assigner: &mut T,
    fn_name: String,
    p: ark_bn254::G1Affine,
    script: Script,
    hint: Vec<Hint>,
) -> (Vec<Segment>, FqType, FqType) {
    let mut segments = vec![];

    let mut result_p_a = FqType::new(assigner, &format!("{}_o_a", fn_name));
    result_p_a.fill_with_data(FqData(-p.x / p.y));
    let mut result_p_b = FqType::new(assigner, &format!("{}_o_b", fn_name));
    result_p_b.fill_with_data(FqData(p.y.inverse().unwrap()));

    segments.push(
        Segment::new_with_name(fn_name, script)
            .add_result(&result_p_a.clone())
            .add_result(&result_p_b.clone())
            .add_hint(hint),
    );
    (segments, result_p_a, result_p_b)
}

#[cfg(test)]
mod test {
    use super::*;
    
    use crate::bn254::{curves::G1Affine, utils::g1_affine_push};
    use crate::bn254::fq::Fq;
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::bn254::msm::hinted_msm_with_constant_bases_affine;
    use crate::bn254::utils::g1_affine_push_not_montgomery;
    use crate::bn254::utils::hinted_from_eval_point;
    use crate::chunker::assigner::*;
    use crate::chunker::elements::DataType::G1PointData;
    use crate::{execute_script_with_inputs, execute_script, execute_script_without_stack_limit};

    use ark_ff::Field;
    use ark_std::UniformRand;
    use num_bigint::BigUint;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use ark_ec::{CurveGroup, VariableBaseMSM};
    use ark_std::{end_timer, start_timer, test_rng};


    #[test]
    fn test_make_chunk_p() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let p = ark_bn254::G1Affine::rand(&mut prng);
        let (ell_by_constant_affine_script, hints) = hinted_from_eval_point(p);
        let script = script! {
            for tmp in hints.clone() {
                { tmp.push() }
            }
            { ell_by_constant_affine_script.clone() }
            { Fq::push_u32_le_not_montgomery(&BigUint::from(-p.x / p.y).to_u32_digits()) }
            { Fq::push_u32_le_not_montgomery(&BigUint::from(p.y.inverse().unwrap()).to_u32_digits()) }
            { Fq::equalverify(2, 0) }
            { Fq::equalverify(1, 0) }
            OP_TRUE
        };
        let exec_result = execute_script(script);
        println!("exec_result: {:}", exec_result);

        println!("chunk:");
        let mut assigner = DummyAssinger {};
        let (segments, r1, r2) = make_chunk_p(
            &mut assigner,
            "test".to_owned(), 
            p,
            ell_by_constant_affine_script.clone(),
            hints.clone(),
        );

        for segment in segments {
            let witness = segment.witness(&assigner);
            let script = segment.script(&assigner);

            let res = execute_script_with_inputs(script.clone(), witness.clone());
            println!("segment exec_result: {}", res);

            let zero: Vec<u8> = vec![];
            assert_eq!(res.final_stack.len(), 1, "{}", segment.name); // only one element left
            assert_eq!(res.final_stack.get(0), zero, "{}", segment.name);
            assert!(
                res.stats.max_nb_stack_items < 1000,
                "{}",
                res.stats.max_nb_stack_items
            );

            let mut lenw = 0;
            for w in witness {
                lenw += w.len();
            }
            assert!(
                script.len() + lenw < 4000000,
                "script and witness len"
            );
        }
    }

    #[test]
    fn test_p1() {
        let k = 2;
        let n = 1 << k;
        let rng = &mut test_rng();

        let scalars = (0..n).map(|_| ark_bn254::Fr::rand(rng)).collect::<Vec<_>>();

        let bases = (0..n)
            .map(|_| ark_bn254::G1Projective::rand(rng).into_affine())
            .collect::<Vec<_>>();

        let expect = ark_bn254::G1Projective::msm(&bases, &scalars).unwrap();
        let expect = expect.into_affine();
        let (msm, hints) = hinted_msm_with_constant_bases_affine(&bases, &scalars);

        let start = start_timer!(|| "collect_script");
        let script = script! {
            for hint in hints {
                { hint.push() }
            }

            { msm.clone() }
            // { g1_affine_push_not_montgomery(expect) }
            // { G1Affine::equalverify() }
            // OP_TRUE
        };
        end_timer!(start);

        println!("hinted_msm_with_constant_bases: = {} bytes", msm.len());
        let start = start_timer!(|| "execute_msm_script");
        let exec_result = execute_script_without_stack_limit(script);
        end_timer!(start);
        // assert!(exec_result.success);
        println!("exec_result {}", exec_result);

        let mut assigner = DummyAssinger {};
        let g1a = expect;
        let mut g1p = G1PointType::new(&mut assigner, &format!("{}", "test"));
        g1p.fill_with_data(G1PointData(g1a));
        let (segments, a,b) = p1(&mut assigner, g1p, g1a);

        for segment in segments {
            let witness = segment.witness(&assigner);
            let script = segment.script(&assigner);

            let res = execute_script_with_inputs(script.clone(), witness.clone());
            println!("segment exec_result: {}", res);

            let zero: Vec<u8> = vec![];
            assert_eq!(res.final_stack.len(), 1, "{}", segment.name); // only one element left
            assert_eq!(res.final_stack.get(0), zero, "{}", segment.name);
            assert!(
                res.stats.max_nb_stack_items < 1000,
                "{}",
                res.stats.max_nb_stack_items
            );

            let mut lenw = 0;
            for w in witness {
                lenw += w.len();
            }
            assert!(
                script.len() + lenw < 4000000,
                "script and witness len"
            );
        }
    }
}