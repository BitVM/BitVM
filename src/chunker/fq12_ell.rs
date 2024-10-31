use super::elements::{
    DataType::Fq12Data, DataType::Fq2Data, DataType::FqData, ElementTrait, Fq12Type, Fq2Type,
    FqType,
};
use super::{assigner::BCAssigner, segment::Segment};
use crate::bn254::{ell_coeffs::EllCoeff, fp254impl::Fp254Impl, fq::Fq, fq12::Fq12};
use crate::treepp::*;
use ark_ff::Field;

pub fn fq12_ell_wrapper<T: BCAssigner>(
    assigner: &mut T,
    prefix: &str,
    f: ark_bn254::Fq12,
    x: ark_bn254::Fq,
    y: ark_bn254::Fq,
    constant: &EllCoeff,
) -> (Vec<Segment>, Fq12Type) {
    let mut pf = Fq12Type::new(assigner, &format!("{}{}", prefix, "f"));
    pf.fill_with_data(Fq12Data(f));
    let mut px = FqType::new(assigner, &format!("{}{}", prefix, "x"));
    px.fill_with_data(FqData(x));
    let mut py = FqType::new(assigner, &format!("{}{}", prefix, "y"));
    py.fill_with_data(FqData(y));

    fq12_ell(assigner, prefix, pf, px, py, f, x, y, constant)
}

pub fn fq12_ell<T: BCAssigner>(
    assigner: &mut T,
    prefix: &str,
    pf: Fq12Type,
    px: FqType,
    py: FqType,
    f: ark_bn254::Fq12,
    x: ark_bn254::Fq,
    y: ark_bn254::Fq,
    constant: &EllCoeff,
) -> (Vec<Segment>, Fq12Type) {
    assert_eq!(constant.0, ark_bn254::Fq2::ONE);

    let (hinted_script1, hint1) = Fq::hinted_mul_by_constant(x, &constant.1.c0);
    let (hinted_script2, hint2) = Fq::hinted_mul_by_constant(x, &constant.1.c1);
    let (hinted_script3, hint3) = Fq::hinted_mul_by_constant(y, &constant.2.c0);
    let (hinted_script4, hint4) = Fq::hinted_mul_by_constant(y, &constant.2.c1);
    let mut c1 = constant.1;
    c1.mul_assign_by_fp(&x);
    let mut c2 = constant.2;
    c2.mul_assign_by_fp(&y);

    let script_lines_0 = vec![
        // [x', y']
        // update c1, c1' = x' * c1
        Fq::copy(1),
        hinted_script1,
        // [ x', y', x' * c1.0]
        Fq::roll(2),
        hinted_script2,
        // [y', x' * c1.0, x' * c1.1]
        // [y', x' * c1]

        // update c2, c2' = -y' * c2
        Fq::copy(2),
        hinted_script3, // Fq::mul_by_constant(&constant.2.c0),
        // [y', x' * c1, y' * c2.0]
        Fq::roll(3),
        hinted_script4,
        // [x' * c1, y' * c2.0, y' * c2.1]
        // [x' * c1, y' * c2]
        // [c1', c2']
    ];
    let mut script_0 = script! {};
    for script_line_0 in script_lines_0 {
        script_0 = script_0.push_script(script_line_0.compile());
    }
    let mut hints_0 = Vec::new();
    hints_0.extend(hint1);
    hints_0.extend(hint2);
    hints_0.extend(hint3);
    hints_0.extend(hint4);
    //
    let mut tc1 = Fq2Type::new(assigner, &format!("{}{}", prefix, "c1"));
    let mut tc2 = Fq2Type::new(assigner, &format!("{}{}", prefix, "c2"));
    tc1.fill_with_data(Fq2Data(c1));
    tc2.fill_with_data(Fq2Data(c2));

    let segment0 = Segment::new(script_0)
        .add_parameter(&px)
        .add_parameter(&py)
        .add_result(&tc1)
        .add_result(&tc2)
        .add_hint(hints_0);

    let mut f1 = f;
    f1.mul_by_034(&constant.0, &c1, &c2);
    let c = f1;
    let mut tc = Fq12Type::new(assigner, &format!("{}{}", prefix, "c"));
    tc.fill_with_data(Fq12Data(c));

    let (script_1, hint_1) = Fq12::hinted_mul_by_34(f, c1, c2);
    //  // compute the new f with c1'(c3) and c2'(c4), where c1 is trival value 1
    //  script_1,
    // // [f, c1', c2']
    //  // [f]
    let segment1 = Segment::new(script_1)
        .add_parameter(&pf)
        .add_parameter(&tc1)
        .add_parameter(&tc2)
        .add_result(&tc)
        .add_hint(hint_1);

    (vec![segment0, segment1], tc)
}

#[cfg(test)]
mod test {
    use super::fq12_ell_wrapper;
    use crate::bn254::ell_coeffs::G2Prepared;
    use crate::bn254::fq12::Fq12;
    use crate::chunker::elements;
    use crate::chunker::{assigner::DummyAssinger, segment};
    use crate::treepp::*;

    use crate::bn254::utils::{
        fq12_push_not_montgomery,
        hinted_from_eval_point,
    };
    use crate::{execute_script_with_inputs};

    use crate::bn254::utils::*;
    use ark_ff::Field;
    use ark_std::UniformRand;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_hinted_ell_by_constant_affine() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let f = ark_bn254::Fq12::rand(&mut prng);
        let b = ark_bn254::g2::G2Affine::rand(&mut prng);
        let p = ark_bn254::g1::G1Affine::rand(&mut prng);

        // affine mode
        let coeffs = G2Prepared::from_affine(b);
        let (from_eval_point_script, hints_eval) = hinted_from_eval_point(p);
        let (ell_by_constant_affine_script, hints) = hinted_ell_by_constant_affine(
            f,
            -p.x / p.y,
            p.y.inverse().unwrap(),
            &coeffs.ell_coeffs[0],
        );
        println!(
            "Pairing.ell_by_constant_affine: {} bytes",
            ell_by_constant_affine_script.len()
        );

        // affine mode as well
        let hint = {
            assert_eq!(coeffs.ell_coeffs[0].0, ark_bn254::fq2::Fq2::ONE);

            let mut f1 = f;
            let mut c1new = coeffs.ell_coeffs[0].1;
            c1new.mul_assign_by_fp(&(-p.x / p.y));

            let mut c2new = coeffs.ell_coeffs[0].2;
            c2new.mul_assign_by_fp(&(p.y.inverse().unwrap()));

            f1.mul_by_034(&coeffs.ell_coeffs[0].0, &c1new, &c2new);
            f1
        };

        let script = script! {
            for tmp in hints_eval {
                { tmp.push() }
            }
            for tmp in hints {
                { tmp.push() }
            }
            { fq12_push_not_montgomery(f) }
            { from_eval_point_script }
            { ell_by_constant_affine_script.clone() }
            { fq12_push_not_montgomery(hint) }
            { Fq12::equalverify() }
            OP_TRUE
        };
        let exec_result = execute_script(script);
        println!("exec_result: {:}", exec_result);
        // assert!(exec_result.success);

        //
        let mut assigner = DummyAssinger {};
        let mut segments = Vec::new();
        let fn_name = format!("F_{}_mul_c_1p{}", 0, 0);
        let (segments_mul, mul): (Vec<segment::Segment>, elements::Fq12Type) = fq12_ell_wrapper(
            &mut assigner,
            &fn_name,
            f,
            -p.x / p.y,
            p.y.inverse().unwrap(),
            &coeffs.ell_coeffs[0],
        );
        segments.extend(segments_mul);

        println!("segments size {}", segments.len());
        for i in 0..segments.len() {
            println!(
                "segment {} script {} input {} output {} hint {}",
                i,
                segments[i].script.len(),
                segments[i].parameter_list.len(),
                segments[i].result_list.len(),
                segments[i].hints.len()
            );
        }

        // Get witness and script
        let script0 = segments[0].script(&assigner);
        let witness0 = segments[0].witness(&assigner);
        // Check the consistency between script and witness
        println!("witness0 len {}", witness0.len());
        println!("script0 len {}", script0.len());
        let res0 = execute_script_with_inputs(script0, witness0);
        println!("res0: {:}", res0);

        // Get witness and script
        let script1 = segments[1].script(&assigner);
        let witness1 = segments[1].witness(&assigner);
        // Check the consistency between script and witness
        println!("witness1 len {}", witness1.len());
        println!("script1 len {}", script1.len());
        let res1 = execute_script_with_inputs(script1, witness1);
        println!("res1: {:}", res1);
    }
}
