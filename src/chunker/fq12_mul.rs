use super::elements::{DataType::Fq6Data, DataType::Fq12Data,ElementTrait, Fq6Type,Fq12Type};
use super::{assigner::BCAssigner, segment::Segment};
use crate::bn254::fq12::Fq12;
use crate::bn254::fq6::Fq6;
use crate::bn254::utils::fq6_push_not_montgomery;
use crate::treepp::*;
use std::ops::{Add, Mul};

/// a * b -> c
pub fn fq12_mul_wrapper<T: BCAssigner>(
    assigner: &mut T,
    prefix: &str,
    mut a: ark_bn254::Fq12,
    mut b: ark_bn254::Fq12,
) -> (Vec<Segment>, Fq12Type) {
    let mut ta0 = Fq6Type::new(assigner, &format!("{}{}",prefix,"a0"));
    ta0.fill_with_data(Fq6Data(a.c0));
    let mut ta1 = Fq6Type::new(assigner, &format!("{}{}",prefix,"a1"));
    ta1.fill_with_data(Fq6Data(a.c1));
    let mut tb0 = Fq6Type::new(assigner, &format!("{}{}",prefix,"b0"));
    tb0.fill_with_data(Fq6Data(b.c0));
    let mut tb1 = Fq6Type::new(assigner, &format!("{}{}",prefix,"b1"));
    tb0.fill_with_data(Fq6Data(b.c1));

    fq12_mul(assigner,prefix,ta0,ta1,tb0,tb1,a,b)
}

/// a * b -> c
pub fn fq12_mul<T: BCAssigner>(
    assigner: &mut T,
    prefix: &str,
    a0: Fq6Type,
    a1: Fq6Type,
    b0: Fq6Type,
    b1: Fq6Type,
    mut a: ark_bn254::Fq12,
    mut b: ark_bn254::Fq12,
) -> (Vec<Segment>, Fq12Type) {
    let c = a.mul(b);
    let (hinted_script1, hint1) = Fq6::hinted_mul(6, a.c0, 0, b.c0);
    let (hinted_script2, hint2) = Fq6::hinted_mul(6, a.c1, 0, b.c1);
    let (hinted_script3, hint3) = Fq6::hinted_mul(6, a.c0 + a.c1, 0, b.c0 + b.c1);

    // intermediate states
    let mut a0b0 = Fq6Type::new(assigner, &format!("{}{}",prefix,"a0b0"));
    let mut a0b1 = Fq6Type::new(assigner, &format!("{}{}",prefix,"a0b1"));
    let mut a0_a1 = Fq6Type::new(assigner, &format!("{}{}",prefix,"a0_a1")); // means a0+a1
    let mut b0_b1 = Fq6Type::new(assigner, &format!("{}{}",prefix,"b0_b1")); // means b0+b1
    let mut ab = Fq6Type::new(assigner, &format!("{}{}",prefix,"a0_a1 * b0_b1"));

    a0b0.fill_with_data(Fq6Data(a.c0.mul(b.c0)));
    a0b1.fill_with_data(Fq6Data(a.c0.mul(b.c1)));
    a0_a1.fill_with_data(Fq6Data(a.c0.add(a.c1)));
    b0_b1.fill_with_data(Fq6Data(b.c0.add(b.c1)));
    ab.fill_with_data(Fq6Data(a.c0.add(a.c1).mul(b.c0.add(b.c1))));

    // final states
    let mut c0 = Fq6Type::new(assigner, &format!("{}{}",prefix,"c0"));
    let mut c1 = Fq6Type::new(assigner, &format!("{}{}",prefix,"c1"));

    c0.fill_with_data(Fq6Data(c.c0));
    c1.fill_with_data(Fq6Data(c.c1));

    let segment1 = Segment::new(hinted_script1)
        .add_parameter(&a0)
        .add_parameter(&b0)
        .add_result(&a0b0)
        .add_hint(hint1);

    let segment2 = Segment::new(hinted_script2)
        .add_parameter(&a0)
        .add_parameter(&b1)
        .add_result(&a0b1)
        .add_hint(hint2);

    let segment3 = Segment::new(script! {
        {Fq6::add(0, 6)}
        {Fq6::add(6, 12)}
    })
    .add_parameter(&a0)
    .add_parameter(&a1)
    .add_parameter(&b1)
    .add_result(&a0_a1)
    .add_result(&b0_b1);

    let segment4 = Segment::new(hinted_script3)
        .add_parameter(&a0_a1)
        .add_parameter(&b0_b1)
        .add_result(&ab)
        .add_hint(hint3);

    let segment5 = Segment::new(Fq12::mul_fq6_by_nonresidue())
        .add_parameter(&a0b0)
        .add_result(&c0);

    let segment6 = Segment::new(script! {
        {Fq6::add(0, 6)}
        {Fq6::sub(6, 0)}
    })
    .add_parameter(&ab)
    .add_parameter(&a0b0)
    .add_parameter(&a0b1)
    .add_result(&c1);


    let mut tc = Fq12Type::new(assigner, &format!("{}{}",prefix,"c"));
    tc.fill_with_data(Fq12Data(c));
    let segment7 = Segment::new(script! {
        // todo
    })
    .add_parameter(&c0)
    .add_parameter(&c1)
    .add_result(&tc);

    (
        vec![segment1, segment2, segment3, segment4, segment5, segment6, segment7],
        tc,
    )
}

#[cfg(test)]
mod test {
    use super::fq12_mul;
    use crate::{
        bn254::{
            ell_coeffs::G2Prepared,
            fq12::Fq12,
            utils::{ell,fq12_push_not_montgomery, hinted_ell_by_constant_affine, hinted_from_eval_point},
        },
        chunker::{
            assigner::DummyAssinger,
            elements::{DataType::Fq6Data, DataType::Fq12Data, ElementTrait, Fq6Type, Fq12Type},
            segment::Segment,
        },
        execute_script, execute_script_with_inputs,
        hash::blake3_u32::blake3_var_length,
        treepp::script,
    };
    use ark_ff::{Field, UniformRand};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::ops::Mul;

    #[test]
    fn test_fq12() {
        let mut assigner = DummyAssinger {};

        let mut a0 = Fq6Type::new(&mut assigner, "a0");
        let mut a1 = Fq6Type::new(&mut assigner, "a1");
        let mut b0 = Fq6Type::new(&mut assigner, "b0");
        let mut b1 = Fq6Type::new(&mut assigner, "b1");

        let mut prng: ChaCha20Rng = ChaCha20Rng::seed_from_u64(0);
        let a = ark_bn254::Fq12::rand(&mut prng);
        let b = ark_bn254::Fq12::rand(&mut prng);
        let c = a.mul(&b);

        // Output segment without data
        let (segments, c): (Vec<Segment>, Fq12Type) = fq12_mul(
            &mut assigner,
            "no_prefix",
            a0.clone(),
            a1.clone(),
            b0.clone(),
            b1.clone(),
            a,
            b,
        );

        // Output segment with data
        a0.fill_with_data(Fq6Data(a.c0));
        a1.fill_with_data(Fq6Data(a.c1));
        b0.fill_with_data(Fq6Data(b.c0));
        b1.fill_with_data(Fq6Data(b.c1));
        let (filled_segments, c): (Vec<Segment>, Fq12Type) =
            fq12_mul(&mut assigner, "no_prefix", a0, a1, b0, b1, a, b);

        // Get witness and script
        let script0 = segments[0].script(&assigner);
        let witness0 = filled_segments[0].witness(&assigner);

        // Check the consistency between script and witness
        println!("witness len {}", witness0.len());
        println!("script len {}", script0.len());

        let res = execute_script_with_inputs(script0, witness0);
        println!("res.successs {}", res.success);
        println!("res.stack len {}", res.final_stack.len());
        println!("rse.remaining: {}", res.remaining_script);
        println!("res: {:1000}", res);
    }

    #[test]
    fn test_frobenius_map() {
        let map = Fq12::hinted_frobenius_map(1, ark_bn254::Fq12::ONE);
        println!(
            "estimate script size for frobenius map 1 {}",
            blake3_var_length(9 * 12).len()
                + blake3_var_length(9 * 12).len()
                + map.0.len()
                + map.1.iter().fold(0, |x, hint| x + hint.push().len())
        );
        let map = Fq12::hinted_frobenius_map(2, ark_bn254::Fq12::ONE);
        println!(
            "estimate script size for frobenius map 2 {}",
            blake3_var_length(9 * 12).len()
                + blake3_var_length(9 * 12).len()
                + map.0.len()
                + map.1.iter().fold(0, |x, hint| x + hint.push().len())
        );
    }

    #[test]
    fn test_hinted_ell_by_constant_affine() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let f = ark_bn254::Fq12::rand(&mut prng);
        let b = ark_bn254::g2::G2Affine::rand(&mut prng);
        let p = ark_bn254::g1::G1Affine::rand(&mut prng);

        // affine mode
        let coeffs = G2Prepared::from_affine(b);
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
        println!(
            "total bytes {}",
            ell_by_constant_affine_script.len()
                + blake3_var_length(9 * 12).len()
                + blake3_var_length(9 * 12).len()
                + blake3_var_length(9 * 2 * 2).len()
                + hints.iter().fold(0, |x, hint| x + hint.push().len())
        );

        println!(
            "chunk0 size {}",
            271456
                + blake3_var_length(9 * 12).len()
                + blake3_var_length(9 * 2).len()
                + blake3_var_length(9 * 12).len()
                + blake3_var_length(9 * 2 * 2).len()
        );

        println!(
            "chunk1 size {}",
            1953847
                + blake3_var_length(9 * 12).len()
                + blake3_var_length(9 * 2 * 2).len()
                + blake3_var_length(9 * 12).len()
        );
    }
    
    #[test]
    fn test_hinted_square() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let mut max_stack = 0;

        for _ in 0..1 {
            let a = ark_bn254::Fq12::rand(&mut prng);
            let b = a.square();

            let (hinted_square, hints) = Fq12::hinted_square(a);
            println!(
                "hinted_square script {} bytes",hinted_square.len()
            );
            println!(
                "hinted_square total script {} bytes",
                blake3_var_length(9 * 12).len()  // input
                    + 9 * 12
                    + hinted_square.len()  // script
                    + hints.iter().fold(0, |x, hint| x + hint.push().len()) //hints
                    + blake3_var_length(9 * 12).len() // result
            );

            let script = script! {
                for hint in hints { 
                    { hint.push() }
                }
                { fq12_push_not_montgomery(a) }
                { hinted_square.clone() }
                // { fq12_push_not_montgomery(b) }
                // { Fq12::equalverify() }
                // OP_TRUE
            };
            let exec_result = execute_script(script);
            // assert!(exec_result.success);
            println!("exec_result {}", exec_result);
        }
    }
}
