use super::elements::{DataType::Fq12Data, DataType::Fq6Data, ElementTrait, Fq12Type, Fq6Type};
use super::{assigner::BCAssigner, segment::Segment};
use crate::bn254::fq12::Fq12;
use crate::bn254::fq6::Fq6;
use crate::treepp::*;
use std::ops::{Add, Mul};

/// a * b -> c
pub fn fq12_mul_wrapper<T: BCAssigner>(
    assigner: &mut T,
    prefix: &str,
    pa: Fq12Type,
    pb: Fq12Type,
    a: ark_bn254::Fq12,
    b: ark_bn254::Fq12,
) -> (Vec<Segment>, Fq12Type) {
    let mut segments = Vec::new();

    let mut ta0 = Fq6Type::new(assigner, &format!("{}{}", prefix, "a0"));
    ta0.fill_with_data(Fq6Data(a.c0));
    let mut ta1 = Fq6Type::new(assigner, &format!("{}{}", prefix, "a1"));
    ta1.fill_with_data(Fq6Data(a.c1));
    let mut tb0 = Fq6Type::new(assigner, &format!("{}{}", prefix, "b0"));
    tb0.fill_with_data(Fq6Data(b.c0));
    let mut tb1 = Fq6Type::new(assigner, &format!("{}{}", prefix, "b1"));
    tb1.fill_with_data(Fq6Data(b.c1));

    let segment0 = Segment::new_with_name(
        format!("{}{}", prefix, "fq12_to_fq6"),
        script! {
            // todo
        },
    )
    .add_parameter(&pa)
    .add_parameter(&pb)
    .add_result(&ta0)
    .add_result(&ta1)
    .add_result(&tb0)
    .add_result(&tb1);

    segments.push(segment0);

    let (segment1, mul) = fq12_mul(assigner, prefix, ta0, ta1, tb0, tb1, a, b);
    segments.extend(segment1);

    (segments, mul)
}

/// a * b -> c
pub fn fq12_mul<T: BCAssigner>(
    assigner: &mut T,
    prefix: &str,
    a0: Fq6Type,
    a1: Fq6Type,
    b0: Fq6Type,
    b1: Fq6Type,
    a: ark_bn254::Fq12,
    b: ark_bn254::Fq12,
) -> (Vec<Segment>, Fq12Type) {
    let c = a.mul(b);
    let (hinted_script1, hint1) = Fq6::hinted_mul(6, a.c0, 0, b.c0);
    let (hinted_script2, hint2) = Fq6::hinted_mul(6, a.c1, 0, b.c1);
    let (hinted_script3, hint3) = Fq6::hinted_mul(6, a.c0 + a.c1, 0, b.c0 + b.c1);

    // intermediate states
    let mut a0b0 = Fq6Type::new(assigner, &format!("{}{}", prefix, "a0b0"));
    let mut a1b1 = Fq6Type::new(assigner, &format!("{}{}", prefix, "a1b1"));
    let mut a0_a1 = Fq6Type::new(assigner, &format!("{}{}", prefix, "a0_a1")); // means a0+a1
    let mut b0_b1 = Fq6Type::new(assigner, &format!("{}{}", prefix, "b0_b1")); // means b0+b1
    let mut ab = Fq6Type::new(assigner, &format!("{}{}", prefix, "a0_a1 * b0_b1"));

    a0b0.fill_with_data(Fq6Data(a.c0.mul(b.c0)));
    a1b1.fill_with_data(Fq6Data(a.c1.mul(b.c1)));
    a0_a1.fill_with_data(Fq6Data(a.c0.add(a.c1)));
    b0_b1.fill_with_data(Fq6Data(b.c0.add(b.c1)));
    ab.fill_with_data(Fq6Data(a.c0.add(a.c1).mul(b.c0.add(b.c1))));

    // final states
    let mut c0 = Fq6Type::new(assigner, &format!("{}{}", prefix, "c0"));
    let mut c1 = Fq6Type::new(assigner, &format!("{}{}", prefix, "c1"));

    c0.fill_with_data(Fq6Data(c.c0));
    c1.fill_with_data(Fq6Data(c.c1));

    let segment1 = Segment::new_with_name(format!("{}{}", prefix, "a0 * b0"), hinted_script1)
        .add_parameter(&a0)
        .add_parameter(&b0)
        .add_result(&a0b0)
        .add_hint(hint1);

    let segment2 = Segment::new_with_name(format!("{}{}", prefix, "a1 * b1"), hinted_script2)
        .add_parameter(&a1)
        .add_parameter(&b1)
        .add_result(&a1b1)
        .add_hint(hint2);

    let segment3 = Segment::new_with_name(
        format!("{}{}", prefix, "a0 + a1, b0 + b1"),
        script! {
            {Fq6::add(0, 6)}
            {Fq6::add(6, 12)}
        },
    )
    .add_parameter(&a0)
    .add_parameter(&a1)
    .add_parameter(&b0)
    .add_parameter(&b1)
    .add_result(&b0_b1)
    .add_result(&a0_a1);

    let segment4 = Segment::new_with_name(
        format!("{}{}", prefix, "(a0 + a1) * (b0 + b1)"),
        hinted_script3,
    )
    .add_parameter(&a0_a1)
    .add_parameter(&b0_b1)
    .add_result(&ab)
    .add_hint(hint3);

    let segment5 = Segment::new_with_name(
        format!("{}{}", prefix, "nonresidue(a0b0)"),
        script! {
            {Fq12::mul_fq6_by_nonresidue()}
            { Fq6::add(6, 0) }
        },
    )
    .add_parameter(&a0b0)
    .add_parameter(&a1b1)
    .add_result(&c0);

    let segment6 = Segment::new_with_name(
        format!("{}{}", prefix, "fq6_to_fq12"),
        script! {
            {Fq6::add(0, 6)}
            {Fq6::sub(6, 0)}
        },
    )
    .add_parameter(&ab)
    .add_parameter(&a0b0)
    .add_parameter(&a1b1)
    .add_result(&c1);

    let mut tc = Fq12Type::new(assigner, &format!("{}{}", prefix, "c"));
    tc.fill_with_data(Fq12Data(c));
    let segment7 = Segment::new_with_name(
        format!("{}{}", prefix, "convert_fq6_to_fq12"),
        script! {})
        .add_parameter(&c0)
        .add_parameter(&c1)
        .add_result(&tc);

    (
        vec![
            segment1, segment2, segment3, segment4, segment5, segment6, segment7,
        ],
        tc,
    )
}

#[cfg(test)]
mod test {
    use super::{fq12_mul, fq12_mul_wrapper};
    use crate::{
        bn254::{
            ell_coeffs::G2Prepared,
            fq12::Fq12,
            utils::{fq12_push_not_montgomery, hinted_ell_by_constant_affine},
        },
        chunker::{
            assigner::DummyAssinger,
            elements::{DataType::Fq12Data, DataType::Fq6Data, ElementTrait, Fq12Type, Fq6Type},
            segment::{self, Segment},
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

        // Output segment with data
        a0.fill_with_data(Fq6Data(a.c0));
        a1.fill_with_data(Fq6Data(a.c1));
        b0.fill_with_data(Fq6Data(b.c0));
        b1.fill_with_data(Fq6Data(b.c1));

        let (filled_segments, _): (Vec<Segment>, Fq12Type) =
            fq12_mul(&mut assigner, "test_", a0, a1, b0, b1, a, b);

        for segment in filled_segments {
            let witness = segment.witness(&assigner);
            let script = segment.script(&assigner);

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

        // // Get witness and script
        // let script0 = segments[0].script(&assigner);
        // let witness0 = filled_segments[0].witness(&assigner);

        // // Check the consistency between script and witness
        // println!("witness len {}", witness0.len());
        // println!("script len {}", script0.len());

        // let res = execute_script_with_inputs(script0, witness0);
        // println!("res.successs {}", res.success);
        // println!("res.stack len {}", res.final_stack.len());
        // println!("rse.remaining: {}", res.remaining_script);
        // println!("res: {:1000}", res);
    }

    #[test]
    fn test_fq12_wrapper() {
        let mut assigner = DummyAssinger {};

        let mut a_type = Fq12Type::new(&mut assigner, "a");
        let mut b_type = Fq12Type::new(&mut assigner, "b");

        let mut prng: ChaCha20Rng = ChaCha20Rng::seed_from_u64(0);
        let a = ark_bn254::Fq12::rand(&mut prng);
        let b = ark_bn254::Fq12::rand(&mut prng);
        let c = a.mul(&b);

        // Output segment with data
        a_type.fill_with_data(Fq12Data(a));
        b_type.fill_with_data(Fq12Data(b));

        let (filled_segments, c): (Vec<Segment>, Fq12Type) =
            fq12_mul_wrapper(&mut assigner, "test_", a_type, b_type, a, b);

        println!("segements num {}", filled_segments.len());

        for segment in filled_segments {
            let witness = segment.witness(&assigner);
            let script = segment.script(&assigner);

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
