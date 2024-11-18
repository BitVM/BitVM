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
    chunk_fq12_multiplication(assigner, prefix, pa,pb, a,b)
}

/// a * b -> c
pub fn chunk_fq12_multiplication<T: BCAssigner>(
    assigner: &mut T,
    prefix: &str,
    pa: Fq12Type,
    pb: Fq12Type,
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

    let segment1 = Segment::new_with_name(
        format!("{}{}", prefix, "a0 * b0"), 
        script! {
            //[a0,a1, b0, b1]
            {Fq6::drop()}
            //[a0,a1, b0]
            {Fq6::roll(6)}
            //[a0, b0, a1]
            {Fq6::drop()}
            // [a0, b0]
            {hinted_script1}
        }
        )
        .add_parameter(&pa)
        .add_parameter(&pb)
        .add_result(&a0b0)
        .add_hint(hint1);

    let segment2 = Segment::new_with_name(format!("{}{}", prefix, "a1 * b1"), 
        script! {
            //[a0,a1, b0, b1]
            {Fq6::roll(6)}
            //[a0,a1, b1, b0]
            {Fq6::drop()}
            //[a0,a1, b1]
            {Fq6::roll(12)}
            //[a1, b1, a0]
            {Fq6::drop()}
            // [a1, b1]
            {hinted_script2}
        }
        )
        .add_parameter(&pa)
        .add_parameter(&pb)
        .add_result(&a1b1)
        .add_hint(hint2);

    let segment4 = Segment::new_with_name(
        format!("{}{}", prefix, "(a0 + a1) * (b0 + b1)"),
        script! {
            {Fq6::add(0, 6)}
            {Fq6::add(6, 12)}
            {Fq6::roll(6)}
            {hinted_script3}
        },
    )
    .add_parameter(&pa)
    .add_parameter(&pb)
    .add_result(&ab)
    .add_hint(hint3);


    let mut tc = Fq12Type::new(assigner, &format!("{}{}", prefix, "c"));
    tc.fill_with_data(Fq12Data(c));

    let segment6 = Segment::new_with_name(
        format!("{}{}", prefix, "fq6_to_fq12"),
        script! {
            // [ab, a0b0, a1b1]
            {Fq6::copy(6)}
            {Fq6::copy(6)}
            // [ab, a0b0, a1b1, a0b0,a1b1]
            {Fq12::mul_fq6_by_nonresidue()}
            { Fq6::add(6, 0) }
            // [ab, a0b0, a1b1, c0]
            {Fq6::toaltstack()}
            // [ab, a0b0, a1b1 | c0]
            {Fq6::add(0, 6)}
            {Fq6::sub(6, 0)}
            // [c1 | c0]
            {Fq6::fromaltstack()}
            // [c1, c0]
            {Fq6::roll(6)}
            // [c0, c1]
        },
    )
    .add_parameter(&ab)
    .add_parameter(&a0b0)
    .add_parameter(&a1b1)
    .add_result(&tc);

    (
        vec![
            segment1, segment2, /*segment3,*/ segment4, /*segment5,*/ segment6, /*segment7,*/
        ],
        tc,
    )
}

#[cfg(test)]
mod test {
    use super::{chunk_fq12_multiplication, fq12_mul_wrapper};
    use crate::{
        chunker::{
            assigner::DummyAssinger,
            elements::{DataType::Fq12Data, DataType::Fq6Data, ElementTrait, Fq12Type, Fq6Type},
            segment::{Segment},
        }, execute_script_with_inputs,
    };
    use ark_ff::UniformRand;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::ops::Mul;

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

            let mut lenw = 0;
            for w in witness.clone() {
                lenw += w.len();
            }
            println!("segment name {} script size {} witness size {}", segment.name, segment.script.clone().len(),lenw );

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
