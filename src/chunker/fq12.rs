use crate::layouter::{make_fq6_var, DefaultManager, Segment};
use crate::layouter::{ElelemntType, Element};
use bitcomm::{script, BcManagerIns, BcOperator, SecretGenIns, Winternitz};
use bitvm::bn254::{fq12::Fq12, fq6::Fq6};
use primitives::BCManager;
use std::ops::{Add, Mul};

/// a * b -> c
fn fq12_mul(
    assigner: &mut DefaultManager,
    a0: Element,
    a1: Element,
    b0: Element,
    b1: Element,
    mut a: ark_bn254::Fq12,
    mut b: ark_bn254::Fq12,
) -> (Vec<Segment>, Element, Element) {
    let c = a.mul(b);
    let (hinted_script1, hint1) = Fq6::hinted_mul(6, a.c0, 0, b.c0);
    let (hinted_script2, hint2) = Fq6::hinted_mul(6, a.c1, 0, b.c1);
    let (hinted_script3, hint3) = Fq6::hinted_mul(6, a.c0 + a.c1, 0, b.c0 + b.c1);

    // intermediate states
    let mut a0b0 = make_fq6_var(assigner, "a0b0");
    let mut a0b1 = make_fq6_var(assigner, "a0b1");
    let mut a0_a1 = make_fq6_var(assigner, "a0_a1"); // means a0+a1
    let mut b0_b1 = make_fq6_var(assigner, "b0_b1"); // means b0+b1
    let mut ab = make_fq6_var(assigner, "a0_a1 * b0_b1");

    a0b0.fill_with_fq6(a.c0.mul(b.c0));
    a0b1.fill_with_fq6(a.c0.mul(b.c1));
    a0_a1.fill_with_fq6(a.c0.add(a.c1));
    b0_b1.fill_with_fq6(b.c0.add(b.c1));
    ab.fill_with_fq6(a.c0.add(a.c1).mul(b.c0.add(b.c1)));

    // final states
    let mut c0 = make_fq6_var(assigner, "c0");
    let mut c1 = make_fq6_var(assigner, "c1");

    c0.fill_with_fq6(c.c0);
    c1.fill_with_fq6(c.c1);

    let segment1 = Segment::new(
        script! {
            {hinted_script1}
        },
        vec![a0.clone(), b0.clone()],
        vec![a0b0.clone()],
        hint1,
    );

    let segment2 = Segment::new(
        script! {
            {hinted_script2}
        },
        vec![a0.clone(), b1.clone()],
        vec![a0b1.clone()],
        hint2,
    );

    let segment3 = Segment::new(
        script! {
            {Fq6::add(0, 6)}
            {Fq6::add(6, 12)}
        },
        vec![a0.clone(), a1.clone(), b0.clone(), b1.clone()],
        vec![a0_a1.clone(), b0_b1.clone()],
        vec![],
    );

    let segment4 = Segment::new(
        script! {
            {hinted_script3}
        },
        vec![a0_a1.clone(), b0_b1.clone()],
        vec![ab.clone()],
        hint3,
    );

    let segment5 = Segment::new(
        script! {
            {Fq12::mul_fq6_by_nonresidue()}
        },
        vec![a0b0.clone()],
        vec![c0.clone()],
        vec![],
    );

    let segment6 = Segment::new(
        script! {
            {Fq6::add(0, 6)}
            {Fq6::sub(6, 0)}
        },
        vec![ab.clone(), a0b0.clone(), a0b1.clone()],
        vec![c1.clone()],
        vec![],
    );

    (
        vec![segment1, segment2, segment3, segment4, segment5, segment6],
        c0,
        c1,
    )
}

#[cfg(test)]
mod test {
    use super::fq12_mul;
    use crate::layouter::{make_fq6_var, new_default_manager, DefaultManager, Element, Segment};
    use ark_ff::{Field, UniformRand};
    use bitvm::{
        bn254::{
            ell_coeffs::G2Prepared,
            fq12::Fq12,
            utils::{ell, hinted_ell_by_constant_affine, hinted_from_eval_point},
        },
        execute_script, execute_script_with_inputs,
        hash::blake3_u32::blake3_var_length,
    };
    use primitives::BCommitOperator;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::ops::Mul;

    #[test]
    fn test_fq12() {
        let mut mgr = new_default_manager();
        let mut a0 = make_fq6_var(&mut mgr, "a0");
        let mut a1 = make_fq6_var(&mut mgr, "a1");
        let mut b0 = make_fq6_var(&mut mgr, "b0");
        let mut b1 = make_fq6_var(&mut mgr, "b1");

        let mut prng: ChaCha20Rng = ChaCha20Rng::seed_from_u64(0);
        let a = ark_bn254::Fq12::rand(&mut prng);
        let b = ark_bn254::Fq12::rand(&mut prng);
        let c = a.mul(&b);

        let (segments, c0, c1): (Vec<Segment>, Element, Element) = fq12_mul(
            &mut mgr,
            a0.clone(),
            a1.clone(),
            b0.clone(),
            b1.clone(),
            a,
            b,
        );

        a0.fill_with_fq6(a.c0);
        a1.fill_with_fq6(a.c1);
        b0.fill_with_fq6(b.c0);
        b1.fill_with_fq6(b.c1);

        let (filled_segments, c0, c1): (Vec<Segment>, Element, Element) =
            fq12_mul(&mut mgr, a0, a1, b0, b1, a, b);

        let witness0 = filled_segments[0].witness();
        // FIXME: should be same as the unfilled segments.
        let script0 = filled_segments[0].script();
        println!("witness len {}", witness0.len());
        println!("script len {}", script0.len());
        println!("inner_script len {}", filled_segments[0].script.len());
        println!("total len {}", witness0.len() + script0.len());

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
}
