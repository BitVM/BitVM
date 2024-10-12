use std::cmp::min;

use super::utils::Hint;
use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::utils::fr_push_not_montgomery;
use crate::bn254::{curves::G1Affine, curves::G1Projective, utils::fr_push};
use crate::treepp::*;
use ark_ec::{AdditiveGroup, AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, Field, PrimeField};

pub fn affine_double_line_coeff(
    t: &mut ark_bn254::G1Affine,
    i_step: u32,
) -> ((ark_bn254::Fq, ark_bn254::Fq), ark_bn254::G1Affine) {
    let step_p = t.mul_bigint([(1 << i_step) - 1]).into_affine();
    (affine_add_line_coeff(t, step_p), step_p)
}

pub fn affine_add_line_coeff(
    t: &mut ark_bn254::G1Affine,
    p: ark_bn254::G1Affine,
) -> (ark_bn254::Fq, ark_bn254::Fq) {
    // alpha = (t.y - q.y) / (t.x - q.x)
    // bias = t.y - alpha * t.x
    let alpha = (t.y - p.y) / (t.x - p.x);
    let bias = t.y - alpha * t.x;

    // update T
    // T.x = alpha^2 - t.x - q.x
    // T.y = -bias - alpha * T.x
    let tx = alpha.square() - t.x - p.x;
    t.y = -bias - alpha * tx;
    t.x = tx;

    (alpha, -bias)
}

pub fn collect_scalar_mul_coeff(
    base: ark_bn254::G1Affine,
    scalar: ark_bn254::Fr,
    i_step: u32,
) -> (
    Vec<(ark_bn254::Fq, ark_bn254::Fq)>,
    Vec<ark_bn254::G1Affine>,
    Vec<ark_bn254::G1Affine>,
) {
    if scalar == ark_bn254::Fr::ONE {
        (vec![], vec![], vec![])
    } else {
        // precomputed lookup table (affine)
        let mut p_mul: Vec<ark_bn254::G1Affine> = Vec::new();
        p_mul.push(ark_bn254::G1Affine::zero());
        for _ in 1..(1 << i_step) {
            p_mul.push((p_mul.last().unwrap().clone() + base.clone()).into_affine());
        }

        // split into chunks
        let chunks = scalar
            .into_bigint()
            .to_bits_be()
            .iter()
            .map(|b| if *b { 1_u8 } else { 0_u8 })
            .skip(256 - crate::bn254::fr::Fr::N_BITS as usize)
            .collect::<Vec<_>>()
            .chunks(i_step as usize)
            .map(|slice| slice.into_iter().fold(0, |acc, &b| (acc << 1) + b as u32))
            .collect::<Vec<u32>>();
        assert!(chunks.len() > 0);

        // query lookup table, then double/add based on that
        let mut line_coeff = vec![];
        let mut step_points = vec![];
        let mut trace = vec![];
        let mut t = p_mul[chunks[0] as usize];
        // for check variables
        let mut acc = ark_bn254::G1Projective::from(p_mul[chunks[0] as usize]);
        let mut s = ark_ff::BigInt::<4>::from(chunks[0]);
        trace.push(p_mul[chunks[0] as usize]);
        chunks.iter().skip(1).enumerate().for_each(|(idx, query)| {
            let depth = if (idx == chunks.len() - 2)
                && (crate::bn254::fr::Fr::N_BITS as u32 % i_step != 0)
            {
                crate::bn254::fr::Fr::N_BITS as u32 % i_step
            } else {
                i_step
            };
            let tmp = t.clone();
            let (double_coeff, step_p) = affine_double_line_coeff(&mut t, depth);
            line_coeff.push(double_coeff);
            step_points.push(step_p);
            assert_eq!(tmp + step_p, tmp.mul_bigint([1 << depth]));
            assert_eq!(
                step_p.y().unwrap() - double_coeff.0 * step_p.x().unwrap() + double_coeff.1,
                ark_bn254::Fq::ZERO
            );
            assert_eq!(
                tmp.y().unwrap() - double_coeff.0 * tmp.x().unwrap() + double_coeff.1,
                ark_bn254::Fq::ZERO
            );

            // FOR DEBUG
            s <<= depth;
            for _ in 0..depth {
                acc.double_in_place();
            }
            trace.push(acc.into_affine());

            line_coeff.push(affine_add_line_coeff(&mut t, p_mul[*query as usize]));
            // FOR DEBUG
            acc += ark_bn254::G1Projective::from(p_mul[*query as usize]);
            trace.push(acc.into_affine());
            // TODO: zero point can be ignored
            // if p_mul[*query as usize] != ark_bn254::G1Projective::ZERO {
            //     line_coeff.push(affine_add_line_coeff(&mut t, p_mul[*query as usize]));
            //     // FOR DEBUG
            //     acc += ark_bn254::G1Projective::from(p_mul[*query as usize]);
            // }

            // FOR DEBUG
            s.add_with_carry(&ark_ff::BigInt::<4>::from(*query));
        });
        assert_eq!(s, scalar.into_bigint());
        assert_eq!(acc.into_affine(), (base * scalar).into_affine());

        // return line coefficients of single scalar mul
        (line_coeff, step_points, trace)
    }
}

// line coefficients, denoted as tuple (alpha, bias), for the purpose of affine mode of MSM
pub fn prepare_msm_input(
    bases: &[ark_bn254::G1Affine],
    scalars: &[ark_bn254::Fr],
    i_step: u32,
) -> (
    Vec<(
        Vec<(ark_bn254::Fq, ark_bn254::Fq)>,
        Vec<ark_bn254::G1Affine>,
        Vec<ark_bn254::G1Affine>,
    )>,
    Vec<(ark_bn254::Fq, ark_bn254::Fq)>,
) {
    let groups = bases
        .into_iter()
        .zip(scalars.into_iter())
        .collect::<Vec<_>>();

    // inner part
    let inner_coeffs = groups
        .clone()
        .into_iter()
        .map(|(&base, &scalar)| collect_scalar_mul_coeff(base, scalar, i_step))
        .collect::<Vec<_>>();

    // outer part
    let mut acc = (groups[0].0.clone() * groups[0].1.clone()).into_affine();
    let outer_coeffs = groups
        .into_iter()
        .skip(1)
        .map(|(&base, &scalar)| affine_add_line_coeff(&mut acc, (base * scalar).into_affine()))
        .collect::<Vec<_>>();

    (inner_coeffs, outer_coeffs)
}

// Will compute msm and return the affine point
// Output Stack: [x,y]
pub fn msm(bases: &[ark_bn254::G1Affine], scalars: &[ark_bn254::Fr]) -> Script {
    assert_eq!(bases.len(), scalars.len());
    let bases: Vec<ark_ec::short_weierstrass::Projective<ark_bn254::g1::Config>> =
        bases.iter().map(|&p| p.into()).collect();
    let len = bases.len();
    let scalar_mul = G1Projective::scalar_mul();

    script! {
        // 1. init the sum=0;
        {G1Projective::push_zero()}
        for i in 0..len {
            // 2. scalar mul
            { G1Projective::push(bases[i]) }
            if scalars[i] != ark_bn254::Fr::ONE {
                { fr_push(scalars[i]) }
                { scalar_mul.clone() }
            }

            // 3. sum the base
            { G1Projective::add() }
        }
        // convert into Affine
        { G1Projective::into_affine() }
    }
}

pub fn msm_with_constant_bases_affine(
    bases: &[ark_bn254::G1Affine],
    scalars: &[ark_bn254::Fr],
) -> Script {
    assert_eq!(bases.len(), scalars.len());
    let len = bases.len();
    let i_step = 12_u32;
    let (inner_coeffs, outer_coeffs) = prepare_msm_input(bases, scalars, i_step);
    script! {
        for i in 0..len {
            if scalars[i] != ark_bn254::Fr::ONE {
                { fr_push(scalars[i]) }
                { G1Affine::scalar_mul_by_constant_g1(bases[i], inner_coeffs[i].0.clone(), inner_coeffs[i].1.clone(), inner_coeffs[i].2.clone()) }
            } else {
                { G1Affine::push(bases[i]) }
            }
            // check coeffs before using
            if i > 0 {
                { G1Affine::check_add(outer_coeffs[i - 1].0, outer_coeffs[i - 1].1) }
            }
        }
        // into_affine involving extreem expensive field inversion, X/Z^2 and Y/Z^3, fortunately there's no need to do into_affine any more here
    }
}

pub fn hinted_msm_with_constant_bases_affine(
    bases: &[ark_bn254::G1Affine],
    scalars: &[ark_bn254::Fr],
) -> (Script, Vec<Hint>) {
    assert_eq!(bases.len(), scalars.len());
    let len = bases.len();
    let i_step = 12_u32;
    let (inner_coeffs, outer_coeffs) = prepare_msm_input(bases, scalars, i_step);

    let mut hints = Vec::new();
    let mut hinted_scripts = Vec::new();

    // 1. init the sum=0;
    let mut p = ark_bn254::G1Affine::zero();
    for i in 0..len {
        let mut c = bases[i];
        if scalars[i] != ark_bn254::Fr::ONE {
            let (hinted_script, hint) = G1Affine::hinted_scalar_mul_by_constant_g1(scalars[i], &mut c, inner_coeffs[i].0.clone(), inner_coeffs[i].1.clone(), inner_coeffs[i].2.clone());
            
            hinted_scripts.push(hinted_script);
            hints.extend(hint);
        }
        // check coeffs before using
        if i > 0 {
            let (hinted_script, hint) = G1Affine::hinted_check_add(p, c, outer_coeffs[i - 1].0, outer_coeffs[i - 1].1);
            hinted_scripts.push(hinted_script);
            hints.extend(hint);
        }
    }

        let mut hinted_scripts_iter = hinted_scripts.into_iter();
        let mut script_lines = Vec::new();
    
        // 1. init the sum=0;
        script_lines.push(G1Affine::push_zero());
        for i in 0..len {
            // 2. scalar mul
            if scalars[i] != ark_bn254::Fr::ONE {
                script_lines.push(fr_push_not_montgomery(scalars[i]));
                script_lines.push(hinted_scripts_iter.next().unwrap());
            } else {
                script_lines.push(G1Affine::push(bases[i]));
            }
            // 3. sum the base
            script_lines.push(hinted_scripts_iter.next().unwrap());
        }
        // convert into Affine
        script_lines.push(hinted_scripts_iter.next().unwrap());
    
        let mut script = script! {};
        for script_line in script_lines {
            script = script.push_script(script_line.compile());
        }

        (script, hints)
    // into_affine involving extreem expensive field inversion, X/Z^2 and Y/Z^3, fortunately there's no need to do into_affine any more here
}

// Will compute msm assuming bases are constant and return the affine point
// Output Stack: [x,y]
pub fn msm_with_constant_bases(bases: &[ark_bn254::G1Affine], scalars: &[ark_bn254::Fr]) -> Script {
    assert_eq!(bases.len(), scalars.len());
    let bases: Vec<ark_ec::short_weierstrass::Projective<ark_bn254::g1::Config>> =
        bases.iter().map(|&p| p.into()).collect();
    let len = bases.len();

    println!("len: {len}");
    script! {
        // 1. init the sum=0;
        {G1Projective::push_zero()}
        for i in 0..len {
            // 2. scalar mul
            if scalars[i] != ark_bn254::Fr::ONE {
                { fr_push(scalars[i]) }
                { G1Projective::scalar_mul_by_constant_g1(bases[i]) }
            } else {
                { G1Projective::push(bases[i]) }
            }
            // 3. sum the base
            { G1Projective::add() }
        }
        // convert into Affine
        { G1Projective::into_affine() }
    }
}

pub fn hinted_msm_with_constant_bases(
    bases: &[ark_bn254::G1Affine],
    scalars: &[ark_bn254::Fr],
) -> (Script, Vec<Hint>) {
    assert_eq!(bases.len(), scalars.len());
    let bases: Vec<ark_ec::short_weierstrass::Projective<ark_bn254::g1::Config>> =
        bases.iter().map(|&p| p.into()).collect();
    let len = bases.len();

    let mut hints = Vec::new();
    let mut hinted_scripts = Vec::new();

    // 1. init the sum=0;
    let mut p = ark_bn254::G1Projective::ZERO;
    for i in 0..len {
        // 2. scalar mul
        let mut c = bases[i];
        if scalars[i] != ark_bn254::Fr::ONE {
            let (hinted_script, hint) =
                G1Projective::hinted_scalar_mul_by_constant_g1(scalars[i], &mut c);
            hinted_scripts.push(hinted_script);
            hints.extend(hint);
        }
        // 3. sum the base
        let (hinted_script, hint) = G1Projective::hinted_add(p, c);
        hinted_scripts.push(hinted_script);
        hints.extend(hint);
        p += c;
    }
    // convert into Affine
    let (hinted_script, hint) = G1Projective::hinted_into_affine(p);
    hinted_scripts.push(hinted_script);
    hints.extend(hint);

    let mut hinted_scripts_iter = hinted_scripts.into_iter();
    let mut script_lines = Vec::new();

    // 1. init the sum=0;
    script_lines.push(G1Projective::push_zero());
    for i in 0..len {
        // 2. scalar mul
        if scalars[i] != ark_bn254::Fr::ONE {
            script_lines.push(fr_push_not_montgomery(scalars[i]));
            script_lines.push(hinted_scripts_iter.next().unwrap());
        } else {
            script_lines.push(G1Projective::push_not_montgomery(bases[i]));
        }
        // 3. sum the base
        script_lines.push(hinted_scripts_iter.next().unwrap());
    }
    // convert into Affine
    script_lines.push(hinted_scripts_iter.next().unwrap());

    let mut script = script! {};
    for script_line in script_lines {
        script = script.push_script(script_line.compile());
    }

    (script, hints)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::bn254::utils::g1_affine_push_not_montgomery;
    use crate::bn254::{curves::G1Affine, utils::g1_affine_push};
    use crate::{execute_script, execute_script_without_stack_limit};
    use ark_ec::{CurveGroup, VariableBaseMSM};

    use ark_std::{end_timer, start_timer, test_rng, UniformRand};

    #[test]
    fn test_msm_script() {
        let k = 2;
        let n = 1 << k;
        let rng = &mut test_rng();

        let scalars = (0..n).map(|_| ark_bn254::Fr::rand(rng)).collect::<Vec<_>>();

        let bases = (0..n)
            .map(|_| ark_bn254::G1Projective::rand(rng).into_affine())
            .collect::<Vec<_>>();

        let expect = ark_bn254::G1Projective::msm(&bases, &scalars).unwrap();
        let expect = expect.into_affine();

        let start = start_timer!(|| "collect_script");
        let script = script! {
            { msm(&bases, &scalars) }
            { g1_affine_push(expect) }
            { G1Affine::equalverify() }
            OP_TRUE
        };
        end_timer!(start);

        println!("msm::test_msm_script = {} bytes", script.len());
        let start = start_timer!(|| "execute_msm_script");
        run(script);
        end_timer!(start);
    }

    #[test]
    fn test_msm_with_constant_bases_projective() {
        let k = 1;
        let n = 1 << k;
        let rng = &mut test_rng();

        let scalars = (0..n).map(|_| ark_bn254::Fr::rand(rng)).collect::<Vec<_>>();

        let bases = (0..n)
            .map(|_| ark_bn254::G1Projective::rand(rng).into_affine())
            .collect::<Vec<_>>();

        let expect = ark_bn254::G1Projective::msm(&bases, &scalars).unwrap();
        let expect = expect.into_affine();
        let msm = msm_with_constant_bases(&bases, &scalars);

        let start = start_timer!(|| "collect_script");
        let script = script! {
            { msm.clone() }
            { g1_affine_push(expect) }
            { G1Affine::equalverify() }
            OP_TRUE
        };
        end_timer!(start);

        println!("msm_with_constant_bases_projective: = {} bytes", msm.len());
        let start = start_timer!(|| "execute_msm_script");
        run(script);
        end_timer!(start);
    }

    #[test]
    fn test_msm_with_constant_bases_affine() {
        let k = 1;
        let n = 1 << k;
        let rng = &mut test_rng();

        let scalars = (0..n).map(|_| ark_bn254::Fr::rand(rng)).collect::<Vec<_>>();

        let bases = (0..n)
            .map(|_| ark_bn254::G1Projective::rand(rng).into_affine())
            .collect::<Vec<_>>();

        let expect = ark_bn254::G1Projective::msm(&bases, &scalars).unwrap();
        let expect = expect.into_affine();
        let msm = msm_with_constant_bases_affine(&bases, &scalars);

        let script = script! {
            { msm.clone() }
            { g1_affine_push(expect) }
            { G1Affine::equalverify() }
            OP_TRUE
        };

        let exec_result = execute_script_without_stack_limit(script);
        println!("{}", exec_result.final_stack);
        assert!(exec_result.success);
    }

    #[test]
    fn test_scalar_mul_projective() {
        let k = 0;
        let n = 1 << k;
        let rng = &mut test_rng();

        let scalars = (0..n).map(|_| ark_bn254::Fr::rand(rng)).collect::<Vec<_>>();

        let bases = (0..n)
            .map(|_| ark_bn254::G1Projective::rand(rng))
            .collect::<Vec<_>>();

        let scalar_mul_projective_script =
            crate::bn254::curves::G1Projective::scalar_mul_by_constant_g1(bases[0]);

        let script = script! {
            { fr_push(scalars[0]) }
            { scalar_mul_projective_script.clone() }
            { crate::bn254::curves::G1Projective::into_affine() }
            { crate::bn254::curves::G1Affine::push((bases[0] * scalars[0]).into_affine()) }
            { crate::bn254::curves::G1Affine::equalverify() }
            OP_TRUE
        };
        let exec_result = execute_script_without_stack_limit(script);
        println!("{}", exec_result.final_stack);
        assert!(exec_result.success);

        println!(
            "script size of scalar_mul_projective: {}",
            scalar_mul_projective_script.len()
        );
    }

    #[test]
    fn test_scalar_mul_affine() {
        let k = 0;
        let n = 1 << k;
        let rng = &mut test_rng();

        let scalars = (0..n).map(|_| ark_bn254::Fr::rand(rng)).collect::<Vec<_>>();

        let bases = (0..n)
            .map(|_| ark_bn254::G1Projective::rand(rng).into_affine())
            .collect::<Vec<_>>();

        let (inner_coeffs, _) = prepare_msm_input(&bases, &scalars, 12);
        let scalar_mul_affine_script = crate::bn254::curves::G1Affine::scalar_mul_by_constant_g1(
            bases[0],
            inner_coeffs[0].0.clone(),
            inner_coeffs[0].1.clone(),
            inner_coeffs[0].2.clone(),
        );

        let script = script! {
            { fr_push(scalars[0]) }
            { scalar_mul_affine_script.clone() }
            { crate::bn254::curves::G1Affine::push((bases[0] * scalars[0]).into_affine()) }
            { crate::bn254::curves::G1Affine::equalverify() }
            OP_TRUE
        };
        let exec_result = execute_script_without_stack_limit(script);
        println!("{}", exec_result.final_stack);
        assert!(exec_result.success);

        println!(
            "script size of scalar_mul_affine: {}",
            scalar_mul_affine_script.len()
        );
    }

    #[test]
    fn test_hinted_msm_with_constant_bases_script() {
        let k = 2;
        let n = 1 << k;
        let rng = &mut test_rng();

        let scalars = (0..n).map(|_| ark_bn254::Fr::rand(rng)).collect::<Vec<_>>();

        let bases = (0..n)
            .map(|_| ark_bn254::G1Projective::rand(rng).into_affine())
            .collect::<Vec<_>>();

        let expect = ark_bn254::G1Projective::msm(&bases, &scalars).unwrap();
        let expect = expect.into_affine();
        let (msm, hints) = hinted_msm_with_constant_bases(&bases, &scalars);

        let start = start_timer!(|| "collect_script");
        let script = script! {
            for hint in hints {
                { hint.push() }
            }

            { msm.clone() }
            { g1_affine_push_not_montgomery(expect) }
            { G1Affine::equalverify() }
            OP_TRUE
        };
        end_timer!(start);

        println!("hinted_msm_with_constant_bases: = {} bytes", msm.len());
        let start = start_timer!(|| "execute_msm_script");
        let exec_result = execute_script_without_stack_limit(script);
        end_timer!(start);
        assert!(exec_result.success);
    }

    #[test]
    fn test_demo() {
        use crate::bn254::fp254impl::Fp254Impl;

        // let script = script! {
        //     { crate::bn254::fr::Fr::push_dec("7") }
        //     { crate::bn254::fr::Fr::decode_montgomery() }
        //     { crate::bn254::fr::Fr::convert_to_le_bits() }
        //     // { crate::bn254::fr::Fr::convert_to_le_bits_toaltstack() }
        // };
        // let exec_result = execute_script_without_stack_limit(script);
        // println!("{:?}", exec_result.final_stack);
        // let a = ark_ff::BigInt::<4>::from([3_u32, 5_u32, 7_u32, 9_u32]);
        // println!("{:?}", a.to_bits_le());
    }
}
