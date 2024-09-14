use crate::bn254::utils::fr_push_not_montgomery;
use crate::bn254::{curves::G1Projective, utils::fr_push};
use crate::treepp::*;
use ark_ff::Field;
use ark_ec::AdditiveGroup;
use super::utils::Hint;

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

pub fn hinted_msm_with_constant_bases(bases: &[ark_bn254::G1Affine], scalars: &[ark_bn254::Fr]) -> (Script, Vec<Hint>) {
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
            let (hinted_script, hint) = G1Projective::hinted_scalar_mul_by_constant_g1(scalars[i], &mut c);
            hinted_scripts.push(hinted_script);
            hints.extend(hint);
        }
        // 3. sum the base
        let (hinted_script, hint) = G1Projective::hinted_add(p,  c);
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

    let mut script = script!{};
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
    fn test_msm_with_constant_bases_script() {
        let k = 0;
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

        println!("msm_with_constant_bases: = {} bytes", msm.len());
        let start = start_timer!(|| "execute_msm_script");
        run(script);
        end_timer!(start);
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
}
