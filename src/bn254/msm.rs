use crate::bn254::curves::G1Projective;
use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::fq::Fq;
use crate::bn254::fr::Fr;
use std::ops::Mul;
use crate::treepp::{script, Script};
use ark_ff::Field;
use num_bigint::BigUint;

pub fn g1_affine_push(point: ark_bn254::G1Affine) -> Script {
    script! {
        { Fq::push_u32_le(&BigUint::from(point.x).to_u32_digits()) }
        { Fq::push_u32_le(&BigUint::from(point.y).to_u32_digits()) }
    }
}

fn fr_push(scalar: ark_bn254::Fr) -> Script {
    script! {
        { Fr::push_u32_le(&BigUint::from(scalar).to_u32_digits()) }
    }
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
            // { G1Projective::add() }
            { G1Projective::push(bases[i].mul(scalars[i])) }
        }
        // // convert into Affine
        // { G1Projective::into_affine() }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{bn254::curves::G1Affine, run};
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
            // { g1_affine_push(expect) }
            // { G1Affine::equalverify() }
            // OP_TRUE
        };
        end_timer!(start);

        println!("msm_with_constant_bases: = {} bytes", msm.len());
        let start = start_timer!(|| "execute_msm_script");
        let exec_result = execute_script(script);
        end_timer!(start);
        assert!(exec_result.success);
    }
}
