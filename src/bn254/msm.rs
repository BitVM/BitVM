use crate::bigint::U254;
use crate::bn254::curves::G1Projective;
use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::fq::Fq;
use crate::treepp::{pushable, script, Script};
use num_bigint::BigUint;
use std::ops::Mul;

fn g1_projective_push(point: ark_bn254::G1Projective) -> Script {
    script! {
        { Fq::push_u32_le(&BigUint::from(point.x).to_u32_digits()) }
        { Fq::push_u32_le(&BigUint::from(point.y).to_u32_digits()) }
        { Fq::push_u32_le(&BigUint::from(point.z).to_u32_digits()) }
    }
}

fn g1_affine_push(point: ark_bn254::G1Affine) -> Script {
    script! {
        { Fq::push_u32_le(&BigUint::from(point.x).to_u32_digits()) }
        { Fq::push_u32_le(&BigUint::from(point.y).to_u32_digits()) }
    }
}

fn fr_push(scalar: ark_bn254::Fr) -> Script {
    script! {
        { U254::push_u32_le(&BigUint::from(scalar).to_u32_digits()) }
    }
}

pub fn msm(bases: &[ark_bn254::G1Affine], scalars: &[ark_bn254::Fr]) -> Script {
    assert_eq!(bases.len(), scalars.len());
    let bases: Vec<ark_ec::short_weierstrass::Projective<ark_bn254::g1::Config>> =
        bases.iter().map(|&p| p.into()).collect();
    let len = bases.len();
    let scalar_mul = G1Projective::scalar_mul();

    // 1. init the sum=0;
    let init = G1Projective::push_zero();
    let script = script! {
        {init}
        for i in 0..len {
            // 2. scalar mul
            { g1_projective_push(bases[i]) }
            { fr_push(scalars[i]) }
            { scalar_mul.clone() }

            // 3. sum the base
            { G1Projective::add() }
        }
    };
    script
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::execute_script;
    use ark_ec::{AffineRepr, CurveGroup, Group, VariableBaseMSM};
    use ark_ff::PrimeField;
    use ark_std::{end_timer, start_timer, test_rng, UniformRand};
    use num_traits::Zero;
    use std::ops::{Add, Mul};

    #[test]
    fn test_msm_script() {
        let k = 2;
        let n = 1 << k;
        let rng = &mut test_rng();

        let scalars = (0..n)
            .into_iter()
            .map(|_| ark_bn254::Fr::rand(rng))
            .collect::<Vec<_>>();

        let bases_projects = (0..n)
            .into_iter()
            .map(|_| ark_bn254::G1Projective::rand(rng))
            .collect::<Vec<_>>();

        let bases = bases_projects
            .clone()
            .iter()
            .map(|b| b.into_affine())
            .collect::<Vec<_>>();
        let expect = ark_bn254::G1Projective::msm(&bases, &scalars).unwrap();

        let start = start_timer!(|| "collect_script");
        let script = script! {
            {super::msm(&bases, &scalars) }
            { g1_projective_push(expect) }
            { G1Projective::equalverify() }
            OP_TRUE
        };
        end_timer!(start);

        println!("msm::test_msm_script = {} bytes", script.len());
        let start = start_timer!(|| "execute_msm_script");
        let exec_result = execute_script(script);
        end_timer!(start);
        assert!(exec_result.success);
    }

    #[test]
    fn test_msm_equalverify() {
        let k = 2;
        let n = 1 << k;
        let rng = &mut test_rng();

        let scalars = (0..n)
            .into_iter()
            .map(|_| ark_bn254::Fr::rand(rng))
            .collect::<Vec<_>>();

        let bases_projects = (0..n)
            .into_iter()
            .map(|_| ark_bn254::G1Projective::rand(rng))
            .collect::<Vec<_>>();

        let bases = bases_projects
            .clone()
            .iter()
            .map(|b| b.into_affine())
            .collect::<Vec<_>>();
        let expect = ark_bn254::G1Projective::msm(&bases, &scalars)
            .unwrap()
            .into_affine();

        let start = start_timer!(|| "collect_script");
        let script = script! {
            {super::msm(&bases_projects, &scalars) }
            { g1_affine_push(expect) }
            { Fq::push_one() }
            { G1Projective::equalverify() }
            OP_TRUE
        };
        end_timer!(start);

        println!("msm::test_msm_script = {} bytes", script.len());
        let start = start_timer!(|| "execute_msm_script");
        let exec_result = execute_script(script);
        end_timer!(start);
        assert!(exec_result.success);
    }
}
