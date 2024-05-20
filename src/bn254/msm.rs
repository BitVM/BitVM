use crate::bigint::U254;
use crate::bn254::curves::G1Projective;
use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::fq::Fq;
use crate::treepp::{pushable, script, Script};
use ark_std::iterable::Iterable;
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

pub fn msm(bases: &[ark_bn254::G1Projective], scalars: &[ark_bn254::Fr]) -> Script {
    assert_eq!(bases.len(), scalars.len());
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
    use ark_std::{test_rng, UniformRand};
    use num_traits::Zero;
    use std::ops::{Add, Mul};

    #[test]
    fn test_msm() {
        let k = 3;
        let n = 1 << k;
        let rng = &mut test_rng();

        let scalars = (0..n)
            .into_iter()
            .map(|_| ark_bn254::Fr::rand(rng))
            .collect::<Vec<_>>();

        let bases = (0..n)
            .into_iter()
            .map(|_| ark_bn254::G1Projective::rand(rng).into_affine())
            .collect::<Vec<_>>();

        let expect = ark_bn254::G1Projective::msm(&bases, &scalars)
            .unwrap()
            .into_affine();

        let mut res = ark_bn254::G1Projective::zero();
        scalars.iter().zip(bases.iter()).for_each(|(s, b)| {
            let mul = b.mul_bigint(s.into_bigint());
            res = res.add(mul);
        });

        let actual = res.into_affine();

        assert_eq!(actual, expect);
    }

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

        let script = script! {
            {super::msm(&bases_projects, &scalars) }
            { g1_projective_push(expect) }
            { G1Projective::equalverify() }
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }
}
