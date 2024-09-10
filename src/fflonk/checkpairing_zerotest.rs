#[cfg(test)]
mod test {
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::bn254::fq::Fq;
    use crate::bn254::fq12::Fq12;
    use crate::treepp::*;
    use ark_ec::pairing::Pairing;
    use ark_ec::CurveGroup;
    use ark_ff::{CyclotomicMultSubgroup, Field};
    use ark_std::UniformRand;
    use bitcoin_script::script;
    use num_bigint::BigUint;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::ops::{Mul, Neg};
    use std::str::FromStr;

    fn fq12_push(element: ark_bn254::Fq12) -> Script {
        script! {
            for elem in element.to_base_prime_field_elements() {
                { Fq::push_u32_le(&BigUint::from(elem).to_u32_digits()) }
           }
        }
    }

    #[test]
    fn test_checkpairing_zerotest() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let x = ark_bn254::fr::Fr::rand(&mut prng);

        let a = ark_bn254::g1::G1Affine::rand(&mut prng);
        let b = ark_bn254::g2::G2Affine::rand(&mut prng);

        let ax = a.mul(&x).into_affine();
        let bx = b.mul(&x).into_affine();

        let c = ark_bn254::Bn254::multi_miller_loop_affine([a.neg(), ax], [bx, b]).0;

        let c_cyc = {
            let f1 = c.cyclotomic_inverse().unwrap();

            let mut f2 = c.inverse().unwrap();
            let mut r = f1.mul(&f2);
            f2 = r;

            r.frobenius_map_in_place(2);

            r *= f2;
            r
        };

        let exp = BigUint::from_str("4436617972506257923193419177489456460765748607520165056184824179968964824433551145989002390683181468014844846405056222620624959232531272028933759852593591675750731194524123260979423353851618673937937363358520803481826312825518387").unwrap();
        let hint = c_cyc.cyclotomic_exp(exp.to_u64_digits());

        let r = BigUint::from_str(
            "21888242871839275222246405745257275088548364400416034343698204186575808495617",
        )
        .unwrap();
        let res = hint.cyclotomic_exp(r.to_u64_digits());

        assert_eq!(res, c_cyc);

        let script = script! {
            // push the hint
            { fq12_push(hint) }

            // push c
            { fq12_push(c) }

            // make c cyclotomic
            { Fq12::move_to_cyclotomic() }

            // check that the hint is cyclotomic
            { Fq12::roll(12) }
            { Fq12::cyclotomic_verify_in_place() }

            // power the hint by r
            { Fq12::cyclotomic_pow_by_r() }

            // check equality
            { Fq12::equalverify() }

            OP_TRUE
        };

        println!("fflonk.checkpairing_zerotest = {} bytes", script.len());

        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }
}
