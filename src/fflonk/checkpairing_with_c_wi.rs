#[cfg(test)]
mod test {
    use crate::bn254::ell_coeffs::G2Prepared;
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::bn254::fq::Fq;
    use crate::bn254::fq12::Fq12;
    use crate::bn254::pairing::Pairing;
    use crate::treepp::*;
    use ark_bn254::Bn254;
    use ark_ec::pairing::Pairing as ArkPairing;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::{Field, One};
    use ark_std::UniformRand;
    use num_bigint::BigUint;
    use num_traits::{Num, ToPrimitive};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::ops::Neg;
    use std::str::FromStr;

    fn fq12_push(element: ark_bn254::Fq12) -> Script {
        script! {
            for elem in element.to_base_prime_field_elements() {
                { Fq::push_u32_le(&BigUint::from(elem).to_u32_digits()) }
           }
        }
    }

    // refer table 3 of https://eprint.iacr.org/2009/457.pdf
    // a: Fp12 which is cubic residue
    // c: random Fp12 which is cubic non-residue
    // s: satisfying p^12 - 1 = 3^s * t
    // t: satisfying p^12 - 1 = 3^s * t
    // k: k = (t + 1) // 3
    fn tonelli_shanks_cubic(
        a: ark_bn254::Fq12,
        c: ark_bn254::Fq12,
        s: u32,
        t: BigUint,
        k: BigUint,
    ) -> ark_bn254::Fq12 {
        let mut r = a.pow(t.to_u64_digits());
        let e = 3_u32.pow(s - 1);
        let exp = 3_u32.pow(s) * &t;

        // compute cubic root of (a^t)^-1, say h
        let (mut h, cc, mut c) = (
            ark_bn254::Fq12::ONE,
            c.pow([e as u64]),
            c.inverse().unwrap(),
        );
        for i in 1..(s as i32) {
            let delta = (s as i32) - i - 1;
            let d = if delta < 0 {
                r.pow((&exp / 3_u32.pow((-delta) as u32)).to_u64_digits())
            } else {
                r.pow([3_u32.pow(delta as u32).to_u64().unwrap()])
            };
            if d == cc {
                (h, r) = (h * c, r * c.pow([3_u64]));
            } else if d == cc.pow([2_u64]) {
                (h, r) = (h * c.pow([2_u64]), r * c.pow([3_u64]).pow([2_u64]));
            }
            c = c.pow([3_u64])
        }

        // recover cubic root of a
        r = a.pow(k.to_u64_digits()) * h;
        if t == 3_u32 * k + 1_u32 {
            r = r.inverse().unwrap();
        }

        assert_eq!(r.pow([3_u64]), a);
        r
    }

    // refer from Algorithm 5 of "On Proving Pairings"(https://eprint.iacr.org/2024/640.pdf)
    fn compute_c_wi(f: ark_bn254::Fq12) -> (ark_bn254::Fq12, ark_bn254::Fq12) {
        let p = BigUint::from_str_radix(Fq::MODULUS, 16).unwrap();
        let r = BigUint::from_str(
            "21888242871839275222246405745257275088548364400416034343698204186575808495617",
        )
        .unwrap();
        let lambda = BigUint::from_str(
            "10486551571378427818905133077457505975146652579011797175399169355881771981095211883813744499745558409789005132135496770941292989421431235276221147148858384772096778432243207188878598198850276842458913349817007302752534892127325269"
        ).unwrap();
        let s = 3_u32;
        let exp = p.pow(12_u32) - 1_u32;
        let h = &exp / &r;
        let t = &exp / 3_u32.pow(s);
        let k = (&t + 1_u32) / 3_u32;
        let m = &lambda / &r;
        let d = 3_u32;
        let mm = &m / d;

        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let cofactor_cubic = 3_u32.pow(s - 1) * &t;

        // make f is r-th residue, but it's not cubic residue
        assert_eq!(f.pow(h.to_u64_digits()), ark_bn254::Fq12::ONE);
        assert_ne!(f.pow(cofactor_cubic.to_u64_digits()), ark_bn254::Fq12::ONE);

        // sample a proper scalar w which is cubic non-residue
        let w = {
            let (mut w, mut z) = (ark_bn254::Fq12::ONE, ark_bn254::Fq12::ONE);
            while w == ark_bn254::Fq12::ONE {
                // choose z which is 3-th non-residue
                let mut legendre = ark_bn254::Fq12::ONE;
                while legendre == ark_bn254::Fq12::ONE {
                    z = ark_bn254::Fq12::rand(&mut prng);
                    legendre = z.pow(cofactor_cubic.to_u64_digits());
                }
                // obtain w which is t-th power of z
                w = z.pow(t.to_u64_digits());
            }
            w
        };
        // make sure 27-th root w, is 3-th non-residue and r-th residue
        assert_ne!(w.pow(cofactor_cubic.to_u64_digits()), ark_bn254::Fq12::ONE);
        assert_eq!(w.pow(h.to_u64_digits()), ark_bn254::Fq12::ONE);

        // just two option, w and w^2, since w^3 must be cubic residue, leading f*w^3 must not be cubic residue
        let mut wi = w;
        if (f * wi).pow(cofactor_cubic.to_u64_digits()) != ark_bn254::Fq12::ONE {
            assert_eq!(
                (f * w * w).pow(cofactor_cubic.to_u64_digits()),
                ark_bn254::Fq12::ONE
            );
            wi = w * w;
        }
        assert_eq!(wi.pow(h.to_u64_digits()), ark_bn254::Fq12::ONE);

        assert_eq!(lambda, &d * &mm * &r);
        // f1 is scaled f
        let f1 = f * wi;

        // r-th root of f1, say f2
        let r_inv = r.modinv(&h).unwrap();
        assert_ne!(r_inv, BigUint::one());
        let f2 = f1.pow(r_inv.to_u64_digits());
        assert_ne!(f2, ark_bn254::Fq12::ONE);

        // m'-th root of f, say f3
        let mm_inv = mm.modinv(&(r * h)).unwrap();
        assert_ne!(mm_inv, BigUint::one());
        let f3 = f2.pow(mm_inv.to_u64_digits());
        assert_eq!(f3.pow(cofactor_cubic.to_u64_digits()), ark_bn254::Fq12::ONE);
        assert_ne!(f3, ark_bn254::Fq12::ONE);

        // d-th (cubic) root, say c
        let c = tonelli_shanks_cubic(f3, w, s, t, k);
        assert_ne!(c, ark_bn254::Fq12::ONE);
        assert_eq!(c.pow(lambda.to_u64_digits()), f * wi);

        (c, wi)
    }

    #[test]
    fn test_checkpairing_with_c_wi() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        // exp = 6x + 2 + p - p^2 = lambda - p^3
        let p_pow3 = &BigUint::from_str_radix(Fq::MODULUS, 16).unwrap().pow(3_u32);
        let lambda = BigUint::from_str(
                        "10486551571378427818905133077457505975146652579011797175399169355881771981095211883813744499745558409789005132135496770941292989421431235276221147148858384772096778432243207188878598198850276842458913349817007302752534892127325269"
                    ).unwrap();
        let (exp, sign) = if lambda > *p_pow3 {
            (lambda - p_pow3, true)
        } else {
            (p_pow3 - lambda, false)
        };

        // prove e(P1, Q1) = e(P2, Q2)
        // namely e(-P1, Q1) * e(P2, Q2) = 1
        let P1 = ark_bn254::G1Affine::rand(&mut prng);
        let Q2 = ark_bn254::g2::G2Affine::rand(&mut prng);
        let factor = [3_u64];
        let P2 = P1.mul_bigint(factor).into_affine();
        let Q1 = Q2.mul_bigint(factor).into_affine();
        let Q1_prepared = G2Prepared::from(Q1);
        let Q2_prepared = G2Prepared::from(Q2);

        // f^{lambda - p^3} * wi = c^lambda
        // equivalently (f * c_inv)^{lambda - p^3} * wi = c_inv^{-p^3} = c^{p^3}
        let f = Bn254::multi_miller_loop([P1.neg(), P2], [Q1, Q2]).0;
        println!("Bn254::multi_miller_loop done!");
        let (c, wi) = compute_c_wi(f);
        let c_inv = c.inverse().unwrap();
        let hint = if sign {
            f * wi * (c_inv.pow(exp.to_u64_digits()))
        } else {
            f * wi * (c_inv.pow(exp.to_u64_digits()).inverse().unwrap())
        };
        println!("Accumulated f done!");
        assert_eq!(hint, c.pow(p_pow3.to_u64_digits()));

        // miller loop script
        let dual_miller_loop_with_c_wi =
            Pairing::dual_miller_loop_with_c_wi(&Q1_prepared, &Q2_prepared);
        println!(
            "Pairing.dual_miller_loop_with_c_wi: {} bytes",
            dual_miller_loop_with_c_wi.len()
        );

        // p, q, c, c_inv, wi
        let script = script! {
            { Fq::push_u32_le(&BigUint::from((P1.neg()).x).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from((P1.neg()).y).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(P2.x).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(P2.y).to_u32_digits()) }
            { fq12_push(c) }
            { fq12_push(c_inv) }
            { fq12_push(wi) }
            { dual_miller_loop_with_c_wi.clone() }
            { fq12_push(hint) }
            { Fq12::equalverify() }
            OP_TRUE
        };
        println!("fflonk.checkpairing_miller_loop = {} bytes", script.len());
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }
}
