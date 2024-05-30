#[cfg(test)]
mod test {
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::bn254::fq::Fq;
    use ark_ff::{Field, One};
    use ark_std::UniformRand;
    use num_bigint::BigUint;
    use num_traits::{Num, ToPrimitive};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::str::FromStr;

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

    #[test]
    fn test_compute_c_wi() {
        let p = BigUint::from_str_radix(Fq::MODULUS, 16).unwrap();
        let r = BigUint::from_str(
            "21888242871839275222246405745257275088548364400416034343698204186575808495617",
        )
        .unwrap();
        let lambda = BigUint::from_str(
            "10486551571378427818905133077457505975146652579011797175399169355881771981095211883813744499745558409789005132135496770941292989421431235276221147148858384772096778432243207188878598198850276842458913349817007302752534892127325269"
        ).unwrap();
        let s = 3_u32;
        let exp = p.pow(12) - 1_u32;
        let h = &exp / &r;
        let t = &exp / 3_u32.pow(s);
        let k = (&t + 1_u32) / 3_u32;
        let m = &lambda / &r;
        let d = 3_u32;
        let mm = &m / d;

        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let cofactor_cubic = 3_u32.pow(s - 1) * &t;

        // sample a miller loop result f which is cubic non-residue
        let f = {
            // (p^12 - 1) // 3
            let mut f = ark_bn254::Fq12::rand(&mut prng).pow(r.to_u64_digits());
            let mut legendre = f.pow(cofactor_cubic.to_u64_digits());
            while legendre == ark_bn254::Fq12::ONE {
                f = ark_bn254::Fq12::rand(&mut prng).pow(r.to_u64_digits());
                legendre = f.pow(cofactor_cubic.to_u64_digits());
            }
            f
        };
        assert_eq!(f.pow(h.to_u64_digits()), ark_bn254::Fq12::ONE);

        // sample a proper scalar w which is cubic non-residue
        let w = {
            let (mut w, mut z) = (ark_bn254::Fq12::one(), ark_bn254::Fq12::one());
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

        // m'-th root of f, say f3
        let mm_inv = mm.modinv(&(r * h)).unwrap();
        assert_ne!(mm_inv, BigUint::one());
        let f3 = f2.pow(mm_inv.to_u64_digits());

        // d-th (cubic) root, say c
        let c = tonelli_shanks_cubic(f3, w, s, t, k);
        assert_eq!(c.pow(lambda.to_u64_digits()), f * wi);
    }
}
