// Rephrased from https://github.com/arkworks-rs/algebra/blob/master/ec/src/models/bn/g2.rs#L185
// Cannot directly obtain G2 because of visibility

use ark_ec::bn::g2::G2Prepared as ark_G2Prepared;
use ark_ec::bn::{BnConfig, TwistType};
use ark_ec::short_weierstrass::Affine;
use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::AdditiveGroup;
use ark_ff::Field;
use num_traits::One;

pub type G2Affine<P> = Affine<<P as BnConfig>::G2Config>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct G2Prepared {
    /// Stores the coefficients of the line evaluations as calculated in
    /// <https://eprint.iacr.org/2013/722.pdf>
    pub ell_coeffs: Vec<EllCoeff>,
    pub infinity: bool,
}

// aka. line in miller loop.
pub type EllCoeff = (ark_bn254::Fq2, ark_bn254::Fq2, ark_bn254::Fq2);

#[derive(Clone, Copy, Debug)]
struct G2HomProjective {
    x: ark_bn254::Fq2,
    y: ark_bn254::Fq2,
    z: ark_bn254::Fq2,
}

pub fn affine_double_in_place(
    t: &mut ark_bn254::G2Affine,
    three_div_two: &ark_bn254::Fq,
) -> EllCoeff {
    //  for affine coordinates
    //  slope: alpha = 3 * x^2 / 2 * y
    let mut alpha = t.x.square();
    alpha /= t.y;
    alpha.mul_assign_by_fp(&three_div_two);
    let bias = t.y - alpha * t.x;

    // update T
    // T.x = alpha^2 - 2 * t.x
    // T.y = -bias - alpha * T.x
    let tx = alpha.square() - t.x.double();
    t.y = -bias - alpha * tx;
    t.x = tx;

    (ark_bn254::Fq2::ONE, alpha, bias)
}

pub fn affine_add_in_place(t: &mut ark_bn254::G2Affine, q: &ark_bn254::G2Affine) -> EllCoeff {
    // alpha = (t.y - q.y) / (t.x - q.x)
    // bias = t.y - alpha * t.x
    let alpha = (t.y - q.y) / (t.x - q.x);
    let bias = t.y - alpha * t.x;

    // update T
    // T.x = alpha^2 - t.x - q.x
    // T.y = -bias - alpha * T.x
    let tx = alpha.square() - t.x - q.x;
    t.y = -bias - alpha * tx;
    t.x = tx;

    (ark_bn254::Fq2::ONE, alpha, bias)
}

impl G2HomProjective {
    fn double_in_place(&mut self, two_inv: &ark_bn254::Fq) -> EllCoeff {
        // Formula for line function when working with
        // homogeneous projective coordinates.

        let mut a = self.x * &self.y;
        a.mul_assign_by_fp(two_inv);
        let b = self.y.square();
        let c = self.z.square();
        let e = ark_bn254::g2::Config::COEFF_B * &(c.double() + &c);
        let f = e.double() + &e;
        let mut g = b + &f;
        g.mul_assign_by_fp(two_inv);
        let h = (self.y + &self.z).square() - &(b + &c);
        let i = e - &b;
        let j = self.x.square();
        let e_square = e.square();

        self.x = a * &(b - &f);
        self.y = g.square() - &(e_square.double() + &e_square);
        self.z = b * &h;
        match ark_bn254::Config::TWIST_TYPE {
            TwistType::M => (i, j.double() + &j, -h),
            TwistType::D => (-h, j.double() + &j, i),
        }
    }

    fn add_in_place(&mut self, q: &ark_bn254::G2Affine) -> EllCoeff {
        // Formula for line function when working with
        // homogeneous projective coordinates.
        let theta = self.y - &(q.y * &self.z);
        let lambda = self.x - &(q.x * &self.z);
        let c = theta.square();
        let d = lambda.square();
        let e = lambda * &d;
        let f = self.z * &c;
        let g = self.x * &d;
        let h = e + &f - &g.double();
        self.x = lambda * &h;
        self.y = theta * &(g - &h) - &(e * &self.y);
        self.z *= &e;
        let j = theta * &q.x - &(lambda * &q.y);

        match ark_bn254::Config::TWIST_TYPE {
            TwistType::M => (j, -theta, lambda),
            TwistType::D => (lambda, -theta, j),
        }
    }
}

impl Default for G2Prepared {
    fn default() -> Self {
        Self::from(ark_bn254::G2Affine::generator())
    }
}

impl G2Prepared {
    fn from_affine(q: ark_bn254::G2Affine) -> Self {
        if q.infinity {
            G2Prepared {
                ell_coeffs: vec![],
                infinity: true,
            }
        } else {
            // let two_inv = P::Fp::one().double().inverse().unwrap();
            let two_inv = ark_bn254::Fq::one().double().inverse().unwrap();
            let three_div_two = ark_bn254::Fq::one().double() + ark_bn254::Fq::one() * two_inv;

            let mut ell_coeffs = vec![];
            let mut r = q.clone();

            let neg_q = -q;

            for bit in ark_bn254::Config::ATE_LOOP_COUNT.iter().rev().skip(1) {
                // ell_coeffs.push(r.double_in_place(&two_inv));
                ell_coeffs.push(affine_double_in_place(&mut r, &three_div_two));

                match bit {
                    1 => ell_coeffs.push(affine_add_in_place(&mut r, &q)),
                    -1 => ell_coeffs.push(affine_add_in_place(&mut r, &neg_q)),
                    _ => continue,
                }
            }

            let q1 = mul_by_char(q);
            let mut q2 = mul_by_char(q1);

            if ark_bn254::Config::X_IS_NEGATIVE {
                r.y = -r.y;
            }

            q2.y = -q2.y;

            ell_coeffs.push(affine_add_in_place(&mut r, &q1));
            ell_coeffs.push(affine_add_in_place(&mut r, &q2));

            Self {
                ell_coeffs,
                infinity: false,
            }
        }
    }
}

impl From<ark_bn254::G2Affine> for G2Prepared {
    // equal with line_function.
    fn from(q: ark_bn254::G2Affine) -> Self {
        if q.infinity {
            G2Prepared {
                ell_coeffs: vec![],
                infinity: true,
            }
        } else {
            let two_inv = ark_bn254::Fq::one().double().inverse().unwrap();
            let mut ell_coeffs = vec![];
            let mut r = G2HomProjective {
                x: q.x,
                y: q.y,
                z: ark_bn254::Fq2::one(),
            };

            let neg_q = -q;

            for bit in ark_bn254::Config::ATE_LOOP_COUNT.iter().rev().skip(1) {
                ell_coeffs.push(r.double_in_place(&two_inv));

                match bit {
                    1 => ell_coeffs.push(r.add_in_place(&q)),
                    -1 => ell_coeffs.push(r.add_in_place(&neg_q)),
                    _ => continue,
                }
            }

            let q1 = mul_by_char(q);
            let mut q2 = mul_by_char(q1);

            q2.y = -q2.y;

            ell_coeffs.push(r.add_in_place(&q1));
            ell_coeffs.push(r.add_in_place(&q2));

            Self {
                ell_coeffs,
                infinity: false,
            }
        }
    }
}

impl From<ark_bn254::G2Projective> for G2Prepared {
    fn from(q: ark_bn254::G2Projective) -> Self {
        q.into_affine().into()
    }
}

impl From<ark_G2Prepared<ark_bn254::Config>> for G2Prepared {
    fn from(q: ark_G2Prepared<ark_bn254::Config>) -> Self {
        let ell_coeffs: Vec<(ark_bn254::Fq2, ark_bn254::Fq2, ark_bn254::Fq2)> = q
            .ell_coeffs
            .iter()
            .map(|f| {
                let f1: ark_bn254::Fq2 = f.0;
                let f2: ark_bn254::Fq2 = f.1;
                let f3: ark_bn254::Fq2 = f.2;
                (f1, f2, f3)
            })
            .collect();
        G2Prepared {
            ell_coeffs,
            infinity: false,
        }
    }
}

impl<'a> From<&'a ark_bn254::G2Affine> for G2Prepared {
    fn from(other: &'a ark_bn254::G2Affine) -> Self {
        (*other).into()
    }
}

impl<'a> From<&'a ark_bn254::G2Projective> for G2Prepared {
    fn from(q: &'a ark_bn254::G2Projective) -> Self {
        q.into_affine().into()
    }
}

impl<'a> From<&'a ark_G2Prepared<ark_bn254::Config>> for G2Prepared {
    fn from(q: &'a ark_G2Prepared<ark_bn254::Config>) -> Self {
        q.to_owned().into()
    }
}

pub fn mul_by_char(r: ark_bn254::G2Affine) -> ark_bn254::G2Affine {
    // multiply by field characteristic

    let mut s = r;
    s.x.frobenius_map_in_place(1);
    s.x *= &ark_bn254::Config::TWIST_MUL_BY_Q_X;
    s.y.frobenius_map_in_place(1);
    s.y *= &ark_bn254::Config::TWIST_MUL_BY_Q_Y;

    s
}

#[cfg(test)]
mod tests {
    use ark_bn254::{Fq, Fq2};

    use ark_ec::short_weierstrass::SWCurveConfig;
    use ark_ff::{Field, UniformRand};
    use ark_std::test_rng;
    use num_traits::One;

    use super::G2HomProjective;
    use ark_ff::AdditiveGroup;

    #[test]
    fn test_double_in_place() {
        let mut rng = test_rng();
        let two_inv = Fq::one().double().inverse().unwrap();
        let mut r = G2HomProjective {
            x: Fq2::rand(&mut rng),
            y: Fq2::rand(&mut rng),
            z: Fq2::rand(&mut rng),
        };

        println!("1/2 = {:?}\n\n", two_inv.to_string());

        println!("COEFF_B = {}\n\n", ark_bn254::g2::Config::COEFF_B);

        println!("before double line:");
        println!("r.x = {:?}", r.x.to_string());
        println!("r.y = {:?}", r.y.to_string());
        println!("r.z = {:?}\n\n", r.z.to_string());

        let s = r.double_in_place(&two_inv);

        println!("after double line:");
        println!("r.x = {:?}", r.x.to_string());
        println!("r.y = {:?}", r.y.to_string());
        println!("r.z = {:?}", r.z.to_string());
        println!("s.0 = {:?}", s.0.to_string());
        println!("s.1 = {:?}", s.1.to_string());
        println!("s.2 = {:?}", s.2.to_string());
    }
}
