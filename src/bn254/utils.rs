// utils for push fields into stack
use crate::bn254::ell_coeffs::EllCoeff;
use crate::bn254::ell_coeffs::G2Prepared;
use crate::bn254::fr::Fr;
use crate::bn254::{fq12::Fq12, fq2::Fq2};
use ark_ec::{bn::BnConfig, AffineRepr};
use ark_ff::{AdditiveGroup, BigInt};
use ark_ff::Field;
use num_bigint::BigUint;

use crate::{
    bn254::{fp254impl::Fp254Impl, fq::Fq},
    treepp::*,
};

pub fn fr_push(scalar: ark_bn254::Fr) -> Script {
    script! {
        { Fr::push_u32_le(&BigUint::from(scalar).to_u32_digits()) }
    }
}

pub fn fr_push_not_montgomery(scalar: ark_bn254::Fr) -> Script {
    script! {
        { Fr::push_u32_le_not_montgomery(&BigUint::from(scalar).to_u32_digits()) }
    }
}

pub fn fq_push(element: ark_bn254::Fq) -> Script {
    script! {
        { Fq::push_u32_le(&BigUint::from(element).to_u32_digits()) }
    }
}

pub fn fq_push_not_montgomery(element: ark_bn254::Fq) -> Script {
    script! {
        { Fq::push_u32_le_not_montgomery(&BigUint::from(element).to_u32_digits()) }
    }
}

pub fn fq2_push(element: ark_bn254::Fq2) -> Script {
    script! {
        { Fq::push_u32_le(&BigUint::from(element.c0).to_u32_digits()) }
        { Fq::push_u32_le(&BigUint::from(element.c1).to_u32_digits()) }
    }
}

pub fn fq2_push_not_montgomery(element: ark_bn254::Fq2) -> Script {
    script! {
        { Fq::push_u32_le_not_montgomery(&BigUint::from(element.c0).to_u32_digits()) }
        { Fq::push_u32_le_not_montgomery(&BigUint::from(element.c1).to_u32_digits()) }
    }
}

pub fn fq6_push(element: ark_bn254::Fq6) -> Script {
    script! {
        for elem in element.to_base_prime_field_elements() {
            { Fq::push_u32_le(&BigUint::from(elem).to_u32_digits()) }
       }
    }
}

pub fn fq6_push_not_montgomery(element: ark_bn254::Fq6) -> Script {
    script! {
        for elem in element.to_base_prime_field_elements() {
            { Fq::push_u32_le_not_montgomery(&BigUint::from(elem).to_u32_digits()) }
       }
    }
}

pub fn fq12_push(element: ark_bn254::Fq12) -> Script {
    script! {
        for elem in element.to_base_prime_field_elements() {
            { Fq::push_u32_le(&BigUint::from(elem).to_u32_digits()) }
       }
    }
}

pub fn fq12_push_not_montgomery(element: ark_bn254::Fq12) -> Script {
    script! {
        for elem in element.to_base_prime_field_elements() {
            { Fq::push_u32_le_not_montgomery(&BigUint::from(elem).to_u32_digits()) }
       }
    }
}

pub fn g1_affine_push(point: ark_bn254::G1Affine) -> Script {
    script! {
        { Fq::push_u32_le(&BigUint::from(point.x).to_u32_digits()) }
        { Fq::push_u32_le(&BigUint::from(point.y).to_u32_digits()) }
    }
}

pub fn g1_affine_push_not_montgomery(point: ark_bn254::G1Affine) -> Script {
    script! {
        { Fq::push_u32_le_not_montgomery(&BigUint::from(point.x).to_u32_digits()) }
        { Fq::push_u32_le_not_montgomery(&BigUint::from(point.y).to_u32_digits()) }
    }
}

pub enum Hint {
    Fq(ark_bn254::Fq),
}

impl Hint {
    pub fn push(&self) -> Script {
        match self {
            Hint::Fq(fq) => script! {
                { fq_push_not_montgomery(*fq) }
            },
        }
    }
}

// input:
//  f            12 elements
//  coeffs.c0    2 elements
//  coeffs.c1    2 elements
//  coeffs.c2    2 elements
//  p.x          1 element
//  p.y          1 element
//
// output:
//  new f        12 elements
pub fn ell() -> Script {
    script! {
        // compute the new c0
        { Fq2::mul_by_fq(6, 0) }

        // compute the new c1
        { Fq2::mul_by_fq(5, 2) }

        // roll c2
        { Fq2::roll(4) }

        // compute the new f
        { Fq12::mul_by_034() }
    }
}

// input:
//  f            12 elements
//  p.x          1 element
//  p.y          1 element
//
// output:
//  new f        12 elements
pub fn ell_by_constant(constant: &EllCoeff) -> Script {
    script! {
        // [f, px, py]
        // compute the new c0
        // [f, px, py, py]
        { Fq::copy(0) }
        // [f, px, py, py * q1.x1]
        { Fq::mul_by_constant(&constant.0.c0) }
        // [f, px, py * q1.x1, py]
        { Fq::roll(1) }
        // [f, px, py * q1.x1, py * q1.x2]
        { Fq::mul_by_constant(&constant.0.c1) }

        // compute the new c1
        // [f, px, py * q1.x1, py * q1.x2, px]
        { Fq::copy(2) }
        // [f, px, py * q1.x1, py * q1.x2, px * q1.y1]
        { Fq::mul_by_constant(&constant.1.c0) }
        // [f, py * q1.x1, py * q1.x2, px * q1.y1, px]
        { Fq::roll(3) }
        // [f, py * q1.x1, py * q1.x2, px * q1.y1, px * q1.y2]
        { Fq::mul_by_constant(&constant.1.c1) }

        // compute the new f
        // [f, py * q1.x1, py * q1.x2, px * q1.y1, px * q1.y2]
        { Fq12::mul_by_034_with_4_constant(&constant.2) }
    }
}

// stack input:
//  f            12 elements
//  x': -p.x / p.y   1 element
//  y': 1 / p.y      1 element
// func params:
//  (c0, c1, c2) where c0 is a trival value ONE in affine mode
//
// output:
//  new f        12 elements
pub fn ell_by_constant_affine(constant: &EllCoeff) -> Script {
    assert_eq!(constant.0, ark_bn254::Fq2::ONE);
    script! {
        // [f, x', y']
        // update c1, c1' = x' * c1
        { Fq::copy(1) }
        { Fq::mul_by_constant(&constant.1.c0) }
        // [f, x', y', x' * c1.0]
        { Fq::roll(2) }
        { Fq::mul_by_constant(&constant.1.c1) }
        // [f, y', x' * c1.0, x' * c1.1]
        // [f, y', x' * c1]

        // update c2, c2' = -y' * c2
        { Fq::copy(2) }
        { Fq::mul_by_constant(&constant.2.c0) }
        // [f, y', x' * c1, y' * c2.0]
        { Fq::roll(3) }
        { Fq::mul_by_constant(&constant.2.c1) }
        // [f, x' * c1, y' * c2.0, y' * c2.1]
        // [f, x' * c1, y' * c2]
        // [f, c1', c2']

        // compute the new f with c1'(c3) and c2'(c4), where c1 is trival value 1
        { Fq12::mul_by_34() }
        // [f]
    }
}

pub fn hinted_ell_by_constant_affine(f: ark_bn254::Fq12, x: ark_bn254::Fq, y: ark_bn254::Fq, constant: &EllCoeff) -> (Script, Vec<Hint>) {
    assert_eq!(constant.0, ark_bn254::Fq2::ONE);
    let mut hints = Vec::new();

    let (hinted_script1, hint1) = Fq::hinted_mul_by_constant(x, &constant.1.c0);
    let (hinted_script2, hint2) = Fq::hinted_mul_by_constant(x, &constant.1.c1);
    let (hinted_script3, hint3) = Fq::hinted_mul_by_constant(y, &constant.2.c0);
    let (hinted_script4, hint4) = Fq::hinted_mul_by_constant(y, &constant.2.c1);
    let mut c1 = constant.1;
    c1.mul_assign_by_fp(&x);
    let mut c2 = constant.2;
    c2.mul_assign_by_fp(&y);
    let (hinted_script5, hint5) = Fq12::hinted_mul_by_34(f, c1, c2);

    let script_lines = vec! [
        // [f, x', y']
        // update c1, c1' = x' * c1
        Fq::copy(1),
        hinted_script1,

        // [f, x', y', x' * c1.0]
        Fq::roll(2),
        hinted_script2,
        // [f, y', x' * c1.0, x' * c1.1]
        // [f, y', x' * c1]

        // update c2, c2' = -y' * c2
        Fq::copy(2),
        hinted_script3,  // Fq::mul_by_constant(&constant.2.c0),
        // [f, y', x' * c1, y' * c2.0]
        Fq::roll(3),
        hinted_script4,
        // [f, x' * c1, y' * c2.0, y' * c2.1]
        // [f, x' * c1, y' * c2]
        // [f, c1', c2']

        // compute the new f with c1'(c3) and c2'(c4), where c1 is trival value 1
        hinted_script5,
        // [f]
    ];

    let mut script = script!{};
    for script_line in script_lines {
        script = script.push_script(script_line.compile());
    }
    hints.extend(hint1);
    hints.extend(hint2);
    hints.extend(hint3);
    hints.extend(hint4);
    hints.extend(hint5);
    
    (script, hints)

}

pub fn collect_line_coeffs(
    constants: Vec<G2Prepared>,
) -> Vec<Vec<Vec<(ark_bn254::Fq2, ark_bn254::Fq2, ark_bn254::Fq2)>>> {
    let mut constant_iters = constants
        .iter()
        .map(|item| item.ell_coeffs.iter())
        .collect::<Vec<_>>();
    let mut all_line_coeffs = vec![];

    for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
        let mut line_coeffs = vec![];
        for j in 0..constants.len() {
            // double line coeff
            let mut line_coeff = vec![];
            line_coeff.push(*constant_iters[j].next().unwrap());
            // add line coeff
            if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == 1
                || ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == -1
            {
                line_coeff.push(*constant_iters[j].next().unwrap());
            }
            // line coeff for single point
            line_coeffs.push(line_coeff);
        }
        // line coeffs for all points
        all_line_coeffs.push(line_coeffs);
    }
    {
        let mut line_coeffs = vec![];
        for j in 0..constants.len() {
            // add line coeff
            line_coeffs.push(vec![*constant_iters[j].next().unwrap()]);
        }
        all_line_coeffs.push(line_coeffs);
    }
    {
        let mut line_coeffs = vec![];
        for j in 0..constants.len() {
            // add line coeff
            line_coeffs.push(vec![*constant_iters[j].next().unwrap()]);
        }
        all_line_coeffs.push(line_coeffs);
    }
    for i in 0..constant_iters.len() {
        assert_eq!(constant_iters[i].next(), None);
    }
    assert_eq!(
        all_line_coeffs.len(),
        ark_bn254::Config::ATE_LOOP_COUNT.len() - 1 + 2
    );
    all_line_coeffs
}

/// input of func (params):
///      p.x, p.y
/// output on stack:
///      x' = -p.x / p.y
///      y' = 1 / p.y
pub fn from_eval_point(p: ark_bn254::G1Affine) -> Script {
    let py_inv = p.y().unwrap().inverse().unwrap();
    script! {
        { Fq::push_u32_le(&BigUint::from(py_inv).to_u32_digits()) }
        // [1/y]
        // check p.y.inv() is valid
        { Fq::copy(0) }
        // [1/y, 1/y]
        { Fq::push_u32_le(&BigUint::from(p.y).to_u32_digits()) }
        // [1/y, 1/y, y]
        { Fq::mul() }
        // [1/y, 1]
        { Fq::push_one() }
        // [1/y, 1, 1]
        { Fq::equalverify(1, 0) }
        // [1/y]

        // -p.x / p.y
        { Fq::copy(0) }
        // [1/y, 1/y]
        { Fq::push_u32_le(&BigUint::from(p.x).to_u32_digits()) }
        // [1/y, 1/y, x]
        { Fq::neg(0) }
        // [1/y, 1/y, -x]
        { Fq::mul() }
        // [1/y, -x/y]
        { Fq::roll(1) }
        // [-x/y, 1/y]
    }
}

/// input of func (params):
///      p.x, p.y
/// output on stack:
///      x' = -p.x / p.y
///      y' = 1 / p.y
pub fn hinted_from_eval_point(p: ark_bn254::G1Affine) -> (Script, Vec<Hint>) {
    let mut hints = Vec::new();

    let py_inv = p.y().unwrap().inverse().unwrap();

    let (hinted_script1, hint1) = Fq::hinted_mul(2, py_inv, 0, p.y);
    let (hinted_script2, hint2) = Fq::hinted_mul(2, py_inv, 0, -p.x);
    let script_lines = vec! [
        Fq::push_u32_le_not_montgomery(&BigUint::from(py_inv).to_u32_digits()),
        // [1/y]
        // check p.y.inv() is valid
        Fq::copy(0),
        // [1/y, 1/y]
        Fq::push_u32_le_not_montgomery(&BigUint::from(p.y).to_u32_digits()),
        // [1/y, 1/y, y]
        hinted_script1,
        // [1/y, 1]
        Fq::push_one_not_montgomery(),
        // [1/y, 1, 1]
        Fq::equalverify(1, 0),
        // [1/y]

        // -p.x / p.y
        Fq::copy(0),
        // [1/y, 1/y]
        Fq::push_u32_le_not_montgomery(&BigUint::from(p.x).to_u32_digits()),
        // [1/y, 1/y, x]
        Fq::neg(0),
        // [1/y, 1/y, -x]
        hinted_script2,
        // [1/y, -x/y]
        Fq::roll(1),
        // [-x/y, 1/y]
    ];

    let mut script = script!{};
    for script_line in script_lines {
        script = script.push_script(script_line.compile());
    }
    hints.extend(hint1);
    hints.extend(hint2);

    (script, hints)
}

/// input of stack:
///      p.x, p.y (affine space)
/// output on stack:
///      x' = -p.x / p.y
///      y' = 1 / p.y
pub fn from_eval_point_in_stack() -> Script {
    script! {
        // [x, y]
        { Fq::copy(0) }
        // [x, y, y]
        { Fq::copy(0) }
        // [x, y, y, y]
        { Fq::inv() }
        // [x, y, y, 1/y]
        // check p.y.inv() is valid
        { Fq::mul() }
        // [x, y, 1]
        { Fq::push_one() }
        // [x, y, 1, 1]
        { Fq::equalverify(1, 0) }
        // [x, y]
        { Fq::inv() }
        // [x, 1/y]

        // -p.x / p.y
        { Fq::copy(0) }
        // [x, 1/y, 1/y]
        { Fq::roll(2)}
        // [1/y, 1/y, x]
        { Fq::neg(0) }
        // [1/y, 1/y, -x]
        { Fq::mul() }
        // [1/y, -x/y]
        { Fq::roll(1) }
        // [-x/y, 1/y]
    }
}

pub fn fq_to_bits(fq: BigInt<4>, limb_size: usize) -> Vec<u32> {
    let mut bits: Vec<bool> = ark_ff::BitIteratorBE::new(fq.as_ref()).skip(2).collect();
    bits.reverse();

    bits.chunks(limb_size)
        .map(|chunk| {
            let mut factor = 1;
            let res = chunk.iter().fold(0, |acc, &x| {
                let r = acc + if x { factor } else { 0 };
                factor *= 2;
                r
            });
            res
        })
        .collect()
}

/// add two points T and Q
///     x' = alpha^2 - T.x - Q.x
///     y' = -bias - alpha * x'
///
/// input on stack:
///     T.x (2 elements)
///     Q.x (2 elements)
///
/// input of parameters:
///     c3: alpha - line slope
///     c4: -bias - line intercept
///
/// output on stack:
///     T'.x (2 elements)
///     T'.y (2 elements)
pub fn affine_add_line(c3: ark_bn254::Fq2, c4: ark_bn254::Fq2) -> Script {
    script! {
        // [T.x, Q.x]
        { Fq2::neg(0) }
        // [T.x, -Q.x]
        { Fq2::roll(2) }
        // [-Q.x, T.x]
        { Fq2::neg(0) }
        // [-T.x - Q.x]
        { Fq2::add(2, 0) }
        // [-T.x - Q.x]
        { fq2_push(c3) }
        // [-T.x - Q.x, alpha]
        { Fq2::copy(0) }
        // [-T.x - Q.x, alpha, alpha]
        { Fq2::square() }
        // [-T.x - Q.x, alpha, alpha^2]
        // calculate x' = alpha^2 - T.x - Q.x
        { Fq2::add(4, 0) }
        // [alpha, x']
        { Fq2::copy(0) }
        // [alpha, x', x']
        { Fq2::mul(4, 0) }
        // [x', alpha * x']
        { Fq2::neg(0) }
        // [x', -alpha * x']
        { fq2_push(c4) }
        // [x', -alpha * x', -bias]
        // compute y' = -bias - alpha * x'
        { Fq2::add(2, 0) }
        // [x', y']
    }
}

pub fn hinted_affine_add_line(tx: ark_bn254::Fq2, qx: ark_bn254::Fq2, c3: ark_bn254::Fq2, c4: ark_bn254::Fq2) -> (Script, Vec<Hint>) {
    let mut hints = Vec::new();
    let (hinted_script1, hint1) = Fq2::hinted_mul(4, c3, 0, c3.square()-tx-qx);

    let script_lines = vec! [
        // [T.x, Q.x]
        Fq2::neg(0),
        // [T.x, -Q.x]
        Fq2::roll(2),
        // [-Q.x, T.x]
        Fq2::neg(0),
        // [-T.x - Q.x]
        Fq2::add(2, 0),
        // [-T.x - Q.x]
        fq2_push_not_montgomery(c3),
        // [-T.x - Q.x, alpha]
        fq2_push_not_montgomery(c3.square()),
        // [-T.x - Q.x, alpha, alpha^2]
        // calculate x' = alpha^2 - T.x - Q.x
        Fq2::add(4, 0),
        // [alpha, x']
        Fq2::copy(0),
        // [alpha, x', x']
        hinted_script1,
        // [x', alpha * x']
        Fq2::neg(0),
        // [x', -alpha * x']
        fq2_push_not_montgomery(c4),
        // [x', -alpha * x', -bias]
        // compute y' = -bias - alpha * x'
        Fq2::add(2, 0),
        // [x', y']
    ];

    let mut script = script!{};
    for script_line in script_lines {
        script = script.push_script(script_line.compile());
    }
    hints.extend(hint1);

    (script, hints)
}

/// double a point T:
///     x' = alpha^2 - 2 * T.x
///     y' = -bias - alpha* x'
///
/// input on stack:
///     T.x (2 elements)
///
/// output on stack:
///     T'.x (2 elements)
///     T'.y (2 elements)
pub fn affine_double_line(c3: ark_bn254::Fq2, c4: ark_bn254::Fq2) -> Script {
    script! {
        { Fq2::double(0) }
        { Fq2::neg(0) }
        // [- 2 * T.x]
        { fq2_push(c3) }
        { Fq2::copy(0) }
        { Fq2::square() }
        // [- 2 * T.x, alpha, alpha^2]
        { Fq2::add(4, 0) }
        { Fq2::copy(0) }
        // [alpha, x', x']
        { Fq2::mul(4, 0) }
        { Fq2::neg(0) }
        // [x', -alpha * x']

        { fq2_push(c4) }
        { Fq2::add(2, 0) }
        // [x', y']
    }
}

pub fn hinted_affine_double_line(tx: ark_bn254::Fq2, c3: ark_bn254::Fq2, c4: ark_bn254::Fq2) -> (Script, Vec<Hint>) {
    let mut hints = Vec::new();

    let (hinted_script1, hint1) = Fq2::hinted_mul(4, c3, 0, c3.square()-tx-tx);

    let script_lines = vec! [
        Fq2::double(0),
        Fq2::neg(0),
        // [- 2 * T.x]
        fq2_push_not_montgomery(c3),
        fq2_push_not_montgomery(c3.square()),
        // [- 2 * T.x, alpha, alpha^2]
        Fq2::add(4, 0),
        Fq2::copy(0),
        // [alpha, x', x']
        hinted_script1,
        Fq2::neg(0),
        // [x', -alpha * x']

        fq2_push_not_montgomery(c4),
        Fq2::add(2, 0),
        // [x', y']
    ];

    let mut script = script!{};
    for script_line in script_lines {
        script = script.push_script(script_line.compile());
    }
    hints.extend(hint1);

    (script, hints)
}

/// check line through one point, that is:
///     y - alpha * x - bias = 0
///
/// input on stack:
///     x (2 elements)
///     y (2 elements)
///
/// input of parameters:
///     c3: alpha
///     c4: -bias
///
/// output:
///     true or false (consumed on stack)
pub fn check_line_through_point(c3: ark_bn254::Fq2, c4: ark_bn254::Fq2) -> Script {
    script! {
        // [x, y]
        { Fq2::roll(2) }
        // [y, x]
        { Fq2::mul_by_constant(&c3) }
        // [y, alpha * x]
        { Fq2::neg(0) }
        // [y, -alpha * x]
        { Fq2::add(2, 0) }
        // [y - alpha * x]

        { fq2_push(c4) }
        // [y - alpha * x, -bias]
        { Fq2::add(2, 0) }
        // [y - alpha * x - bias]

        { Fq2::push_zero() }
        // [y - alpha * x - bias, 0]
        { Fq2::equalverify() }
    }
}

pub fn hinted_check_line_through_point(x: ark_bn254::Fq2, c3: ark_bn254::Fq2, c4: ark_bn254::Fq2) -> (Script, Vec<Hint>) {
    let mut hints: Vec<Hint> = Vec::new();
    
    let (hinted_script1, hint1) = Fq2::hinted_mul_by_constant(x, &c3);

    let script_lines = vec![
        // [x, y]
        Fq2::roll(2),
        // [y, x]
        hinted_script1,
        // [y, alpha * x]
        Fq2::neg(0),
        // [y, -alpha * x]
        Fq2::add(2, 0),
        // [y - alpha * x]

        fq2_push_not_montgomery(c4),
        // [y - alpha * x, -bias]
        Fq2::add(2, 0),
        // [y - alpha * x - bias]

        Fq2::push_zero(),
        // [y - alpha * x - bias, 0]
        Fq2::equalverify(),
    ];

    let mut script = script!{};
    for script_line in script_lines {
        script = script.push_script(script_line.compile());
    }
    hints.extend(hint1);

    (script, hints)
}

/// check whether a tuple coefficient (alpha, -bias) of a tangent line is satisfied with expected point T (affine)
/// two aspects:
///     1. alpha * (2 * T.y) = 3 * T.x^2, make sure the alpha is the right ONE
///     2. T.y - alpha * T.x - bias = 0, make sure the -bias is the right ONE
///
/// input on stack:
///     T.x (2 element)
///     T.y (2 element)
///
/// input of parameters:
///     c3: alpha
///     c4: -bias
///
/// output:
///     true or false (consumed on stack)
pub fn check_tangent_line(c3: ark_bn254::Fq2, c4: ark_bn254::Fq2) -> Script {
    script! {
        // alpha * (2 * T.y) = 3 * T.x^2
        { Fq2::copy(0) }
        { Fq2::double(0) }
        { Fq2::mul_by_constant(&c3) }
        // [T.x, T.y, alpha * (2 * T.y)]
        { Fq2::copy(4) }
        { Fq2::square() }
        { Fq2::copy(0) }
        { Fq2::double(0) }
        { Fq2::add(2, 0) }
        // [T.x, T.y, alpha * (2 * T.y), 3 * T.x^2]
        { Fq2::neg(0) }
        { Fq2::add(2, 0) }
        { Fq2::push_zero() }
        { Fq2::equalverify() }
        // [T.x, T.y]

        // check: T.y - alpha * T.x - bias = 0
        { check_line_through_point(c3, c4) }
        // []
    }
}

pub fn hinted_check_tangent_line(t: ark_bn254::G2Affine, c3: ark_bn254::Fq2, c4: ark_bn254::Fq2) -> (Script, Vec<Hint>) {
    let mut hints = Vec::new();

    let (hinted_script1, hint1) = Fq2::hinted_mul_by_constant(t.y.double(), &c3);
    let (hinted_script2, hint2) = Fq2::hinted_square(t.x);
    let (hinted_script3, hint3) = hinted_check_line_through_point(t.x, c3, c4);

    let script_lines = vec! [
        // alpha * (2 * T.y) = 3 * T.x^2
        Fq2::copy(0),
        Fq2::double(0),
        hinted_script1,
        // [T.x, T.y, alpha * (2 * T.y)]
        Fq2::copy(4),
        hinted_script2,
        Fq2::copy(0),
        Fq2::double(0),
        Fq2::add(2, 0),
        // [T.x, T.y, alpha * (2 * T.y), 3 * T.x^2]
        Fq2::neg(0),
        Fq2::add(2, 0),
        Fq2::push_zero(),
        Fq2::equalverify(),
        // [T.x, T.y]

        // check: T.y - alpha * T.x - bias = 0
        hinted_script3,
        // []
    ];

    let mut script = script!{};
    for script_line in script_lines {
        script = script.push_script(script_line.compile());
    }
    hints.extend(hint1);
    hints.extend(hint2);
    hints.extend(hint3);

    (script, hints)
}

/// check whether a tuple coefficient (alpha, -bias) of a chord line is satisfied with expected points T and Q (both are affine cooordinates)
/// two aspects:
///     1. T.y - alpha * T.x - bias = 0
///     2. Q.y - alpha * Q.x - bias = 0, make sure the alpha/-bias are the right ONEs
///
/// input on stack:
///     T.x (2 elements)
///     T.y (2 elements)
///     Q.x (2 elements)
///     Q.y (2 elements)
///
/// input of parameters:
///     c3: alpha
///     c4: -bias
/// output:
///     true or false (consumed on stack)
pub fn check_chord_line(c3: ark_bn254::Fq2, c4: ark_bn254::Fq2) -> Script {
    script! {
        // check: Q.y - alpha * Q.x - bias = 0
        { check_line_through_point(c3, c4) }
        // [T.x, T.y]
        // check: T.y - alpha * T.x - bias = 0
        { check_line_through_point(c3, c4) }
        // []
    }
}

pub fn hinted_check_chord_line(t: ark_bn254::G2Affine, q: ark_bn254::G2Affine, c3: ark_bn254::Fq2, c4: ark_bn254::Fq2) -> (Script, Vec<Hint>) {
    let mut hints = Vec::new();

    let (mut script, hint1) = hinted_check_line_through_point(q.x, c3, c4);
    let (script2, hint2) = hinted_check_line_through_point(t.x, c3, c4);

    script = script.push_script(script2.compile());

    hints.extend(hint1);
    hints.extend(hint2);

    (script, hints)
}

// stack data: beta^{2 * (p - 1) / 6}, beta^{3 * (p - 1) / 6}, beta^{2 * (p^2 - 1) / 6}, 1/2, B,
// P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, Qx, Qy
// [..., Fq12, Fq12, Fq12, Fq12, Fq, Fq, (Fq, Fq), (Fq, Fq), (Fq, Fq), (Fq, Fq), (Fq, Fq)]
//
// flag == true ? T + Q : T - Q
pub fn add_line_with_flag(flag: bool) -> Script {
    script! {
    // let theta = self.y - &(q.y * &self.z);
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy
    { Fq2::copy(6) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, Ty
    { Fq2::copy(2) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, Ty, Qy
    if !flag {
        { Fq2::neg(0) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, Ty, -Qy
    }
    { Fq2::copy(8) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, Ty, Qy, Tz
    { Fq2::mul(2, 0) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, Ty, Qy * Tz
    { Fq2::sub(2, 0) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, Ty - Qy * Tz

    // let lambda = self.x - &(q.x * &self.z);
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta
    { Fq2::copy(10) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, Tx
    { Fq2::copy(6) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, Tx, Qx
    { Fq2::copy(10) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, Tx, Qx, Tz
    { Fq2::mul(2, 0) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, Tx, Qx * Tz
    { Fq2::sub(2, 0) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, Tx - Qx * Tz

    // let c = theta.square();
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, lambda
    { Fq2::copy(2) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, lambda, theta
    { Fq2::square() }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, lambda, theta^2

    // let d = lambda.square();
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, lambda, c
    { Fq2::copy(2) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, lambda, c, lambda
    { Fq2::square() }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, lambda, c, lambda^2

    // let e = lambda * &d;
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, lambda, c, d
    { Fq2::copy(4) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, lambda, c, d, lambda
    { Fq2::copy(2) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, lambda, c, d, lambda, d
    { Fq2::mul(2, 0) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, lambda, c, d, lambda * d

    // let f = self.z * &c;
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, lambda, c, d, e
    { Fq2::copy(14) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, lambda, c, d, e, Tz
    { Fq2::roll(6) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, lambda, d, e, Tz, c
    { Fq2::mul(2, 0) }
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, lambda, d, e, Tz * c

    // let g = self.x * &d;
    // f, Px, Py, Tx, Ty, Tz, Qx, Qy, theta, lambda, d, e, ff
    { Fq2::roll(18) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, d, e, ff, Tx
    { Fq2::roll(6) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, ff, Tx, d
    { Fq2::mul(2, 0) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, ff, Tx * d

    // let h = e + &f - &g.double();
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, ff, g
    { Fq2::copy(0) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, ff, g, g
    { Fq2::neg(0) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, ff, g, -g
    { Fq2::double(0) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, ff, g, -2g
    { Fq2::roll(4) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, g, -2g, ff
    { Fq2::add(2, 0) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, g, -2g + ff
    { Fq2::copy(4) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, g, -2g + ff, e
    { Fq2::add(2, 0) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, g, -2g + ff + e

    // self.x = lambda * &h;
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, g, h
    { Fq2::copy(0) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, g, h, h
    { Fq2::copy(8) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, g, h, h, lambda
    { Fq2::mul(2, 0) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, g, h, h * lambda

    // self.y = theta * &(g - &h) - &(e * &self.y);
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, g, h, x
    { Fq2::copy(10) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, g, h, x, theta
    { Fq2::roll(6) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, h, x, theta, g
    { Fq2::roll(6) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, x, theta, g, h
    { Fq2::sub(2, 0) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, x, theta, g - h
    { Fq2::mul(2, 0) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, x, theta * (g - h)
    { Fq2::copy(4) }
    // f, Px, Py, Ty, Tz, Qx, Qy, theta, lambda, e, x, theta * (g - h), e
    { Fq2::roll(18) }
    // f, Px, Py, Tz, Qx, Qy, theta, lambda, e, x, theta * (g - h), e, Ty
    { Fq2::mul(2, 0) }
    // f, Px, Py, Tz, Qx, Qy, theta, lambda, e, x, theta * (g - h), e * Ty
    { Fq2::sub(2, 0) }
    // f, Px, Py, Tz, Qx, Qy, theta, lambda, e, x, theta * (g - h) - e * Ty

    // self.z *= &e;
    // f, Px, Py, Tz, Qx, Qy, theta, lambda, e, x, y
    { Fq2::roll(14) }
    // f, Px, Py, Qx, Qy, theta, lambda, e, x, y, Tz
    { Fq2::roll(6) }
    // f, Px, Py, Qx, Qy, theta, lambda, x, y, Tz, e
    { Fq2::mul(2, 0) }
    // f, Px, Py, Qx, Qy, theta, lambda, x, y, Tz * e

    // let j = theta * &q.x - &(lambda * &q.y);
    // f, Px, Py, Qx, Qy, theta, lambda, x, y, z
    { Fq2::copy(8) }
    // f, Px, Py, Qx, Qy, theta, lambda, x, y, z, theta
    { Fq2::roll(14) }
    // f, Px, Py, Qy, theta, lambda, x, y, z, theta, Qx
    { Fq2::mul(2, 0) }
    // f, Px, Py, Qy, theta, lambda, x, y, z, theta * Qx
    { Fq2::copy(8) }
    // f, Px, Py, Qy, theta, lambda, x, y, z, theta * Qx, lambda
    { Fq2::roll(14) }
    // f, Px, Py, theta, lambda, x, y, z, theta * Qx, lambda, Qy
    if !flag {
        { Fq2::neg(0) }
    // f, Px, Py, theta, lambda, x, y, z, theta * Qx, lambda, -Qy
    }
    { Fq2::mul(2, 0) }
    // f, Px, Py, theta, lambda, x, y, z, theta * Qx, lambda * Qy
    { Fq2::sub(2, 0) }
    // f, Px, Py, theta, lambda, x, y, z, theta * Qx - lambda * Qy

    // (lambda, -theta, j)
    // f, Px, Py, theta, lambda, x, y, z, j
    { Fq2::roll(8) }
    // f, Px, Py, theta, x, y, z, j, lambda
    { Fq2::roll(10) }
    // f, Px, Py, x, y, z, j, lambda, theta
    { Fq2::neg(0) }
    // f, Px, Py, x, y, z, j, lambda, -theta
    { Fq2::roll(4) }
    // f, Px, Py, x, y, z, lambda, -theta, j

    }
}

// script of double line for the purpose of non-fixed point in miller loop
// stack data: beta^{2 * (p - 1) / 6}, beta^{3 * (p - 1) / 6}, beta^{2 * (p^2 - 1) / 6}, 1/2, B,
// P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz
// [..., Fq12, Fq12, Fq12, Fq12, Fq, Fq, (Fq, Fq), (Fq, Fq), (Fq, Fq)]
pub fn double_line() -> Script {
    script! {

    // let mut a = self.x * &self.y;
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz
    { Fq2::copy(4) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, Tx
    { Fq2::copy(4) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, Tx, Ty
    { Fq2::mul(2, 0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, Tx * Ty

    // a.mul_assign_by_fp(two_inv);
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a
    { Fq::copy(72) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, 1/2
    { Fq2::mul_by_fq(1, 0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a * 1/2

    // let b = self.y.square();
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a
    { Fq2::copy(4) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, Ty
    { Fq2::square() }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, Ty^2

    // let c = self.z.square();
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b
    { Fq2::copy(4) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, Tz
    { Fq2::square() }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, Tz^2

    // let e = ark_bn254::g2::Config::COEFF_B * &(c.double() + &c);
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c
    { Fq2::copy(0) }
    { Fq2::copy(0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, c, c
    { Fq2::double(0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, c, 2 * c
    { Fq2::add(2, 0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, 3 * c
    { Fq2::copy(76) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, 3 * c, B
    { Fq2::mul(2, 0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, 3 * c * B

    // let f = e.double() + &e;
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, e
    { Fq2::copy(0) }
    { Fq2::copy(0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, e, e, e
    { Fq2::double(0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, e, e, 2 * e
    { Fq2::add(2, 0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, e, 3 * e

    // let mut g = b + &f;
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, e, f
    { Fq2::copy(0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, e, f, f
    { Fq2::copy(8) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, e, f, f, b
    { Fq2::add(2, 0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, e, f, f + b

    // g.mul_assign_by_fp(two_inv);
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, e, f, g
    { Fq::copy(82) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, e, f, g, 1/2
    { Fq2::mul_by_fq(1, 0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, e, f, g * 1/2

    // let h = (self.y + &self.z).square() - &(b + &c);
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Ty, Tz, a, b, c, e, f, g
    { Fq2::roll(14) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, Tz, a, b, c, e, f, g, Ty
    { Fq2::roll(14) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, a, b, c, e, f, g, Ty, Tz
    { Fq2::add(2, 0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, a, b, c, e, f, g, Ty + Tz
    { Fq2::square() }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, a, b, c, e, f, g, (Ty + Tz)^2
    { Fq2::copy(10) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, a, b, c, e, f, g, (Ty + Tz)^2, b
    { Fq2::roll(10) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, a, b, e, f, g, (Ty + Tz)^2, b, c
    { Fq2::add(2, 0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, a, b, e, f, g, (Ty + Tz)^2, b + c
    { Fq2::sub(2, 0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, a, b, e, f, g, (Ty + Tz)^2 - (b + c)

    // let i = e - &b;
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, a, b, e, f, g, h
    { Fq2::copy(6) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, a, b, e, f, g, h, e
    { Fq2::copy(10) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, a, b, e, f, g, h, e, b
    { Fq2::sub(2, 0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, a, b, e, f, g, h, e - b

    // let j = self.x.square();
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, Tx, a, b, e, f, g, h, i
    { Fq2::roll(14) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, a, b, e, f, g, h, i, Tx
    { Fq2::square() }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, a, b, e, f, g, h, i, Tx^2

    // let e_square = e.square();
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, a, b, e, f, g, h, i, j
    { Fq2::roll(10) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, a, b, f, g, h, i, j, e
    { Fq2::square() }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, a, b, f, g, h, i, j, e^2

    // self.x = a * &(b - &f);
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, a, b, f, g, h, i, j, e^2
    { Fq2::roll(14) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, b, f, g, h, i, j, e^2, a
    { Fq2::copy(14) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, b, f, g, h, i, j, e^2, a, b
    { Fq2::roll(14) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, b, g, h, i, j, e^2, a, b, f
    { Fq2::sub(2, 0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, b, g, h, i, j, e^2, a, b - f
    { Fq2::mul(2, 0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, b, g, h, i, j, e^2, a * (b - f)

    // self.y = g.square() - &(e_square.double() + &e_square);
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, b, g, h, i, j, e^2, x
    { Fq2::roll(10) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, b, h, i, j, e^2, x, g
    { Fq2::square() }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, b, h, i, j, e^2, x, g^2
    { Fq2::roll(4) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, b, h, i, j, x, g^2, e^2
    { Fq2::copy(0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, b, h, i, j, x, g^2, e^2, e^2
    { Fq2::double(0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, b, h, i, j, x, g^2, e^2, 2 * e^2
    { Fq2::add(2, 0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, b, h, i, j, x, g^2, 3 * e^2
    { Fq2::sub(2, 0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, b, h, i, j, x, g^2 - 3 * e^2

    // self.z = b * &h;
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, b, h, i, j, x, y
    { Fq2::roll(10) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, h, i, j, x, y, b
    { Fq2::roll(10) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, i, j, x, y, b, h
    { Fq2::copy(0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, i, j, x, y, b, h, h
    { Fq2::mul(4, 2) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, i, j, x, y, h, z

    // (-h, j.double() + &j, i)
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, i, j, x, y, h, z
    { Fq2::roll(2) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, i, j, x, y, z, h
    { Fq2::neg(0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, i, j, x, y, z, -h
    { Fq2::roll(8) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, i, x, y, z, -h, j
    { Fq2::copy(0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, i, x, y, z, -h, j, j
    { Fq2::double(0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, i, x, y, z, -h, j, 2 * j
    { Fq2::add(2, 0) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, i, x, y, z, -h, 3 * j
    { Fq2::roll(10) }
    // 1/2, B, P1, P2, P3, P4, Q4, c, c', wi, f, Px, Py, x, y, z, -h, 3 * j, i

    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::bn254::fq2::Fq2;
    use ark_ff::AdditiveGroup;
    use ark_std::UniformRand;
    use num_traits::One;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_ell() {
        println!("Pairing.ell: {} bytes", ell().len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::Fq12::rand(&mut prng);
            let c0 = ark_bn254::Fq2::rand(&mut prng);
            let c1 = ark_bn254::Fq2::rand(&mut prng);
            let c2 = ark_bn254::Fq2::rand(&mut prng);
            let px = ark_bn254::Fq::rand(&mut prng);
            let py = ark_bn254::Fq::rand(&mut prng);

            let b = {
                let mut c0new = c0;
                c0new.mul_assign_by_fp(&py);

                let mut c1new = c1;
                c1new.mul_assign_by_fp(&px);

                let mut b = a;
                b.mul_by_034(&c0new, &c1new, &c2);
                b
            };

            let script = script! {
                { fq12_push(a) }
                { fq2_push(c0) }
                { fq2_push(c1) }
                { fq2_push(c2) }
                { Fq::push_u32_le(&BigUint::from(px).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(py).to_u32_digits()) }
                ell
                { fq12_push(b) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_ell_by_constant_projective() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::Fq12::rand(&mut prng);
            let b = ark_bn254::g2::G2Affine::rand(&mut prng);
            let px = ark_bn254::Fq::rand(&mut prng);
            let py = ark_bn254::Fq::rand(&mut prng);

            // projective mode
            let coeffs = G2Prepared::from(b);
            let ell_by_constant_script = ell_by_constant(&coeffs.ell_coeffs[0]);
            println!(
                "Pairing.ell_by_constant: {} bytes",
                ell_by_constant_script.len()
            );

            // projective mode as well
            let b = {
                let mut c0new = coeffs.ell_coeffs[0].0;
                c0new.mul_assign_by_fp(&py);

                let mut c1new = coeffs.ell_coeffs[0].1;
                c1new.mul_assign_by_fp(&px);

                let mut b = a;
                b.mul_by_034(&c0new, &c1new, &coeffs.ell_coeffs[0].2);
                b
            };

            let script = script! {
                { fq12_push(a) }
                { Fq::push_u32_le(&BigUint::from(px).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(py).to_u32_digits()) }
                { ell_by_constant_script.clone() }
                { fq12_push(b) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_ell_by_constant_affine() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let f = ark_bn254::Fq12::rand(&mut prng);
        let b = ark_bn254::g2::G2Affine::rand(&mut prng);
        let p = ark_bn254::g1::G1Affine::rand(&mut prng);

        // affine mode
        let coeffs = G2Prepared::from_affine(b);
        let ell_by_constant_affine_script = ell_by_constant_affine(&coeffs.ell_coeffs[0]);
        println!(
            "Pairing.ell_by_constant_affine: {} bytes",
            ell_by_constant_affine_script.len()
        );

        // affine mode as well
        let hint = {
            assert_eq!(coeffs.ell_coeffs[0].0, ark_bn254::fq2::Fq2::ONE);

            let mut f1 = f;
            let mut c1new = coeffs.ell_coeffs[0].1;
            c1new.mul_assign_by_fp(&(-p.x / p.y));

            let mut c2new = coeffs.ell_coeffs[0].2;
            c2new.mul_assign_by_fp(&(p.y.inverse().unwrap()));

            f1.mul_by_034(&coeffs.ell_coeffs[0].0, &c1new, &c2new);
            f1
        };

        let script = script! {
            { fq12_push(f) }
            { from_eval_point(p) }
            { ell_by_constant_affine_script.clone() }
            { fq12_push(hint) }
            { Fq12::equalverify() }
            OP_TRUE
        };
        run(script);
    }

    #[test]
    fn test_hinted_ell_by_constant_affine() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let f = ark_bn254::Fq12::rand(&mut prng);
        let b = ark_bn254::g2::G2Affine::rand(&mut prng);
        let p = ark_bn254::g1::G1Affine::rand(&mut prng);

        // affine mode
        let coeffs = G2Prepared::from_affine(b);
        let (from_eval_point_script, hints_eval) = hinted_from_eval_point(p);
        let (ell_by_constant_affine_script, hints) = hinted_ell_by_constant_affine(f, -p.x / p.y, p.y.inverse().unwrap(),&coeffs.ell_coeffs[0]);
        println!(
            "Pairing.ell_by_constant_affine: {} bytes",
            ell_by_constant_affine_script.len()
        );

        // affine mode as well
        let hint = {
            assert_eq!(coeffs.ell_coeffs[0].0, ark_bn254::fq2::Fq2::ONE);

            let mut f1 = f;
            let mut c1new = coeffs.ell_coeffs[0].1;
            c1new.mul_assign_by_fp(&(-p.x / p.y));

            let mut c2new = coeffs.ell_coeffs[0].2;
            c2new.mul_assign_by_fp(&(p.y.inverse().unwrap()));

            f1.mul_by_034(&coeffs.ell_coeffs[0].0, &c1new, &c2new);
            f1
        };

        let script = script! {
            for tmp in hints_eval { 
                { tmp.push() }
            }
            for tmp in hints { 
                { tmp.push() }
            }
            { fq12_push_not_montgomery(f) }
            { from_eval_point_script }
            { ell_by_constant_affine_script.clone() }
            { fq12_push_not_montgomery(hint) }
            { Fq12::equalverify() }
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_from_eval_point() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let p = ark_bn254::G1Affine::rand(&mut prng);
        let script = script! {
            { from_eval_point(p) }
            { Fq::push_u32_le(&BigUint::from(-p.x / p.y).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(p.y.inverse().unwrap()).to_u32_digits()) }
            { Fq::equalverify(2, 0) }
            { Fq::equalverify(1, 0) }
            OP_TRUE
        };
        run(script);
    }

    #[test]
    fn test_hinted_from_eval_point() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let p = ark_bn254::G1Affine::rand(&mut prng);
        let (ell_by_constant_affine_script, hints) = hinted_from_eval_point(p);
        let script = script! {
            for tmp in hints { 
                { tmp.push() }
            }
            { ell_by_constant_affine_script.clone() }
            { Fq::push_u32_le_not_montgomery(&BigUint::from(-p.x / p.y).to_u32_digits()) }
            { Fq::push_u32_le_not_montgomery(&BigUint::from(p.y.inverse().unwrap()).to_u32_digits()) }
            { Fq::equalverify(2, 0) }
            { Fq::equalverify(1, 0) }
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_affine_add_line() {
        // alpha = (t.y - q.y) / (t.x - q.x)
        // bias = t.y - alpha * t.x
        // x' = alpha^2 - T.x - Q.x
        // y' = -bias - alpha * x'
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t = ark_bn254::G2Affine::rand(&mut prng);
        let q = ark_bn254::G2Affine::rand(&mut prng);
        let alpha = (t.y - q.y) / (t.x - q.x);
        // -bias
        let bias_minus = alpha * t.x - t.y;

        let x = alpha.square() - t.x - q.x;
        let y = bias_minus - alpha * x;

        let script = script! {
            { fq2_push(t.x) }
            { fq2_push(q.x) }
            { affine_add_line(alpha, bias_minus) }
            // [x']
            { fq2_push(y) }
            // [x', y', y]
            { Fq2::equalverify() }
            // [x']
            { fq2_push(x) }
            // [x', x]
            { Fq2::equalverify() }
            // []
            OP_TRUE
            // [OP_TRUE]
        };
        run(script);
    }

    #[test]
    fn test_hinted_affine_add_line() {
        // alpha = (t.y - q.y) / (t.x - q.x)
        // bias = t.y - alpha * t.x
        // x' = alpha^2 - T.x - Q.x
        // y' = -bias - alpha * x'
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t = ark_bn254::G2Affine::rand(&mut prng);
        let q = ark_bn254::G2Affine::rand(&mut prng);
        let alpha = (t.y - q.y) / (t.x - q.x);
        // -bias
        let bias_minus = alpha * t.x - t.y;

        let x = alpha.square() - t.x - q.x;
        let y = bias_minus - alpha * x;
        let (hinted_add_line, hints) = hinted_affine_add_line(t.x, q.x, alpha, bias_minus);

        let script = script! {
            for hint in hints { 
                { hint.push() }
            }
            { fq2_push_not_montgomery(t.x) }
            { fq2_push_not_montgomery(q.x) }
            { hinted_add_line.clone() }
            // [x']
            { fq2_push_not_montgomery(y) }
            // [x', y', y]
            { Fq2::equalverify() }
            // [x']
            { fq2_push_not_montgomery(x) }
            // [x', x]
            { Fq2::equalverify() }
            // []
            OP_TRUE
            // [OP_TRUE]
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
        println!("hinted_add_line: {} @ {} stack", hinted_add_line.len(), exec_result.stats.max_nb_stack_items);
    }

    #[test]
    fn test_affine_double_line() {
        // slope: alpha = 3 * x^2 / 2 * y
        // intercept: bias = y - alpha * x
        // x' = alpha^2 - 2 * x
        // y' = -bias - alpha * x'
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t = ark_bn254::G2Affine::rand(&mut prng);
        let two_inv = ark_bn254::Fq::one().double().inverse().unwrap();
        let three_div_two = (ark_bn254::Fq::one().double() + ark_bn254::Fq::one()) * two_inv;
        let mut alpha = t.x.square();
        alpha /= t.y;
        alpha.mul_assign_by_fp(&three_div_two);
        // -bias
        let bias_minus = alpha * t.x - t.y;

        let x = alpha.square() - t.x.double();
        let y = bias_minus - alpha * x;

        let script = script! {
            { fq2_push(t.x) }
            { affine_double_line(alpha, bias_minus) }
            // [x']
            { fq2_push(y) }
            // [x', y', y]
            { Fq2::equalverify() }
            // [x']
            { fq2_push(x) }
            // [x', x]
            { Fq2::equalverify() }
            // []
            OP_TRUE
            // [OP_TRUE]
        };
        run(script);
    }

    #[test]
    fn test_hinted_affine_double_line() {
        // slope: alpha = 3 * x^2 / 2 * y
        // intercept: bias = y - alpha * x
        // x' = alpha^2 - 2 * x
        // y' = -bias - alpha * x'
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t = ark_bn254::G2Affine::rand(&mut prng);
        let two_inv = ark_bn254::Fq::one().double().inverse().unwrap();
        let three_div_two = (ark_bn254::Fq::one().double() + ark_bn254::Fq::one()) * two_inv;
        let mut alpha = t.x.square();
        alpha /= t.y;
        alpha.mul_assign_by_fp(&three_div_two);
        // -bias
        let bias_minus = alpha * t.x - t.y;

        let x = alpha.square() - t.x.double();
        let y = bias_minus - alpha * x;
        let (hinted_double_line, hints) = hinted_affine_double_line(t.x, alpha, bias_minus);

        let script = script! {
            for hint in hints { 
                { hint.push() }
            }
            { fq2_push_not_montgomery(t.x) }
            { hinted_double_line }
            // [x']
            { fq2_push_not_montgomery(y) }
            // [x', y', y]
            { Fq2::equalverify() }
            // [x']
            { fq2_push_not_montgomery(x) }
            // [x', x]
            { Fq2::equalverify() }
            // []
            OP_TRUE
            // [OP_TRUE]
        };
        run(script);
    }

    #[test]
    fn test_check_tangent_line() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t = ark_bn254::G2Affine::rand(&mut prng);
        let two_inv = ark_bn254::Fq::one().double().inverse().unwrap();
        let three_div_two = (ark_bn254::Fq::one().double() + ark_bn254::Fq::one()) * two_inv;
        let mut alpha = t.x.square();
        alpha /= t.y;
        alpha.mul_assign_by_fp(&three_div_two);
        // -bias
        let bias_minus = alpha * t.x - t.y;
        assert_eq!(alpha * t.x - t.y, bias_minus);
        let script = script! {
            { fq2_push(t.x) }
            { fq2_push(t.y) }
            { check_line_through_point(alpha, bias_minus) }
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);

        println!("check_line: {} @ {} stack", check_line_through_point(alpha, bias_minus).len(), exec_result.stats.max_nb_stack_items);
    }

    #[test]
    fn test_hinted_check_tangent_line() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t = ark_bn254::G2Affine::rand(&mut prng);
        let two_inv = ark_bn254::Fq::one().double().inverse().unwrap();
        let three_div_two = (ark_bn254::Fq::one().double() + ark_bn254::Fq::one()) * two_inv;
        let mut alpha = t.x.square();
        alpha /= t.y;
        alpha.mul_assign_by_fp(&three_div_two);
        // -bias
        let bias_minus = alpha * t.x - t.y;
        assert_eq!(alpha * t.x - t.y, bias_minus);

        let (hinted_check_line, hints) = hinted_check_line_through_point(t.x, alpha, bias_minus);

        let script = script! {
            for hint in hints { 
                { hint.push() }
            }
            { fq2_push_not_montgomery(t.x) }
            { fq2_push_not_montgomery(t.y) }
            { hinted_check_line.clone() }
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
        println!("hinted_check_line: {} @ {} stack", hinted_check_line.len(), exec_result.stats.max_nb_stack_items);
    }

    #[test]
    fn test_check_chord_line() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t = ark_bn254::G2Affine::rand(&mut prng);
        let q = ark_bn254::G2Affine::rand(&mut prng);
        let alpha = (t.y - q.y) / (t.x - q.x);
        // -bias
        let bias_minus = alpha * t.x - t.y;
        assert_eq!(alpha * t.x - t.y, bias_minus);
        let script = script! {
            { fq2_push(t.x) }
            { fq2_push(t.y) }
            { check_line_through_point(alpha, bias_minus) }
            { fq2_push(q.x) }
            { fq2_push(q.y) }
            { check_line_through_point(alpha, bias_minus) }
            OP_TRUE
        };
        run(script);
    }

    #[test]
    fn test_hinted_check_chord_line() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t = ark_bn254::G2Affine::rand(&mut prng);
        let q = ark_bn254::G2Affine::rand(&mut prng);
        let alpha = (t.y - q.y) / (t.x - q.x);
        // -bias
        let bias_minus = alpha * t.x - t.y;
        assert_eq!(alpha * t.x - t.y, bias_minus);
        let (hinted_check_line, hints) = hinted_check_chord_line(t, q, alpha, bias_minus);

        let script = script! {
            for hint in hints { 
                { hint.push() }
            }
            { fq2_push_not_montgomery(t.x) }
            { fq2_push_not_montgomery(t.y) }
            { fq2_push_not_montgomery(q.x) }
            { fq2_push_not_montgomery(q.y) }
            { hinted_check_line.clone() }
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
        println!("hinted_check_line: {} @ {} stack", hinted_check_line.len(), exec_result.stats.max_nb_stack_items);
    }
}
