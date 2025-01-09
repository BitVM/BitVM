use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::fq::Fq;
use crate::bn254::fq2::Fq2;
use crate::bn254::fq12::Fq12;
use crate::bn254::ell_coeffs::EllCoeff;
use crate::bn254::ell_coeffs::G2Prepared;
use crate::treepp::{script, Script};
use super::utils::Hint;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{AdditiveGroup, Field};
use std::ops::{Add, Div, Mul, Sub};
use bitcoin::ScriptBuf;
use ark_ec::bn::BnConfig;

pub struct G2Affine;

//B = Fq2(19485874751759354771024239261021720505790618469301721065564631296452457478373,
//266929791119991161246907387137283842545076965332900288569378510910307636690)
impl G2Affine {
    pub fn is_on_curve() -> Script {
        script! {
            { Fq2::copy(2) }
            { Fq2::square() }
            { Fq2::roll(4) }
            { Fq2::mul(2,0) }
            { Fq::push_dec("19485874751759354771024239261021720505790618469301721065564631296452457478373") }
            { Fq::push_dec("266929791119991161246907387137283842545076965332900288569378510910307636690") }
            { Fq2::add(2, 0) }
            { Fq2::roll(2) }
            { Fq2::square() }
            { Fq2::equal() }
        }
    }

    pub fn hinted_is_on_curve(x: ark_bn254::Fq2, y: ark_bn254::Fq2) -> (Script, Vec<Hint>) {
        let (x_sq, x_sq_hint) = Fq2::hinted_square(x);
        let (x_cu, x_cu_hint) = Fq2::hinted_mul(0, x, 2, x*x);
        let (y_sq, y_sq_hint) = Fq2::hinted_square(y);

        let mut hints = Vec::new();
        hints.extend(x_sq_hint);
        hints.extend(x_cu_hint);
        hints.extend(y_sq_hint);

        let scr = script! {
            { Fq2::copy(2) }
            { x_sq }
            { Fq2::roll(4) }
            { x_cu }
            { Fq::push_dec_not_montgomery("19485874751759354771024239261021720505790618469301721065564631296452457478373") }
            { Fq::push_dec_not_montgomery("266929791119991161246907387137283842545076965332900288569378510910307636690") }
            { Fq2::add(2, 0) }
            { Fq2::roll(2) }
            { y_sq }
            { Fq2::equal() }
        };
        (scr, hints)
    }

    pub fn push_not_montgomery(element: ark_bn254::G2Affine) -> Script {
        script! {
            { Fq2::push_not_montgomery(element.x) }
            { Fq2::push_not_montgomery(element.y) }
        }
    }

    pub fn read_from_stack_not_montgomery(witness: Vec<Vec<u8>>) -> ark_bn254::G2Affine {
        assert_eq!(witness.len() as u32, Fq::N_LIMBS * 4);
        let x = Fq2::read_from_stack_not_montgomery(witness[0..2 * Fq::N_LIMBS as usize].to_vec());
        let y = Fq2::read_from_stack_not_montgomery(
            witness[2 * Fq::N_LIMBS as usize..4 * Fq::N_LIMBS as usize].to_vec(),
        );
        ark_bn254::G2Affine {
            x,
            y,
            infinity: false,
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

pub fn hinted_ell_by_constant_affine_and_sparse_mul(
    f: ark_bn254::Fq12,
    x: ark_bn254::Fq,
    y: ark_bn254::Fq,
    constant: &EllCoeff,
) -> (Script, Vec<Hint>) {
    assert_eq!(constant.0, ark_bn254::Fq2::ONE);
    let mut hints = Vec::new();

    let (hinted_script_ell, hint_ell) = hinted_ell_by_constant_affine(x, y, constant.1, constant.2);

    let mut c1 = constant.1;
    c1.mul_assign_by_fp(&x);
    let mut c2 = constant.2;
    c2.mul_assign_by_fp(&y);
    let (hinted_script5, hint5) = Fq12::hinted_mul_by_34(f, c1, c2);

    let hinted_script_constant = script! {
        for _ in 0..4 {
            for _ in 0..Fq::N_LIMBS {
                OP_DEPTH OP_1SUB OP_ROLL 
            }  
        }
     };
    let script = script! {
        {hinted_script_constant}
         // // [slope, bias, f,  x', y']
         // {Fq2::roll(16)}, {Fq2::roll(16)},
         // [f, x', y', slope, bias]
         {Fq2::roll(4)}
         // [f, slope, bias, x', y']
         {hinted_script_ell}
         // [f, c1', c2']
         // compute the new f with c1'(c3) and c2'(c4), where c1 is trival value 1
         {hinted_script5}
         // [f]
    };

    hints.extend_from_slice(&vec![
        Hint::Fq(constant.1.c0),
        Hint::Fq(constant.1.c1),
        Hint::Fq(constant.2.c0),
        Hint::Fq(constant.2.c1),
    ]);

    hints.extend(hint_ell);
    hints.extend(hint5);


    (script, hints)
}


pub fn hinted_ell_by_constant_affine(x: ark_bn254::Fq, y: ark_bn254::Fq, slope: ark_bn254::Fq2, bias: ark_bn254::Fq2) -> (Script, Vec<Hint>) {
    let mut hints = Vec::new();

    let (hinted_script1, hint1) = Fq::hinted_mul(1, x, 0, slope.c0);
    let (hinted_script2, hint2) = Fq::hinted_mul(1, x, 0, slope.c1);
    let (hinted_script3, hint3) = Fq::hinted_mul(1, y, 0, bias.c0);
    let (hinted_script4, hint4) = Fq::hinted_mul(1, y, 0, bias.c1);


    let script_lines = vec! [
        // [slope, bias, x', y']
        // update c1, c1' = x' * c1
        Fq::copy(1),
        // [slope0, slope1, bias0, bias1, x', y', x']
        Fq::roll(6),
        // [slope1, bias0, bias1, x', y', x', slope0]
        hinted_script1,
        // [slope1, bias0, bias1, x', y', x'* slope0]

        Fq::roll(2),
        // [slope1, bias0, bias1, y', x'* slope0, x']
        Fq::roll(5),
        // [bias0, bias1, y', x'* slope0, x', slope1]
        hinted_script2,
        // [bias0, bias1, y', x'* slope0, x'* slope1]

        // update c2, c2' = -y' * c2
        Fq::copy(2),
        // [bias0, bias1, y', x'* slope0, x'* slope1, y']
        Fq::roll(5),
        // [bias1, y', x'* slope0, x'* slope1, y', bias0]
        hinted_script3,  
        // [bias1, y', x'* slope0, x'* slope1, y'*bias0]
        Fq::roll(3),
        // [bias1, x'* slope0, x'* slope1, y'*bias0, y']
        Fq::roll(4),
        // [x'* slope0, x'* slope1, y'*bias0, y', bias1]
        hinted_script4,
        // [x'* slope0, x'* slope1, y'*bias0, y'* bias1]

    ];

    let mut script = script!{};
    for script_line in script_lines {
        script = script.push_script(script_line.compile());
    }
    hints.extend(hint1);
    hints.extend(hint2);
    hints.extend(hint3);
    hints.extend(hint4);
    
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
        for constant in &mut constant_iters {
            // double line coeff
            let mut line_coeff = vec![];
            line_coeff.push(*constant.next().unwrap());
            // add line coeff
            if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == 1
                || ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == -1
            {
                line_coeff.push(*constant.next().unwrap());
            }
            // line coeff for single point
            line_coeffs.push(line_coeff);
        }
        // line coeffs for all points
        all_line_coeffs.push(line_coeffs);
    }
    {
        let mut line_coeffs = vec![];
        for constant in &mut constant_iters {
            // add line coeff
            line_coeffs.push(vec![*constant.next().unwrap()]);
        }
        all_line_coeffs.push(line_coeffs);
    }
    {
        let mut line_coeffs = vec![];
        for constant in &mut constant_iters {
            // add line coeff
            line_coeffs.push(vec![*constant.next().unwrap()]);
        }
        all_line_coeffs.push(line_coeffs);
    }
    for constant in &mut constant_iters {
        assert_eq!(constant.next(), None);
    }
    assert_eq!(
        all_line_coeffs.len(),
        ark_bn254::Config::ATE_LOOP_COUNT.len() - 1 + 2
    );
    all_line_coeffs
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
        { Fq2::push(c3) }
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
        { Fq2::push(c4) }
        // [x', -alpha * x', -bias]
        // compute y' = -bias - alpha * x'
        { Fq2::add(2, 0) }
        // [x', y']
    }
}

pub fn hinted_affine_add_line(
    tx: ark_bn254::Fq2,
    qx: ark_bn254::Fq2,
    c3: ark_bn254::Fq2,
    _c4: ark_bn254::Fq2,
) -> (Script, Vec<Hint>) {
    let mut hints = Vec::new();
    let (hinted_script0, hint0) = Fq2::hinted_square(c3);
    let (hinted_script1, hint1) = Fq2::hinted_mul(4, c3, 0, c3.square() - tx - qx);

    let script_lines = vec![
        // [c3, c4, T.x, Q.x]
        Fq2::neg(0),
        // [c3, c4,T.x, -Q.x]
        Fq2::roll(2),
        // [c3, c4,-Q.x, T.x]
        Fq2::neg(0),
        // [c3, c4, -Q.x. -T.x]
        Fq2::add(2, 0),
        // [c3, c4, -T.x - Q.x]
        Fq2::copy(4), // Fq2::push_not_montgomery(c3),
        // [c3, c4, -T.x - Q.x, alpha]
        Fq2::copy(0),
        hinted_script0, // Fq2::push_not_montgomery(c3.square()),
        // [c3, c4, -T.x - Q.x, alpha, alpha^2]
        // calculate x' = alpha^2 - T.x - Q.x
        Fq2::add(4, 0),
        // [c3, c4, alpha, x']
        Fq2::copy(0),
        // [c3, c4, alpha, x', x']
        hinted_script1,
        // [c3, c4, x', alpha * x']
        Fq2::neg(0),
        // [c3, c4, x', -alpha * x']
        Fq2::copy(4),// Fq2::push_not_montgomery(c4),
        // [x', -alpha * x', -bias]
        // compute y' = -bias - alpha * x'
        Fq2::add(2, 0),
        // [c3, c4, x', y']
    ];

    let mut script = script! {};
    for script_line in script_lines {
        script = script.push_script(script_line.compile());
    }
    hints.extend(hint0);
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
        { Fq2::push(c3) }
        { Fq2::copy(0) }
        { Fq2::square() }
        // [- 2 * T.x, alpha, alpha^2]
        { Fq2::add(4, 0) }
        { Fq2::copy(0) }
        // [alpha, x', x']
        { Fq2::mul(4, 0) }
        { Fq2::neg(0) }
        // [x', -alpha * x']

        { Fq2::push(c4) }
        { Fq2::add(2, 0) }
        // [x', y']
    }
}

pub fn hinted_affine_double_line(
    tx: ark_bn254::Fq2,
    c3: ark_bn254::Fq2,
    _c4: ark_bn254::Fq2,
) -> (Script, Vec<Hint>) {
    let mut hints = Vec::new();

    let (hinted_script0, hint0) = Fq2::hinted_square(c3);
    let (hinted_script1, hint1) = Fq2::hinted_mul(4, c3, 0, c3.square() - tx - tx);

    //[c3(2), c4(2), t.x(2)]
    let script_lines = vec![
        Fq2::double(0),
        Fq2::neg(0),
        // [c3(2), c4(2), - 2 * T.x(2)]
        Fq2::copy(4),// Fq2::push_not_montgomery(c3),
        Fq2::copy(0),
        hinted_script0, // Fq2::push_not_montgomery(c3.square()),
        // [c3(2), c4(2), - 2 * T.x, alpha, alpha^2]
        Fq2::add(4, 0),
        Fq2::copy(0),
        // [c3(2), c4(2), alpha, x', x']
        hinted_script1,
        Fq2::neg(0),
        // [c3(2), c4(2), x', -alpha * x']
        Fq2::copy(4),//Fq2::push_not_montgomery(c4),
        // [c3(2), c4(2), x', -alpha * x', c4(2)]
        Fq2::add(2, 0),
        // [c3(2), c4(2), x', y']
    ];

    let mut script = script! {};
    for script_line in script_lines {
        script = script.push_script(script_line.compile());
    }
    hints.extend(hint0);
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

        { Fq2::push(c4) }
        // [y - alpha * x, -bias]
        { Fq2::add(2, 0) }
        // [y - alpha * x - bias]

        { Fq2::push_zero() }
        // [y - alpha * x - bias, 0]
        { Fq2::equalverify() }
    }
}


pub fn hinted_check_tangent_line(
    t: ark_bn254::G2Affine,
    c3: ark_bn254::Fq2,
    c4: ark_bn254::Fq2,
) -> (Script, Vec<Hint>) {
    let mut hints = Vec::new();

    // let (hinted_script1, hint1) = Fq2::hinted_mul_by_constant(t.y.double(), &c3);
    let (hinted_script1, hint1) = Fq2::hinted_mul(2, t.y.double(), 0, c3);
    let (hinted_script2, hint2) = Fq2::hinted_square(t.x);
    let (hinted_script3, hint3) = hinted_check_line_through_point(t.x, c3, c4);
    
    // [c3(2),c4(2),t(4) ]
    let script_lines = vec![
        // alpha * (2 * T.y) = 3 * T.x^2
        Fq2::copy(0),
        Fq2::double(0),
        // [c3(2),c4(2),t(4),t.y*2 (2)]
        Fq2::copy(8),
        // [c3(2),c4(2),t(4),t.y*2 (2), c3(2)]
        hinted_script1,
        // [c3(2),c4(2), T.x(2), T.y(2), alpha * 2 * T.y (2)]
        Fq2::copy(4),
        // [c3(2),c4(2), T.x(2), T.y(2), alpha * 2 * T.y (2), T.x(2)]
        hinted_script2,
        // [c3(2),c4(2), T.x(2), T.y(2), alpha * 2 * T.y (2), T.x^2(2)]
        Fq2::copy(0),
        // [c3(2),c4(2), T.x(2), T.y(2), alpha * 2 * T.y (2), T.x^2(2), T.x^2(2) ]
        Fq2::double(0),
        // [c3(2),c4(2), T.x(2), T.y(2), alpha * 2 * T.y (2), T.x^2(2), 2 * T.x^2(2) ]
        Fq2::add(2, 0),
        // [c3(2),c4(2), T.x(2), T.y(2), alpha * 2 * T.y(2), 3 * T.x^2(2)]
        Fq2::neg(0),
        Fq2::add(2, 0),
        Fq2::push_zero(),
        Fq2::equalverify(),
        // [c3(2),c4(2), T.x(2), T.y(2)]

        // check: T.y - alpha * T.x - bias = 0
        hinted_script3,
        // [c3(2),c4(2)]
    ];

    let mut script = script! {};
    for script_line in script_lines {
        script = script.push_script(script_line.compile());
    }
    hints.extend(hint1);
    hints.extend(hint2);
    hints.extend(hint3);

    (script, hints)
}

pub fn hinted_check_line_through_point(
    x: ark_bn254::Fq2,
    c3: ark_bn254::Fq2,
    _c4: ark_bn254::Fq2,
) -> (Script, Vec<Hint>) {
    let mut hints: Vec<Hint> = Vec::new();

    // let (hinted_script1, hint1) = Fq2::hinted_mul_by_constant(x, &c3);
    let (hinted_script1, hint1) = Fq2::hinted_mul(2, x, 0, c3);

    let script_lines = vec![
        // [c3, c4, x, y]
        Fq2::roll(2),
        // [c3, c4, y, x]
        Fq2::copy(6),
        // [c3, c4, y, x,c3]
        hinted_script1,
        // [c3, c4, y, alpha * x]
        Fq2::neg(0),
        // [c3, c4, y, -alpha * x]
        Fq2::add(2, 0),
        // [c3, c4, y - alpha * x]
        Fq2::copy(2), // Fq2::push_not_montgomery(c4),
        // [c3, c4, y - alpha * x, -bias]
        Fq2::add(2, 0),
        // [c3, c4, y - alpha * x - bias]
        Fq2::push_zero(),
        // [c3, c4, y - alpha * x - bias, 0]
        Fq2::equalverify(),
        // [c3, c4]
    ];

    let mut script = script! {};
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

pub fn hinted_check_chord_line(
    t: ark_bn254::G2Affine,
    q: ark_bn254::G2Affine,
    c3: ark_bn254::Fq2,
    c4: ark_bn254::Fq2,
) -> (Script, Vec<Hint>) {
    let mut hints = Vec::new();

    let (script1, hint1) = hinted_check_line_through_point(q.x, c3, c4);
    let (script2, hint2) = hinted_check_line_through_point(t.x, c3, c4);

     
    //[c3(2),c4(2),t(4),q(4)]
     let script_lines = vec![
        Fq2::copy(10),
        // [c3(2),c4(2),t(4),q(4),c3(2)]
        Fq2::copy(10),
        // [c3(2),c4(2),t(4),q(4),c3(2),c4(2)]
        Fq2::roll(6),
        Fq2::roll(6),
        //[c3(2),c4(2),t(4),c3(2),c4(2),q(4)]
        script1,
        // // [c3(2),c4(2),t4(4),c3(2),c4(2)]
        Fq2::roll(6),
        Fq2::roll(6),
        // [c3(2),c4(2),c3(2),c4(2),t4(4)]
        script2,
        // [c3(2),c4(2),c3(2),c4(2)]
        Fq2::drop(),
        Fq2::drop(),
        // [c3(2),c4(2)]
    ];

    let mut script = script! {};
    for script_line in script_lines {
        script = script.push_script(script_line.compile());
    }

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


#[derive(Debug, Default, Clone)]
pub struct ScriptContext<F: ark_ff::Field> {
    pub inputs: Vec<F>,
    pub outputs: Vec<F>,
    pub auxiliary: Vec<usize>,
}

#[derive(Debug, Clone, Default)]
pub struct SplitScript {
    pub script: ScriptBuf,
    pub input_len: u32,
    pub output_len: u32,
}

pub struct PairingNative;

impl PairingNative {
    // Reference: https://github.com/arkworks-rs/algebra/blob/master/curves/bn254/src/curves/g2.rs#L59
    // https://github.com/BitVM/BitVM/issues/109
    pub fn witness_g2_subgroup_check(
        point: &ark_bn254::g2::G2Affine,
        constants: [ark_bn254::Fq2; 2],
        scalar_bit: Vec<bool>,
    ) -> (bool, Vec<ScriptContext<ark_bn254::Fq2>>) {
        let mut script_contexts = vec![];

        let mut script_context = ScriptContext::default();

        // Maps (x,y) -> (x^p * (u+9)^((p-1)/3), y^p * (u+9)^((p-1)/2))
        script_context
            .inputs
            .push(point.clone().x().unwrap().to_owned());
        script_context
            .inputs
            .push(point.clone().y().unwrap().to_owned());

        let mut p_times_point = *point;
        p_times_point.x.frobenius_map_in_place(1);
        p_times_point.y.frobenius_map_in_place(1);

        p_times_point.x *= constants[0];
        p_times_point.y *= constants[1];

        script_context
            .outputs
            .push(p_times_point.clone().x().unwrap().to_owned());
        script_context
            .outputs
            .push(p_times_point.clone().y().unwrap().to_owned());

        script_contexts.push(script_context);

        let (x_times_point, witness) = Self::witness_split_scalar_mul_g2(point, &scalar_bit);

        assert_eq!(p_times_point, x_times_point);

        script_contexts.extend(witness);

        (true, script_contexts)
    }
    
    pub fn witness_split_scalar_mul_g2(
        base: &ark_bn254::G2Affine,
        scalar: &[bool],
    ) -> (ark_bn254::G2Affine, Vec<ScriptContext<ark_bn254::Fq2>>) {
        let res = base.to_owned();
        let mut tmp = base.to_owned();

        let mut script_contexts = vec![];

        for b in scalar.iter().skip(1) {

            let (lambda, miu, res_x, res_y) = PairingNative::line_double_g2(&tmp);

            let mut script_context = ScriptContext::default();

            script_context.inputs.push(lambda);
            script_context.inputs.push(miu);
            script_context.inputs.push(tmp.x().unwrap().to_owned());
            script_context.inputs.push(tmp.y().unwrap().to_owned());
            script_context.outputs.push(res_x);
            script_context.outputs.push(res_y);

            tmp = tmp.add(tmp).into_affine();

            assert_eq!(res_x, tmp.x().unwrap().clone());
            assert_eq!(res_y, tmp.y().unwrap().clone());

            // ecc_double_add_data_set.push(ecc_double_add_data_tmp);
            script_contexts.push(script_context);

            if *b {
                let mut script_context = ScriptContext::default();

                let (lambda, miu, res_x, res_y) = PairingNative::line_add_g2(&res, &tmp);

                script_context.inputs.push(lambda);
                script_context.inputs.push(miu);
                script_context.inputs.push(res.x().unwrap().to_owned());
                script_context.inputs.push(res.y().unwrap().to_owned());
                script_context.inputs.push(tmp.x().unwrap().to_owned());
                script_context.inputs.push(tmp.y().unwrap().to_owned());
                script_context.outputs.push(res_x);
                script_context.outputs.push(res_y);

                tmp = tmp.add(res).into_affine();

                assert_eq!(res_x, tmp.x().unwrap().clone());
                assert_eq!(res_y, tmp.y().unwrap().clone());

                script_contexts.push(script_context);
            }
        }

        (tmp, script_contexts)
    }

    pub fn line_add_g2(
        point1: &ark_bn254::G2Affine,
        point2: &ark_bn254::G2Affine,
    ) -> (
        ark_bn254::Fq2,
        ark_bn254::Fq2,
        ark_bn254::Fq2,
        ark_bn254::Fq2,
    ) {
        let (x1, y1) = (point1.x, point1.y);
        let (x2, y2) = (point2.x, point2.y);

        // slope: alpha = (y2-y1)/(x2-x1)
        let alpha = (y2.sub(y1)).div(x2.sub(x1));
        // bias = y1 - alpha * x1
        let bias = y1 - alpha * x1;

        let x3 = alpha.square() - x1 - x2;
        let y3 = -(bias + alpha * x3);

        (alpha, bias, x3, y3)
    }

    pub fn line_double_g2(
        point: &ark_bn254::G2Affine,
    ) -> (
        ark_bn254::Fq2,
        ark_bn254::Fq2,
        ark_bn254::Fq2,
        ark_bn254::Fq2,
    ) {
        let (x, y) = (point.x, point.y);

        // slope: alpha = 3 * x ^ 2 / (2 * y)
        let alpha = x
            .square()
            .mul(ark_bn254::Fq2::from(3))
            .div(y.mul(ark_bn254::Fq2::from(2)));
        // bias = y - alpha * x
        let bias = y - alpha * x;

        let x3 = alpha.square() - x.double();
        let y3 = -(bias + alpha * x3);

        (alpha, bias, x3, y3)
    }
}
pub struct PairingSplitScript;

impl PairingSplitScript {
    pub fn scalar_mul_split_g2(scalar_bit: Vec<bool>) -> Vec<Script> {
        let mut script_chunks: Vec<Script> = vec![];

        for bit in scalar_bit.iter().skip(1) {
            script_chunks.push(Self::double_line_g2());

            if *bit {
                script_chunks.push(Self::add_line_g2());
            }
        }

        script_chunks
    }

    // Stack top: [Q.x, Q.y]
    // Stack top: [Q.x, Q.y * fro]
    // Stack top: [Q.x, Q.y * fro * constant_1]
    // Stack top: [Q.x] | [Q.y * fro * constant_1]
    // Stack top: [Q.x * fro] | [Q.y * fro * constant_1]
    // Stack top: [Q.x * fro * constant_0] | [Q.y * fro * constant_1]
    // Stack top: [Q.x * fro * constant_0, Q.y * fro * constant_1]
    pub fn g2_subgroup_check(constants: [ark_bn254::Fq2; 2], scalar_bit: Vec<bool>) -> Vec<Script> {
        let mut res = vec![];

        res.push(script! {

            { Fq2::frobenius_map(1)}
            { Fq2::mul_by_constant(&constants[1])}
            { Fq2::toaltstack()}
            { Fq2::frobenius_map(1)}
            { Fq2::mul_by_constant(&constants[0])}
            { Fq2::fromaltstack()}

        });

        res.extend(Self::scalar_mul_split_g2(scalar_bit));

        res
    } // Stack top: [lamda, mu,   Q.x, Q.y ]
      // Type:      [Fq2,   Fq2, (Fq2, Fq2)]
    pub fn double_line_g2() -> Script {
        script! {
            // check 2*lamda*y == 3 * q.x^2
            // [lamda, mu, x, y, y ]
            { Fq2::copy(0) }
            // [lamda, mu, x, y, y, lamda ]
            { Fq2::copy(8) }
            // [lamda, mu, x, y, y * lamda ]
            { Fq2::mul(0, 2) }
            // [lamda, mu, x, y, 2 *y * lamda ]
            { Fq2::double(0) }
            // [lamda, mu, x, y] | [ 2 *y * lamda ]
            { Fq2::toaltstack() }
            // 2 * lamda * y == 3 * x^2
            // [lamda, mu, x, y, x] | [ 2 *y * lamda ]
            { Fq2::copy(2) }
            // [lamda, mu, x, y, x^2] | [ 2 *y * lamda ]
            { Fq2::square() }
            // [lamda, mu, x, y, x^2, x^2] | [ 2 *y * lamda ]
            { Fq2::copy(0) }
            // [lamda, mu, x, y, x^2, 2x^2] | [ 2 *y * lamda ]
            { Fq2::double(0) }
            // [lamda, mu, x, y, 3x^2] | [ 2 *y * lamda ]
            { Fq2::add(0, 2) }
            // [lamda, mu, x, y, 3x^2, 2 *y * lamda ]
            { Fq2::fromaltstack() }
            // [lamda, mu, x, y]
            { Fq2::equalverify() }
            // check y - lamda * x _ mu == 0
            // [lamda, mu, x, y, mu]
            { Fq2::copy(4) }
            // [lamda, mu, x, y - mu]
            { Fq2::sub(2, 0) }
            // [lamda, mu, x, y - mu, x]
            { Fq2::copy(2) }
            // [lamda, mu, x, y - mu, x, lamda]
            { Fq2::copy(8) }
            // [lamda, mu, x, y - mu, x * lamda]
            { Fq2::mul(0, 2) }
            // [lamda, mu, x, y - mu - x * lamda]
            { Fq2::sub(2, 0) }
            // [lamda, mu, x, y - mu - x * lamda, 0]
            { Fq2::push_zero() }
            // [lamda, mu, x]
            { Fq2::equalverify() }
            // calcylate x_3 = lamda^2 - 2x
            // [lamda, mu, x, lamda]
            { Fq2::copy(4) }
            // [lamda, mu, x, lamda^2]
            { Fq2::square() }
            // [lamda, mu, lamda^2, 2x]
            { Fq2::double(2) }
            // [lamda, mu, lamda^2 - 2x]
            { Fq2::sub(2, 0) }
            // [lamda, mu, x3, x3 ]
            { Fq2::copy(0) }
            // [mu, x3, lamda * x3 ]
            { Fq2::mul(0, 6) }
            // [x3, lamda * x3 + mu ]
            { Fq2::add(0, 4) }
            // [x3, y3 ]
            { Fq2::neg(0) }
        }
    }

    // Stack top: [lamda, mu,  Q.x1, Q.y1, Q.x2, Q.y2 ]
    // Type:      [Fq2,   Fq2, (Fq2, Fq2), (Fq2, Fq2)]
    pub fn add_line_g2() -> Script {
        script! {
            // check y2 - lamda * x2 - mu == 0
            // [lamda, mu, x1, y1, x2, y2, mu]
            { Fq2::copy(8) }
            // [lamda, mu, x1, y1, x2, y2 - mu]
            { Fq2::sub(2, 0) }
            // [lamda, mu, x1, y1, x2, y2 - mu, x2]
            { Fq2::copy(2) }
            // [lamda, mu, x1, y1, x2, y2 - mu, x2, lambda]
            { Fq2::copy(12) }
            // [lamda, mu, x1, y1, x2, y2 - mu, x2 * lambda]
            { Fq2::mul(0, 2) }
            // [lamda, mu, x1, y1, x2, y2 - mu - x2 * lambda]
            { Fq2::sub(2, 0) }
            // [lamda, mu, x1, y1, x2, y2 - mu - x2 * lambda, 0]
            { Fq2::push_zero() }
            // [lamda, mu, x1, y1, x2]
            { Fq2::equalverify() }
            // check y1 - lamda * x1 - mu == 0
            // [lamda, mu, x1, y1, x2, mu]
            { Fq2::copy(6) }
            // [lamda, mu, x1, x2, y1 - mu]
            { Fq2::sub(4, 0) }
            // [lamda, mu, x1, x2, y1 - mu, x1]
            { Fq2::copy(4) }
            // [lamda, mu, x1, x2, y1 - mu, x1, lambda]
            { Fq2::copy(10) }
            // [lamda, mu, x1, x2, y1 - mu, x1 * lambda]
            { Fq2::mul(0, 2) }
            // [lamda, mu, x1, x2, y1 - mu - x1 * lambda]
            { Fq2::sub(2, 0) }
            // [lamda, mu, x1, x2, y1 - mu - x2 * lambda, 0]
            { Fq2::push_zero() }
            // [lamda, mu, x1, x2]
            { Fq2::equalverify() }
            // calcylate x_3 = lamda^2 - x1 - x2
            // [lamda, mu, x1 + x2]
            {Fq2::add(0, 2)}
            // [lamda, mu, x1 + x2, lamda]
            { Fq2::copy(4) }
            // [lamda, mu, x1 + x2, lamda^2]
            { Fq2::square() }
            // [lamda, mu, lamda^2 - (x1 + x2)]
            { Fq2::sub(0, 2) }
            // [lamda, mu, x3, x3 ]
            { Fq2::copy(0) }
            // [mu, x3, lamda * x3 ]
            { Fq2::mul(0, 6) }
            // [x3, lamda * x3 + mu ]
            { Fq2::add(0, 4) }
            // [x3, y3 ]
            { Fq2::neg(0) }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::bn254::g1::{from_eval_point, hinted_from_eval_point, G1Affine};
    use crate::bn254::g2::G2Affine;
    use crate::bn254::fq::Fq;
    use crate::bn254::fq2::Fq2;
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::chunker::common::extract_witness_from_stack;
    use crate::{execute_script, run, treepp::*};
    use super::*;
    use ark_std::UniformRand;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::str::FromStr;
    use ark_std::end_timer;
    use ark_std::start_timer;
    use num_bigint::BigUint;
    use ark_ff::AdditiveGroup;
    use num_traits::One;

    #[test]
    fn test_read_from_stack() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let a = ark_bn254::G1Affine::rand(&mut prng);
        let script = script! {
            {G1Affine::push_not_montgomery(a)}
        };

        let res = execute_script(script);
        let witness = extract_witness_from_stack(res);
        let recovered_a = G1Affine::read_from_stack_not_montgomery(witness);

        assert_eq!(a, recovered_a);

        let b = ark_bn254::G2Affine::rand(&mut prng);
        let script = script! {
            {G2Affine::push_not_montgomery(b)}
        };

        let res = execute_script(script);
        let witness = extract_witness_from_stack(res);
        let recovered_b = G2Affine::read_from_stack_not_montgomery(witness);

        assert_eq!(b, recovered_b);
    }

    #[test]
    fn test_g2_affine_is_on_curve() {
        let affine_is_on_curve = G2Affine::is_on_curve();

        println!("G2.affine_is_on_curve: {} bytes", affine_is_on_curve.len());

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..3 {
            let point = ark_bn254::G2Affine::rand(&mut prng);

            let script = script! {
                { Fq2::push(point.x) }
                { Fq2::push(point.y) }
                { affine_is_on_curve.clone()}
            };
            println!("curves::test_affine_is_on_curve = {} bytes", script.len());
            run(script);

            let script = script! {
                { Fq2::push(point.x) }
                { Fq2::push(point.y) }
                { Fq2::double(0) }
                { affine_is_on_curve.clone()}
                OP_NOT
            };
            println!("curves::test_affine_is_on_curve = {} bytes", script.len());
            run(script);
        }
    }

    #[test]
    fn test_hinted_g2_affine_is_on_curve() {

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..3 {
            let point = ark_bn254::G2Affine::rand(&mut prng);
            let (scr, hints) = G2Affine::hinted_is_on_curve(point.x, point.y);
            let script = script! {
                for hint in hints { 
                    { hint.push() }
                }
                { Fq2::push_not_montgomery(point.x) }
                { Fq2::push_not_montgomery(point.y) }
                { scr}
            };
            println!("curves::test_affine_is_on_curve = {} bytes", script.len());
            let res = execute_script(script);
            assert!(res.success);

            let (scr, hints) = G2Affine::hinted_is_on_curve(point.x, point.y + point.y);
            let script = script! {
                for hint in hints { 
                    { hint.push() }
                }
                { Fq2::push_not_montgomery(point.x) }
                { Fq2::push_not_montgomery(point.y) }
                {Fq2::double(0)}
                { scr}
                OP_NOT
            };
            println!("curves::test_affine_is_on_curve = {} bytes", script.len());
            let res = execute_script(script);
            assert!(res.success);
        }
    }

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
                { Fq12::push(a) }
                { Fq2::push(c0) }
                { Fq2::push(c1) }
                { Fq2::push(c2) }
                { Fq::push_u32_le(&BigUint::from(px).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(py).to_u32_digits()) }
                ell
                { Fq12::push(b) }
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
                { Fq12::push(a) }
                { Fq::push_u32_le(&BigUint::from(px).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(py).to_u32_digits()) }
                { ell_by_constant_script.clone() }
                { Fq12::push(b) }
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
            { Fq12::push(f) }
            { from_eval_point(p) }
            { ell_by_constant_affine_script.clone() }
            { Fq12::push(hint) }
            { Fq12::equalverify() }
            OP_TRUE
        };
        run(script);
    }

    #[test]
    fn test_hinted_ell_by_constant_affine() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let b = ark_bn254::g2::G2Affine::rand(&mut prng);
        let p = ark_bn254::g1::G1Affine::rand(&mut prng);

        // affine mode
        let coeffs = G2Prepared::from_affine(b).ell_coeffs[0];
        let (ell_by_constant_affine_script, hints) = hinted_ell_by_constant_affine(
            p.x,
            p.y,
            coeffs.1,
            coeffs.2,
        );
        println!(
            "Pairing.ell_by_constant_affine: {} bytes",
            ell_by_constant_affine_script.len()
        );

        let script = script! {
            for tmp in hints {
                { tmp.push() }
            }
            // aux hints: Ellcoeffs: [slope, biasminus]
            { Fq2::push_not_montgomery(coeffs.1) } // slope
            { Fq2::push_not_montgomery(coeffs.2) } // biasminus

            // runtime input: P
            { Fq::push_not_montgomery(p.x) }
            { Fq::push_not_montgomery(p.y) }
            { ell_by_constant_affine_script }

            // validate output
            {Fq::push_not_montgomery(coeffs.2.c0 * p.y)}
            {Fq::push_not_montgomery(coeffs.2.c1 * p.y)}
            { Fq2::equalverify() }

            {Fq::push_not_montgomery(coeffs.1.c0 * p.x)}
            {Fq::push_not_montgomery(coeffs.1.c1 * p.x)}
            { Fq2::equalverify() }
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);        
    }

    #[test]
    fn test_hinted_ell_by_constant_affine_and_sparse_mul() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let f = ark_bn254::Fq12::rand(&mut prng);
        let b = ark_bn254::g2::G2Affine::rand(&mut prng);
        let p = ark_bn254::g1::G1Affine::rand(&mut prng);

        // affine mode
        let coeffs = G2Prepared::from_affine(b);
        let (from_eval_point_script, hints_eval) = hinted_from_eval_point(p);
        let (ell_by_constant_affine_script, hints) = hinted_ell_by_constant_affine_and_sparse_mul(
            f,
            -p.x / p.y,
            p.y.inverse().unwrap(),
            &coeffs.ell_coeffs[0],
        );
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
            { Fq12::push_not_montgomery(f) }

            { Fq::push_not_montgomery(p.y.inverse().unwrap()) }
            { Fq::push_not_montgomery(p.x) }
            { Fq::push_not_montgomery(p.y) }
            { from_eval_point_script }

            { ell_by_constant_affine_script.clone() }
            { Fq12::push_not_montgomery(hint) }
            { Fq12::equalverify() }
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
            { Fq2::push(t.x) }
            { Fq2::push(q.x) }
            { affine_add_line(alpha, bias_minus) }
            // [x']
            { Fq2::push(y) }
            // [x', y', y]
            { Fq2::equalverify() }
            // [x']
            { Fq2::push(x) }
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
            { Fq2::push_not_montgomery(alpha) }
            { Fq2::push_not_montgomery(bias_minus) }
            { Fq2::push_not_montgomery(t.x) }
            { Fq2::push_not_montgomery(q.x) }
            { hinted_add_line.clone() }
            // [c3(2),c4(2),add(4)]
            { Fq2::roll(6) }
            { Fq2::roll(6) }
            { Fq2::drop() }
            { Fq2::drop() }
            // [x']
            { Fq2::push_not_montgomery(y) }
            // [x', y', y]
            { Fq2::equalverify() }
            // [x']
            { Fq2::push_not_montgomery(x) }
            // [x', x]
            { Fq2::equalverify() }
            // []
            OP_TRUE
            // [OP_TRUE]
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
        println!(
            "hinted_add_line: {} @ {} stack",
            hinted_add_line.len(),
            exec_result.stats.max_nb_stack_items
        );
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
            { Fq2::push(t.x) }
            { affine_double_line(alpha, bias_minus) }
            // [x']
            { Fq2::push(y) }
            // [x', y', y]
            { Fq2::equalverify() }
            // [x']
            { Fq2::push(x) }
            // [x', x]
            { Fq2::equalverify() }
            // []
            OP_TRUE
            // [OP_TRUE]
        };
        run(script);
    }


    #[test]
    fn test_hinted_check_line_through_point() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t = ark_bn254::G2Affine::rand(&mut prng);
        let two_inv = ark_bn254::Fq::one().double().inverse().unwrap();
        let three_div_two = (ark_bn254::Fq::one().double() + ark_bn254::Fq::one()) * two_inv;
        let mut alpha = t.x.square();
        alpha /= t.y;
        alpha.mul_assign_by_fp(&three_div_two);
        // -bias
        let bias_minus = alpha * t.x - t.y;

        let (scr, hints) = hinted_check_line_through_point(t.x, alpha, bias_minus);
        println!("hinted_check_line_through_point: {}", scr.len());

        let script = script! {
            for hint in hints {
                { hint.push() }
            }
            { Fq2::push_not_montgomery(alpha) }
            { Fq2::push_not_montgomery(bias_minus) }
            
            { Fq2::push_not_montgomery(t.x) }
            { Fq2::push_not_montgomery(t.y) }
            {scr}
            { Fq2::drop() }
            { Fq2::drop() }
            OP_TRUE
        };
        assert!(execute_script(script).success);


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
        println!("hinted_affine_double_line: {}", hinted_double_line.len());

        let script = script! {
            for hint in hints {
                { hint.push() }
            }
            { Fq2::push_not_montgomery(alpha) }
            { Fq2::push_not_montgomery(bias_minus) }
            { Fq2::push_not_montgomery(t.x) }
            { hinted_double_line }
            // [c3(2),c4(2),add(4)]
            { Fq2::roll(6) }
            { Fq2::roll(6) }
            { Fq2::drop() }
            { Fq2::drop() }
            // [x']
            { Fq2::push_not_montgomery(y) }
            // [x', y', y]
            { Fq2::equalverify() }
            // [x']
            { Fq2::push_not_montgomery(x) }
            // [x', x]
            { Fq2::equalverify() }
            // []
            OP_TRUE
            // [OP_TRUE]
        };
        assert!(execute_script(script).success);
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
            { Fq2::push(t.x) }
            { Fq2::push(t.y) }
            { check_line_through_point(alpha, bias_minus) }
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);

        println!(
            "check_line: {} @ {} stack",
            check_line_through_point(alpha, bias_minus).len(),
            exec_result.stats.max_nb_stack_items
        );
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

        let (hinted_check_line, hints) = hinted_check_tangent_line(t, alpha, bias_minus);

        let script = script! {
            for hint in hints {
                { hint.push() }
            }
            { Fq2::push_not_montgomery(alpha) }
            { Fq2::push_not_montgomery(bias_minus) }
            { Fq2::push_not_montgomery(t.x) }
            { Fq2::push_not_montgomery(t.y) }
            { hinted_check_line.clone() }
            { Fq2::drop() }
            { Fq2::drop() }
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
        println!(
            "hinted_check_line: {} @ {} stack",
            hinted_check_line.len(),
            exec_result.stats.max_nb_stack_items
        );
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
            { Fq2::push(t.x) }
            { Fq2::push(t.y) }
            { check_line_through_point(alpha, bias_minus) }
            { Fq2::push(q.x) }
            { Fq2::push(q.y) }
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
            { Fq2::push_not_montgomery(alpha) }
            { Fq2::push_not_montgomery(bias_minus) }
            { Fq2::push_not_montgomery(t.x) }
            { Fq2::push_not_montgomery(t.y) }
            { Fq2::push_not_montgomery(q.x) }
            { Fq2::push_not_montgomery(q.y) }
            { hinted_check_line.clone() }
            { Fq2::drop() }
            { Fq2::drop() }
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
        println!(
            "hinted_check_line: {} @ {} stack",
            hinted_check_line.len(),
            exec_result.stats.max_nb_stack_items
        );
    }

    #[test]
    fn test_g2_subgroup_check() {

        let mut prng = ChaCha20Rng::seed_from_u64(0);
        
        #[allow(non_snake_case)]
        for _ in 0..1 {
            let P_POWER_ENDOMORPHISM_COEFF_0 = ark_bn254::Fq2::new(
                ark_bn254::Fq::from_str("21575463638280843010398324269430826099269044274347216827212613867836435027261").unwrap(),
                ark_bn254::Fq::from_str("10307601595873709700152284273816112264069230130616436755625194854815875713954").unwrap()
            );

            // PSI_Y = (u+9)^((p-1)/2) = TWIST_MUL_BY_Q_Y
            let P_POWER_ENDOMORPHISM_COEFF_1 = ark_bn254::Fq2::new(
                ark_bn254::Fq::from_str("2821565182194536844548159561693502659359617185244120367078079554186484126554").unwrap(),
                ark_bn254::Fq::from_str("3505843767911556378687030309984248845540243509899259641013678093033130930403").unwrap(),
            );

            let scalar_bit: Vec<bool> = ark_ff::BitIteratorBE::without_leading_zeros(&[17887900258952609094, 8020209761171036667]).collect();

            let p = ark_bn254::G2Affine::rand(&mut prng);

            let scripts = PairingSplitScript::g2_subgroup_check([P_POWER_ENDOMORPHISM_COEFF_0, P_POWER_ENDOMORPHISM_COEFF_1], scalar_bit.clone());

            println!(
                "curves::test_g2_subgroup_check script chunk num = {}",
                scripts.len()
            );

            // **************** prepare witness data ******************

            let (res, witness) = PairingNative::witness_g2_subgroup_check(&p, [P_POWER_ENDOMORPHISM_COEFF_0, P_POWER_ENDOMORPHISM_COEFF_1], scalar_bit.clone());

            assert!(res);

            println!(
                "curves::test_g2_subgroup_check witness data len = {}",
                witness.len()
            );

            //********** Check ech script chunk with witness data *************//

            // execute for each msm-script and witness
            for (i, (wit, scp)) in witness.iter().zip(scripts).enumerate() {
                let final_script = script! {
                    for input in wit.inputs.iter() {
                        { Fq::push_u32_le(&BigUint::from(input.c0).to_u32_digits()) }
                        { Fq::push_u32_le(&BigUint::from(input.c1).to_u32_digits()) }
                    }
                    { scp.clone() }
                    for output in wit.outputs.iter() {
                        { Fq::push_u32_le(&BigUint::from(output.c0).to_u32_digits()) }
                        { Fq::push_u32_le(&BigUint::from(output.c1).to_u32_digits()) }

                    }
                    { Fq::equalverify(4,0) }
                    { Fq::equalverify(3,0) }
                    { Fq::equalverify(2,0) }
                    { Fq::equalverify(1,0) }
                    OP_TRUE
                };
                let start = start_timer!(|| "execute_test_g2_subgroup_check_script");
                let exec_result = execute_script(final_script);
                assert!(exec_result.success);
                println!("subscript[{}] runs successfully!", i);
                end_timer!(start);
            }
        }
    }
}

