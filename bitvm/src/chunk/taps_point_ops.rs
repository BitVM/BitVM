use crate::bn254::g2::{hinted_affine_add_line_empty_elements, hinted_affine_double_line, hinted_affine_double_line_keep_elements, hinted_check_line_through_point, hinted_check_line_through_point_empty_elements, hinted_check_line_through_point_keep_elements, hinted_check_tangent_line_keep_elements, hinted_ell_by_constant_affine, hinted_mul_by_char_on_phi_q, hinted_mul_by_char_on_q, G2Affine};
use crate::bn254::{self, utils::*};
use crate::bn254::{fq2::Fq2};
use crate::chunk::blake3compiled::hash_messages;
use crate::{
    bn254::{fp254impl::Fp254Impl, fq::Fq},
    treepp::*,
};
use ark_ec::{AffineRepr, CurveGroup}; 
use ark_ff::{AdditiveGroup, Field};
use std::ops::Neg;

use super::element::*;

pub(crate) fn utils_point_double_eval(t: ark_bn254::G2Affine, p: ark_bn254::G1Affine) -> ((ark_bn254::G2Affine, (ark_bn254::Fq2, ark_bn254::Fq2)), Script, Vec<Hint>) {
    let mut hints = vec![];

    let t_is_zero = t.is_zero() || (t == ark_bn254::G2Affine::new_unchecked(ark_bn254::Fq2::ZERO, ark_bn254::Fq2::ZERO)); // t is none or Some(0)
    let (alpha, bias) = if t_is_zero {
        (ark_bn254::Fq2::ZERO, ark_bn254::Fq2::ZERO)
    } else {
        let alpha = (t.x.square() + t.x.square() + t.x.square()) / (t.y + t.y); 
        let bias = t.y - alpha * t.x;
        (alpha, bias)
    };

    let (hinted_script1, hint1) = hinted_check_tangent_line_keep_elements(t,alpha, -bias);
    let (hinted_script2, hint2) = hinted_affine_double_line_keep_elements(t.x,alpha, -bias);
    let (hinted_script3, hint3) = hinted_ell_by_constant_affine(p.x, p.y,alpha, -bias);

    let mut dbl_le0 = alpha;
    dbl_le0.mul_assign_by_fp(&p.x);
    let mut dbl_le1 = -bias;
    dbl_le1.mul_assign_by_fp(&p.y);
    
    let result = ((t + t).into_affine(), (dbl_le0, dbl_le1));
    if !t_is_zero { 
        hints.push(Hint::Fq(alpha.c0));
        hints.push(Hint::Fq(alpha.c1));
        hints.push(Hint::Fq(-bias.c0));
        hints.push(Hint::Fq(-bias.c1));
        hints.extend(hint1);
        hints.extend(hint2);
        hints.extend(hint3);
    }
 
    let script = script! {    
        // a, b, tx, ty, px, py
        { Fq2::toaltstack()}
        { G2Affine::is_zero_keep_element() }         // ... (dependent on input),  x, y, 0/1
        OP_NOTIF                                     // c3 (alpha), c4 (-bias), ... (other hints), x, y
            for _ in 0..Fq::N_LIMBS * 2 {
                OP_DEPTH OP_1SUB OP_ROLL 
            }                                        // -bias, ...,  x, y, alpha
            for _ in 0..Fq::N_LIMBS * 2 {
                OP_DEPTH OP_1SUB OP_ROLL 
            }                                        // x, y, alpha, -bias
            {Fq2::roll(6)} {Fq2::roll(6)}          // alpha, -bias, x, y
            { hinted_script1 }                       // x, y, alpha, -bias, is_tangent_line_correct 
            {Fq2::roll(6)} {Fq2::roll(6)}
            { Fq2::copy(2) } {Fq2::copy(2)}           // x, y alpha, -bias, alpha, -bias
            { Fq2::copy(10) }                          // x, y alpha, -bias, alpha, -bias, x
            { hinted_script2 }                       // x, y, alpha, -bias, x', y'
            {Fq2::fromaltstack()}                   // x, y, alpha, -bias, x', y', px, py
            {Fq2::roll(4)} {Fq2::roll(4)}           // x, y, alpha, -bias, px, py,  x', y'
            {Fq2::toaltstack()} {Fq2::toaltstack()}
            { hinted_script3 }                                     // x, y, le,
            {Fq2::fromaltstack()} {Fq2::fromaltstack()}  // x, y, le0, le1, x', y'
            {Fq2::roll(6)} {Fq2::roll(6)}                            // x, y, x', y', le

        OP_ENDIF
    };
    (result, script, hints)
}


pub(crate) fn utils_point_add_eval_ate(t: ark_bn254::G2Affine, q4: ark_bn254::G2Affine, p: ark_bn254::G1Affine, is_frob:bool, ate_bit: i8) -> ((ark_bn254::G2Affine, (ark_bn254::Fq2, ark_bn254::Fq2)), Script, Vec<Hint>) {
    let mut hints = vec![];

    let temp_q = q4.clone();
    let (qq, precomp_q_scr, precomp_q_hint) =
    if is_frob {
        if ate_bit == 1 {
            hinted_mul_by_char_on_q(temp_q)
        } else {
            hinted_mul_by_char_on_phi_q(temp_q)
        }
    } else {
        if ate_bit == -1 {
            (temp_q.neg(), script!(
                // [q4]
                {Fq::toaltstack()}
                {Fq::neg(0)}
                {Fq::fromaltstack()}
                {Fq::neg(0)}
                // [-q4]
            ), vec![])                
        } else {
            (temp_q, script!(), vec![])
        }
    };

    let t_is_zero = t.is_zero() || (t == ark_bn254::G2Affine::new_unchecked(ark_bn254::Fq2::ZERO, ark_bn254::Fq2::ZERO)); // t is none or Some(0)
    let q_is_zero = qq.is_zero() || (qq == ark_bn254::G2Affine::new_unchecked(ark_bn254::Fq2::ZERO, ark_bn254::Fq2::ZERO)); // q is none or Some(0)

    let (alpha, bias) = if !t_is_zero && !q_is_zero && t != -qq { // todo: add if t==q and if t == -q
        let alpha = (t.y - qq.y) / (t.x - qq.x);
        let bias = t.y - alpha * t.x;
        (alpha, bias)
    } else {
        (ark_bn254::Fq2::ZERO, ark_bn254::Fq2::ZERO)
    };

    let (hinted_script11, hint11) = hinted_check_line_through_point_keep_elements(t.x, alpha, -bias); // todo: remove unused arg: bias
    let (hinted_script12, hint12) = hinted_check_line_through_point_empty_elements(qq.x, alpha, -bias); // todo: remove unused arg: bias
    let (hinted_script2, hint2) = hinted_affine_add_line_empty_elements(t.x, qq.x, alpha, -bias);
    let (hinted_script3, hint3) = hinted_ell_by_constant_affine(p.x, p.y,alpha, -bias);

    let mut add_le0 = alpha;
    add_le0.mul_assign_by_fp(&p.x);
    let mut add_le1 = -bias;
    add_le1.mul_assign_by_fp(&p.y);

    let result = ((t + qq).into_affine(), (add_le0, add_le1));

    if !t.is_zero() && !qq.is_zero() && t != -qq {
        hints.extend(precomp_q_hint);
        hints.push(Hint::Fq(alpha.c0));
        hints.push(Hint::Fq(alpha.c1));
        hints.push(Hint::Fq(-bias.c0));
        hints.push(Hint::Fq(-bias.c1));
        hints.extend(hint11);
        hints.extend(hint12);
        hints.extend(hint2);
        hints.extend(hint3);
    }

    let script = script! {        // tx ty qx qy
        // a, b, tx, ty, qx, qy, px, py
        {Fq2::toaltstack()}
        // [qx qy]
        {precomp_q_scr}
        // [qx qy]
        { G2Affine::is_zero_keep_element() }
        OP_IF
            { G2Affine::drop() }
        OP_ELSE
            { G2Affine::roll(1) }
            { G2Affine::is_zero_keep_element() }
            OP_IF
                { G2Affine::drop() }
            OP_ELSE                                // qx qy tx ty
                {G2Affine::copy(1)}
                // qx qy tx ty qx qy
                { Fq2::neg(0)}
                // qx qy tx ty qx -qy
                {G2Affine::copy(1)}
                // qx qy tx ty qx -qy tx ty
                {G2Affine::equal()} 
                // qx qy tx ty 0/1
                OP_IF // qx == tx
                    {G2Affine::drop()}
                    {G2Affine::drop()}
                    {Fq2::push(ark_bn254::Fq2::ZERO)}
                    {Fq2::push(ark_bn254::Fq2::ZERO)}
                OP_ELSE
                    for _ in 0..Fq::N_LIMBS * 2 {
                        OP_DEPTH OP_1SUB OP_ROLL 
                    }
                    for _ in 0..Fq::N_LIMBS * 2 {
                        OP_DEPTH OP_1SUB OP_ROLL 
                    }                                  
                    {Fq2::roll(6)} {Fq2::roll(6)}
                    {hinted_script11}
                    {Fq2::roll(6)} {Fq2::roll(6)}
                    { Fq2::copy(2) } { Fq2::copy(2) }    // qx qy tx ty c3 c4, c3, c4
                    { Fq2::copy(14) }
                    { Fq2::roll(14) }                    // qx tx ty c3 c4 c3 c4 qx qy
                    { hinted_script12 }                 // qx tx ty c3 c4 0/1
                    {Fq2::copy(2)} {Fq2::copy(2)}     // qx tx ty c3 c4, c3 c4
                    { Fq2::copy(10) }                    // qx tx ty c3 c4, c3 c4, tx
                    { Fq2::roll(14) }                    // c3 c4 tx qx
                    { hinted_script2 }                 // tx, ty, c3, c4, x' y'
                    {Fq2::fromaltstack()}             // tx, ty, c3, c4, x' y', px, py
                    {Fq2::roll(4)} {Fq2::roll(4)}           // tx, ty, alpha, -bias, px, py,  x', y'
                    {Fq2::toaltstack()} {Fq2::toaltstack()}
                    { hinted_script3 }                         // tx, ty, le,
                    {Fq2::fromaltstack()} {Fq2::fromaltstack()}  // tx, ty, le0, le1, x', y'
                    {Fq2::roll(6)} {Fq2::roll(6)}                            // tx, ty, x', y', le
                OP_ENDIF
            OP_ENDIF
        OP_ENDIF
    };
    (result, script, hints)
}

#[cfg(test)]
mod test {
    use ark_ff::{Field, UniformRand};
    use bitcoin_script::script;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use crate::{bn254::{g1::G1Affine, g2::G2Affine, fp254impl::Fp254Impl, fq2::Fq2}, chunk::taps_point_ops::{utils_point_add_eval_ate}, execute_script, execute_script_without_stack_limit};

    use super::utils_point_double_eval;


    #[test]
    fn test_point_double_eval() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t = ark_bn254::G2Affine::rand(&mut prng);
        let p = ark_bn254::G1Affine::rand(&mut prng);
        
        let ((r, le), scr, hints) = utils_point_double_eval(t, p);

        // a, b, tx, ty, px, py

        let script = script!(
            for h in hints {
                {h.push()}
            }
            {G2Affine::push(t)}
            {G1Affine::push(p)}
            // [hints, tx, ty, px, py]
            {scr}
            // t, R, dbl_le
            {Fq2::push(le.1)}
            {Fq2::equalverify()}
            {Fq2::push(le.0)}
            {Fq2::equalverify()}

            {Fq2::push(r.y)}
            {Fq2::equalverify()}
            {Fq2::push(r.x)}
            {Fq2::equalverify()}


            {Fq2::push(t.y)}
            {Fq2::equalverify()}


            {Fq2::push(t.x)}
            {Fq2::equalverify()}

            
            OP_TRUE
        );
        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(res.success);
        assert!(res.final_stack.len() == 1);    
        println!("max_stack {:?}", res.stats.max_nb_stack_items);
    }


    #[test]
    fn test_point_add_eval_ate() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t = ark_bn254::G2Affine::rand(&mut prng);
        let q = ark_bn254::G2Affine::rand(&mut prng);
        let p = ark_bn254::G1Affine::rand(&mut prng);

        let ((r, le), hinted_check_add, hints) = utils_point_add_eval_ate(t, q, p, true, 1);

        let script = script! {
            for hint in hints {
                { hint.push() }
            }

            { Fq2::push(t.x) }
            { Fq2::push(t.y) }
            { Fq2::push(q.x) }
            { Fq2::push(q.y) }
            { G1Affine::push(p) }
            { hinted_check_add.clone() }
            // [x']


            {Fq2::push(le.1)}
            {Fq2::equalverify()}
            {Fq2::push(le.0)}
            {Fq2::equalverify()}

            {Fq2::push(r.y)}
            {Fq2::equalverify()}
            {Fq2::push(r.x)}
            {Fq2::equalverify()}
            
            
            {Fq2::push(t.y)}
            {Fq2::equalverify()}

            {Fq2::push(t.x)}
            {Fq2::equalverify()}
            // []
            OP_TRUE
            // [OP_TRUE]
        };
        let exec_result = execute_script_without_stack_limit(script);
        for i in 0..exec_result.final_stack.len() {
            println!("{i:} {:?}", exec_result.final_stack.get(i));
        }
        assert!(exec_result.success);
        assert!(exec_result.final_stack.len() == 1);
        println!(
            "point_add_eval: {} @ {} stack",
            hinted_check_add.len(),
            exec_result.stats.max_nb_stack_items
        );
    }

    
}