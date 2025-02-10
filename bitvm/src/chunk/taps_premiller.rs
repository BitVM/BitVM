use crate::bn254::{utils::*};
use crate::bn254::g1::{hinted_from_eval_points, G1Affine};
use crate::bn254::g2::G2Affine;
use crate::bn254::fq2::Fq2;
use crate::chunk::blake3compiled::hash_messages;
use crate::chunk::elements::ElementType;
use crate::chunk::primitives::*;
use crate::{
    bn254::{fp254impl::Fp254Impl, fq::Fq},
    treepp::*,
};
use ark_ec::AffineRepr;
use ark_ff::{AdditiveGroup, Field};



// verify
pub(crate) fn chunk_verify_g1_is_on_curve(
    hint_in_py: ark_ff::BigInt<4>,
    hint_in_px: ark_ff::BigInt<4>,
) -> (bool, Script, Vec<Hint>) {
    fn tap_verify_p_is_on_curve() -> Script {
        let (on_curve_scr, on_curve_hint) = G1Affine::hinted_is_on_curve(ark_bn254::Fq::ONE, ark_bn254::Fq::ONE);
    
        let scr = script! {
            {Fq2::fromaltstack()}
            // [hints, px, py] []
            {Fq::is_zero_keep_element(0)}
            OP_IF 
                {G1Affine::drop()}
                for i in 0..on_curve_hint.len() {
                    {Fq::drop()}
                }
                OP_TRUE
            OP_ELSE 
                // [hints, px, py]
                {on_curve_scr}
                OP_NOT
            OP_ENDIF
        };
        scr
    }
    let p =  ark_bn254::G1Affine::new_unchecked(hint_in_px.into(), hint_in_py.into());
    let (_, hints) = G1Affine::hinted_is_on_curve(p.x, p.y);

    let is_on_curve = p.is_on_curve() && p.y().is_some() && p.y != ark_bn254::Fq::ZERO;

    (is_on_curve, tap_verify_p_is_on_curve(), hints)
}

// verify
pub(crate) fn chunk_verify_g1_hash_is_on_curve(
    hint_in_p: ark_bn254::G1Affine,
) -> (bool, Script, Vec<Hint>) {
    fn tap_verify_p_is_on_curve() -> Script {
        let (on_curve_scr, on_curve_hint) = G1Affine::hinted_is_on_curve(ark_bn254::Fq::ONE, ark_bn254::Fq::ONE);
    
        let ops_scr = script! {
            // [hints, px, py] [phash]
            {Fq::fromaltstack()}
            {Fq2::copy(1)} {Fq2::toaltstack()}
            // [hints, px, py, phash] [py, px]
            for _ in 0..Fq::N_LIMBS as usize * on_curve_hint.len() {
                OP_DEPTH OP_1SUB OP_ROLL 
            }  
            // [px, py, phash, hints]
            for _ in 0..on_curve_hint.len() {
                {Fq::toaltstack()}
            }
            {Fq::toaltstack()}
            // [px, py] [py, px, hints, phash]
            {hash_fp2()} 
            {Fq::fromaltstack()}
            {Fq::equalverify(1, 0)}

            for _ in 0..on_curve_hint.len() {
                {Fq::fromaltstack()}
            }
            {Fq2::fromaltstack()}
            // [hints, px, py]

            // actual curve validation begins
            {Fq::is_zero_keep_element(0)}
            OP_IF 
                {G1Affine::drop()}
                for i in 0..on_curve_hint.len() {
                    {Fq::drop()}
                }
                OP_TRUE
            OP_ELSE 
                // [hints, px, py]
                {on_curve_scr}
                OP_NOT
            OP_ENDIF
        };
    
        script! {
            {ops_scr}
        }
    }


    // assert_eq!(sec_in.len(), 3);
    let p =  hint_in_p;
    let (_, hints) = G1Affine::hinted_is_on_curve(p.x, p.y);

    let is_on_curve = p.is_on_curve() && p.y().is_some() && p.y != ark_bn254::Fq::ZERO;

    (is_on_curve, tap_verify_p_is_on_curve(), hints)
}

// precompute P
pub(crate) fn chunk_precompute_p(
    hint_in_py: ark_ff::BigInt<4>,
    hint_in_px: ark_ff::BigInt<4>,
) -> (ark_bn254::G1Affine, Script, Vec<Hint>) {
    fn tap_precompute_p() -> Script {
        let (eval_xy, hints) = hinted_from_eval_points(
            ark_bn254::G1Affine::new_unchecked(ark_bn254::Fq::ONE, ark_bn254::Fq::ONE),
        );
        let (on_curve_scr, on_curve_hint) = G1Affine::hinted_is_on_curve(ark_bn254::Fq::ONE, ark_bn254::Fq::ONE);
    
        let ops_scr = script! {
            {Fq2::fromaltstack()}
            // [hints, px, py] [pdash_hash]
            {eval_xy} 
        };
    
        let hash_scr = script!(
            {hash_messages(vec![ElementType::G1])}
            OP_TRUE     
        );
        script! {
            {ops_scr}
            // [pdx, pdy]    
            // {hash_scr}
        }
    }
    let p =  ark_bn254::G1Affine::new_unchecked(hint_in_px.into(), hint_in_py.into());
    let pdy = p.y.inverse().unwrap();
    let pdx = -p.x * pdy;
    let pd = ark_bn254::G1Affine::new_unchecked(pdx, pdy);
    let (_, hints) =  hinted_from_eval_points(p);

    (pd, tap_precompute_p(), hints)
}

pub(crate) fn chunk_precompute_p_from_hash(
    hint_in_p: ark_bn254::G1Affine,
) -> (ark_bn254::G1Affine, Script, Vec<Hint>) {
    fn tap_precompute_p_from_hash() -> Script {
        let (eval_xy, hints) = hinted_from_eval_points(
            ark_bn254::G1Affine::new_unchecked(ark_bn254::Fq::ONE, ark_bn254::Fq::ONE),
        );
        let (on_curve_scr, on_curve_hint) = G1Affine::hinted_is_on_curve(ark_bn254::Fq::ONE, ark_bn254::Fq::ONE);
    
        let ops_scr = script! {
            // [hints, px, py] [pdash_hash, phash]
            {Fq2::copy(0)}
            // [hints, p, p]
            {eval_xy} 
            // [hints, p, pdash]
        };
    
        let hash_scr = script!(
            {hash_messages(vec![ElementType::G1, ElementType::G1])}
            OP_TRUE     
        );
        script! {
            {ops_scr}
            // [pdx, pdy]    
            // {hash_scr}
        }
    }
    let p =  hint_in_p;
    let pdy = p.y.inverse().unwrap();
    let pdx = -p.x * pdy;
    let pd = ark_bn254::G1Affine::new_unchecked(pdx, pdy);
    let (_, hints) =  hinted_from_eval_points(p);

    (pd, tap_precompute_p_from_hash(), hints)
}

// hash T4
pub(crate) fn chunk_verify_g2_on_curve(
    hint_q4y1: ark_ff::BigInt<4>,
    hint_q4y0: ark_ff::BigInt<4>,
    hint_q4x1: ark_ff::BigInt<4>,
    hint_q4x0: ark_ff::BigInt<4>,
) -> (bool, Script, Vec<Hint>) {

    fn tap_verify_g2_on_curve(on_curve_scr: Script) -> Script {
        let scr = script! {
            for _ in 0..4 {
                {Fq::fromaltstack()}
            }
            // [hints, x0,x1,y0,y1] []
            {on_curve_scr}
            OP_NOT            
        };
        scr
    }

    let t4 = ark_bn254::G2Affine::new_unchecked(ark_bn254::Fq2::new(hint_q4x0.into(), hint_q4x1.into()), ark_bn254::Fq2::new(hint_q4y0.into(), hint_q4y1.into()));
    let (on_curve_scr, hints) = G2Affine::hinted_is_on_curve(t4.x, t4.y);
    let is_valid = t4.is_on_curve();

    (is_valid, tap_verify_g2_on_curve(on_curve_scr), hints)
}