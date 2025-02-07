use crate::{bn254::{fp254impl::Fp254Impl, fq::Fq}, hash::blake3_u4_compact::blake3_u4_compact, treepp::*};
use bitcoin_script_stack::stack::StackTracker;

use super::{element::ElementType, primitives::{ hash_fp2, hash_fp6, new_hash_g2acc, new_hash_g2acc_with_hash_t, new_hash_g2acc_with_hashed_le}};


fn wrap_scr(scr: Script) -> Script {
    script! {
        { scr }
        for _ in 0..(64-40)/2 { OP_2DROP }
        for _ in 0..40 { OP_TOALTSTACK }
        for _ in 0..(64-40) { 0 }
        for _ in 0..40 { OP_FROMALTSTACK  }
    }
}

pub fn hash_64b() -> Script {
    let mut stack = StackTracker::new();
    blake3_u4_compact(&mut stack, 64, true, true);
    wrap_scr(stack.get_script())
}

pub fn hash_128b() -> Script {
    let mut stack = StackTracker::new();
    blake3_u4_compact(&mut stack, 128, true, true);
    wrap_scr(stack.get_script())
}

pub fn hash_192b() -> Script {
    let mut stack = StackTracker::new();
    blake3_u4_compact(&mut stack, 192, true, true);
    wrap_scr(stack.get_script())
}

pub fn hash_448b() -> Script {
    let mut stack = StackTracker::new();
    blake3_u4_compact(&mut stack, 448, true, true);
    wrap_scr(stack.get_script())
}

pub fn hash_messages(elem_types: Vec<ElementType>) -> Script {
    // Altstack: [Hc, Hb, Ha]
    // Stack: [a, b, c]
    let elem_types: Vec<ElementType> = elem_types.into_iter().filter(|et| et.num_limbs() > 0).collect();
    let mut loop_script = script!();
    for msg_index in 0..elem_types.len() {
        // send other elems to altstack
        let mut remaining = elem_types[msg_index+1..].to_vec();
        let mut from_altstack = script!();
        for elem_type in &remaining {
            from_altstack = script!(
                {from_altstack}
                for _ in 0..elem_type.num_limbs() {
                    {Fq::fromaltstack()}
                }
            );
        }
        remaining.reverse();
        let mut to_altstack = script!();
        for elem_type in &remaining {
            to_altstack = script!(
                {to_altstack}
                for _ in 0..elem_type.num_limbs() {
                    {Fq::toaltstack()}
                }
            );
        }

        // hash remaining element
        let elem_type = elem_types[msg_index];
        let hash_scr = script!(
            if elem_type == ElementType::Fp6 {
                {hash_fp6()}
            } else if elem_type == ElementType::G1 {
                {hash_fp2()}
            } else if elem_type == ElementType::G2EvalPoint {
                {new_hash_g2acc_with_hashed_le()}
            } else if elem_type == ElementType::G2EvalMul {
                {new_hash_g2acc_with_hash_t()}
            } else if elem_type == ElementType::G2Eval {
                {new_hash_g2acc()}
            }
        );

        let verify_scr = script!(
            for _ in 0..Fq::N_LIMBS { 
                OP_DEPTH OP_1SUB OP_ROLL 
            }
            {Fq::fromaltstack()}
            {Fq::equal(1, 0)}
            if msg_index == elem_types.len()-1 {
                OP_NOT
            }
            OP_VERIFY
        );
        loop_script = script!(
            {loop_script}
            {to_altstack}
            {hash_scr}
            {from_altstack}
            {verify_scr}
        );
    }
    loop_script
}

#[cfg(test)]
mod test {

    use ark_ff::Field;

    use crate::{bn254::{fp254impl::Fp254Impl, fq::Fq, fq2::Fq2, fq6::Fq6}, chunk::primitives::{extern_hash_fps, extern_nibbles_to_limbs, hash_fp14, pack_nibbles_to_limbs}};

    use super::*;

    #[test]
    fn test_sth() {
        let hash_scr = hash_messages(vec![ElementType::Fp6, ElementType::Fp6]);
        let a = ark_bn254::Fq6::ONE;
        let b = ark_bn254::Fq6::ONE + ark_bn254::Fq6::ONE;
        let ahash = extern_hash_fps(a.to_base_prime_field_elements().collect());
        let bhash = extern_hash_fps(b.to_base_prime_field_elements().collect());
        let tap_len = hash_scr.len();
        let script = script!(
            for i in extern_nibbles_to_limbs(bhash) {
                {i}
            }
            {Fq::toaltstack()}
            for i in extern_nibbles_to_limbs(ahash) {
                {i}
            }
            {Fq::toaltstack()}
            {Fq6::push(a)}
            {Fq6::push(b)}
            {hash_scr}
            OP_TRUE
        );
        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        // assert!(!res.success && res.final_stack.len() == 1);
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }

    #[test]
    fn test_sth2() {
        let a = vec![ark_bn254::Fq::ONE; 14].to_vec();
        let ahash = extern_hash_fps(a.clone());
        let tap_len = hash_448b().len();
        let script = script!(
            for v in a {
                {Fq::push(v)}
            }
            {hash_fp14()}
            for v in ahash {
                {v}
            }
            {pack_nibbles_to_limbs()}
            {Fq::equalverify(1, 0)}
            OP_TRUE
        );
        let res = execute_script(script);
        assert!(res.success && res.final_stack.len() == 1);
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }
}