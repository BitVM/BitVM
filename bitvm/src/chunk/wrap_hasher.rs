use crate::{bn254::{fp254impl::Fp254Impl, fq::Fq}, hash::blake3_u4_compact::blake3_u4_compact, treepp::*};
use bitcoin_script_stack::stack::StackTracker;
use hash_utils::{hash_fp2, hash_fp6, new_hash_g2acc, new_hash_g2acc_with_hash_t, new_hash_g2acc_with_hashed_le};

use super::{elements::ElementType};

pub const BLAKE3_HASH_LENGTH: usize = 20;

fn wrap_scr(scr: Script) -> Script {
    script! {
        { scr }
        for _ in 0..(32*2-BLAKE3_HASH_LENGTH*2)/2 { OP_2DROP }
        for _ in 0..BLAKE3_HASH_LENGTH*2 { OP_TOALTSTACK }
        for _ in 0..(32*2-BLAKE3_HASH_LENGTH*2) { 0 }
        for _ in 0..BLAKE3_HASH_LENGTH*2 { OP_FROMALTSTACK  }
    }
}

// create Script instance from stack-tracker and pad output with zeros to appropriate hash size
pub(crate) fn hash_n_bytes<const N: u32>() -> Script {
    let mut stack = StackTracker::new();
    blake3_u4_compact(&mut stack, N, true, true);
    wrap_scr(stack.get_script())
}

// helpers to directly hash data structures that we work with
// example: extension field elements, point accumulators
pub(crate) mod hash_utils {
    use bitcoin_script::script;
    use crate::{bn254::{fp254impl::Fp254Impl, fq::Fq, fq2::Fq2}, chunk::{helpers::{pack_nibbles_to_limbs}, wrap_hasher::hash_n_bytes}, treepp::Script};

    pub(crate) fn hash_fp2() -> Script {
        script! {
            { hash_n_bytes::<64>() }
            { pack_nibbles_to_limbs() }
        }
    }

    pub(crate) fn hash_fp4() -> Script {
        script! {
            // [a0b0, a0b1, a1b0, a1b1]
            {Fq2::roll(2)}
            { hash_n_bytes::<128>() }
            { pack_nibbles_to_limbs() }
        }
    }
    
    pub(crate) fn new_hash_g2acc_with_hashed_le() -> Script {
        script! {
            //Stack: [tx, ty, hash_inaux]
            //T
            {Fq::toaltstack()} 
            {hash_fp4()} // HT
    
            {Fq::fromaltstack()}
            {hash_fp2()}
        }
    }
    
    pub(crate) fn new_hash_g2acc() -> Script {
        script!{
            // [t, le]
            for _ in 0..14 {
                {Fq::toaltstack()}
            }
            {hash_fp4()}
            for _ in 0..14 {
                {Fq::fromaltstack()}
            }
            {Fq::roll(14)} {Fq::toaltstack()}
            {hash_fp14()}
            {Fq::fromaltstack()}
            {Fq::roll(1)}
            {hash_fp2()}
        }
    }
    
    pub(crate) fn new_hash_g2acc_with_hash_t() -> Script {
        script!{
            // [le, ht]
            {Fq::toaltstack()}
            {hash_fp14()}
            {Fq::fromaltstack()}
            {Fq::roll(1)}
            {hash_fp2()}
        }
    }
    
    
    pub(crate) fn hash_fp6() -> Script {
        script! {
            {Fq2::roll(2)} {Fq2::roll(4)}
            {hash_n_bytes::<192>()}
            {pack_nibbles_to_limbs()}
    
        }
    }
    
    
    pub(crate) fn hash_fp14() -> Script {
        script! {
            {Fq2::roll(2)} {Fq2::roll(4)} {Fq2::roll(6)} 
            {Fq2::roll(8)} {Fq2::roll(10)} {Fq2::roll(12)}
            {hash_n_bytes::<448>()}
            {pack_nibbles_to_limbs()}
    
        }
    }
}

/// This function is used to add hashing layer to the disprove script.
/// The additional logic here is due to a constraint in blake3_u4 
/// which requires the entire stack to only hold the message to be hashed.
/// Given an array of Elements of different ElementType, the function assumes the order [Input_A_Preimage, Input_B_Preimage, Output_Preimage] for main stack
/// and [Output_Hash, Input_B_Hash, Input_A_Hash] for altstack
// should_do_output_validity_check_bit: we have a bit at the top of stack that determines whether the final equality check between calculated and claimed output
// should be done. This is used in the context where tapscript is disproven based on input invalidity indifferent to output.
// i.e. if the claimed input is invalid, user can disprove indifferent to output computation
pub fn hash_messages(elem_types: Vec<ElementType>) -> Script {
    // Altstack: [Hc, Hb, Ha]
    // Stack: [a, b, c, should_do_output_validity_check_bit]
    let elem_types: Vec<ElementType> = elem_types.into_iter().filter(|et| et.number_of_limbs_of_hashing_preimage() > 0).collect();
    let mut loop_script = script! {};

    for msg_index in 0..elem_types.len() {
        // send other elems to altstack
        let mut remaining = elem_types[msg_index+1..].to_vec();
        let mut from_altstack = script! {};
        for elem_type in &remaining {
            from_altstack = script! {
                {from_altstack}
                for _ in 0..elem_type.number_of_limbs_of_hashing_preimage() {
                    {Fq::fromaltstack()}
                }
            };
        }
        remaining.reverse();
        let mut to_altstack = script! {};
        for elem_type in &remaining {
            to_altstack = script! {
                {to_altstack}
                for _ in 0..elem_type.number_of_limbs_of_hashing_preimage() {
                    {Fq::toaltstack()}
                }
            };
        }

        // hash remaining element
        let elem_type = elem_types[msg_index];
        let hash_scr = script! {
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
        };

        let verify_scr = script! {
            for _ in 0..Fq::N_LIMBS { 
                OP_DEPTH OP_1SUB OP_ROLL 
            }
            {Fq::fromaltstack()}
            {Fq::equal(1, 0)}
            if msg_index == elem_types.len()-1 {
                // [should_do_output_validity_check_bit, output_is_equal]
                OP_TOALTSTACK // [should_do_output_validity_check_bit] [output_is_equal]
                OP_IF
                    OP_FROMALTSTACK
                    OP_NOT  // disprove if claimed output and hashed output are not equal
                OP_ELSE     
                    // should_do_output_validity_check_bit = 0 means the tapscript reached a disprove condition not dependent upon value of output 
                    // i.e. input/intermediate value was invalid
                    OP_FROMALTSTACK
                    OP_DROP // indifferent to equality check
                    {1}     // successfully disprove
                OP_ENDIF
            }
            OP_VERIFY
        };
        loop_script = script! {
            {loop_script}
            OP_TOALTSTACK
            {to_altstack}
            {hash_scr}
            {from_altstack}
            OP_FROMALTSTACK
            {verify_scr}
        };
    }
    loop_script
}