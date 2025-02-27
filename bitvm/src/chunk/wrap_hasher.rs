use crate::{bn254::{fp254impl::Fp254Impl, fq::Fq}, hash::blake3_u4_compact::blake3_u4_compact, treepp::*};
use bitcoin_script_stack::stack::StackTracker;
use hash_utils::{hash_fp2, hash_fp6, hash_g2acc, hash_g2acc_with_hash_t, hash_g2acc_with_hashed_le};

use super::{elements::ElementType};

pub const BLAKE3_HASH_LENGTH: usize = 20;

/// truncate 32 byte output hash to {BLAKE3_HASH_LENGTH} hash output and pad with zeros
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

    /// Compute hash of top two field elements on stack: [a00, a01]
    /// Output is {BLAKE3_HASH_LENGTH} byte output represented in limb-form
    pub(crate) fn hash_fp2() -> Script {
        script! {
            // [a00, a01]
            { hash_n_bytes::<64>() }
            // Hash(a00|a01)
            { pack_nibbles_to_limbs() }
        }
    }

    /// Compute hash of top four field elements on stack: [a00, a01, a10, a11]
    /// Output is {BLAKE3_HASH_LENGTH} byte output represented in limb-form
    pub(crate) fn hash_fp4() -> Script {
        script! {
            // [a00, a01, a10, a11]
            {Fq2::roll(2)}
            // [a10, a11, a00, a01] 
            // Requires first msg-block at the top of stack
            { hash_n_bytes::<128>() }
            // Hash(a00|a01|a10|a11)
            { pack_nibbles_to_limbs() }
        }
    }

    /// Compute hash of top six field elements on stack: [a00, a01, a10, a11, a20, a21]
    /// Output is {BLAKE3_HASH_LENGTH} byte output represented in limb-form
    pub(crate) fn hash_fp6() -> Script {
        script! {
            // [a00, a01, a10, a11, a20, a21]
            {Fq2::roll(2)} {Fq2::roll(4)}
            // [a20, a21, a10, a11, a00, a01]
            // Requires first msg-block at the top of stack
            {hash_n_bytes::<192>()}
            // Hash(a00|a01|a10|a11|a20|a21)
            {pack_nibbles_to_limbs()}
        }
    }
    
    /// Compute hash of top six field elements on stack: [a00, a01,.., a60, a61]
    /// Output is {BLAKE3_HASH_LENGTH} byte output represented in limb-form
    pub(crate) fn hash_fp14() -> Script {
        script! {
            // [a00, a01,... ,a60, a61]
            {Fq2::roll(2)} {Fq2::roll(4)} {Fq2::roll(6)} 
            {Fq2::roll(8)} {Fq2::roll(10)} {Fq2::roll(12)}
            // [a60, a61,... ,a00, a01]
            {hash_n_bytes::<448>()}
            // Hash(a00|a01|..|a60|a61)
            {pack_nibbles_to_limbs()}
        }
    }
    
    /// Compute hash of G2 Point Accumulator (i.e. [t(4), partial_product(14)]) where Hash(partial_product) has been passed as auxiliary input on stack.
    /// Stack: [t(4), Hash_partial_product(1)]
    pub(crate) fn hash_g2acc_with_hashed_le() -> Script {
        script! {
            // [t, Hash_partial_product]
            {Fq::toaltstack()} 
            {hash_fp4()}
            {Fq::fromaltstack()}
            // [Hash_t, Hash_partial_product]
            {hash_fp2()}
            // [ Hash(Hash_t|Hash_partial_product) ]
            // [ Hash(G2Acc) ]
        }
    }
    
    /// Compute hash of G2 Point Accumulator (i.e. [t(4), partial_product(14)]) where all elements are passed as raw value on stack
    /// Stack: [t(4), partial_product(14)]
    pub(crate) fn hash_g2acc() -> Script {
        script!{
            // [t, partial_product]
            for _ in 0..14 {
                {Fq::toaltstack()}
            }
            // [t] [partial_product]
            {hash_fp4()}
            // [Hash_t] [partial_product]
            for _ in 0..14 {
                {Fq::fromaltstack()}
            }
            // [Hash_t partial_product]
            {Fq::roll(14)} {Fq::toaltstack()}
            // [partial_product] [Hash_t]
            {hash_fp14()}
            // [Hash_partial_product] [Hash_t]
            {Fq::fromaltstack()}
            {Fq::roll(1)}
            // [ Hash_t, Hash_partial_product ]
            {hash_fp2()}
            // [ Hash(Hash_t|Hash_partial_priduct) ]
            // [ Hash(G2Acc) ]
        }
    }
    
    /// Compute hash of G2 Point Accumulator (i.e. [t(4), partial_product(14)]) where Hash(t) has been passed as auxiliary input on stack.
    /// Stack: [Hash_partial_priduct(14), Hash_t(1)]
    pub(crate) fn hash_g2acc_with_hash_t() -> Script {
        script!{
            // [partial_product, Hash_t]
            {Fq::toaltstack()}
            {hash_fp14()}
            {Fq::fromaltstack()}
            {Fq::roll(1)}
            // [ Hash_t, Hash_partial_product ]
            {hash_fp2()}
            // [ Hash(Hash_t|Hash_partial_priduct) ]
            // [ Hash(G2Acc) ]
        }
    }
}

/// This function is used to add hashing layer to the disprove script.
/// The additional logic here is due to a constraint in blake3_u4 
/// which requires the entire stack to only hold the message to be hashed.
/// Given an array of Elements of different ElementType, the function assumes the order [Input_A_Preimage, Input_B_Preimage, Output_Preimage, should_do_output_validity_check_bit] for main stack
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
        let mut remaining = elem_types[msg_index+1..].to_vec(); // "remaining" refers to elements other than the msg to hash
        let mut from_altstack = script! {};  // script to bring "remaining" elements back from altstack
        for elem_type in &remaining {
            from_altstack = script! {
                {from_altstack}
                // bring "size" number of elements from altstack; where "size" is the number of limbs of elem_type
                for _ in 0..elem_type.number_of_limbs_of_hashing_preimage() {
                    {Fq::fromaltstack()}
                }
            };
        }
        remaining.reverse();
        let mut to_altstack = script! {}; // script to send "remaining" elements to altstack
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
                {hash_g2acc_with_hashed_le()}
            } else if elem_type == ElementType::G2EvalMul {
                {hash_g2acc_with_hash_t()}
            } else if elem_type == ElementType::G2Eval {
                {hash_g2acc()}
            }
        };

        let verify_scr = script! {
            // bottom of the stack contains the calculated hash, bring it to the top
            for _ in 0..Fq::N_LIMBS { 
                OP_DEPTH OP_1SUB OP_ROLL 
            }
            // top of altstack contains the claimed hash for corresponding message
            {Fq::fromaltstack()}
            // compare hashes
            {Fq::equal(1, 0)}
            if msg_index == elem_types.len()-1 { // if last message
                // [should_do_output_validity_check_bit, output_is_equal] []
                OP_TOALTSTACK // [should_do_output_validity_check_bit] [output_is_equal]
                OP_IF
                    // input was valid, so disprove if output hashes (claimed vs calculated) don't match
                    OP_FROMALTSTACK
                    OP_NOT  
                OP_ELSE     
                    // should_do_output_validity_check_bit = 0 means the tapscript reached a disprove condition not dependent upon value of output 
                    // i.e. input/intermediate value was invalid
                    OP_FROMALTSTACK
                    OP_DROP // indifferent to equality check, therefore drop "output_is_equal" 
                    {1}     // successfully disprove
                OP_ENDIF
            }
            OP_VERIFY
        };
        loop_script = script! {
            {loop_script}
            // send output_validity bit to altstack
            OP_TOALTSTACK
            // send "remaining" elements to altstack
            {to_altstack}
            // hash the message
            {hash_scr}
            // bring "remaining" elements from altstack
            {from_altstack}
            // bring output_validity bit from altstack
            OP_FROMALTSTACK
            // verify that the calculated hash is equal to claimed hash
            {verify_scr}
        };
    }
    loop_script
}