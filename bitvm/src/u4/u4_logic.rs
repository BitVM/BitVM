use crate::treepp::{script, Script};

use crate::u4::u4_add::u4_arrange_nibbles;

use super::u4_std::u4_drop;

/*
    Full tables for bitwise operations consist of 16x16 elements and to calculate, functions OP_PICK 16 * A + B
    Half tables for bitwise operations consist of 16*17/2=136 elements to save space and to calculate, they operate with a triangular shape and ordering the input values
*/


/// Pushes the bitwise XOR table
pub fn u4_push_full_xor_table() -> Script {
    script! {
        for i in (0..16).rev() {
            for j in (0..16).rev() {
                {i ^ j}
            }
        }
    }
}

/// Drops full logic table
pub fn u4_drop_full_logic_table() -> Script { u4_drop(16 * 16) }

/// Pushes table for the value x * 16 
pub fn u4_push_full_lookup() -> Script {
    script! {
        for i in (0..=256).rev().step_by(16) {
            { i }
        }
    }
}

/// Drops the table for x * 16
pub fn u4_drop_full_lookup() -> Script { u4_drop(17) }

/// Pushes the half bitwise XOR table
pub fn u4_push_half_xor_table() -> Script {
    script! {
        for i in (0..16).rev() {
            for j in (i..16).rev() {
                {i ^ j}
            }
        }
    }
}

/// Pushes the half bitwise AND table
pub fn u4_push_half_and_table() -> Script {
    script! {
        OP_15
        OP_14
        OP_DUP
        OP_13
        OP_12
        OP_2DUP
        OP_DUP
        OP_2DUP
        OP_11
        OP_10
        OP_9
        OP_8
        OP_11
        OP_10
        OP_DUP
        OP_8
        OP_DUP
        OP_10
        OP_DUP
        OP_9
        OP_8
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_DUP
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_7
        OP_6
        OP_5
        OP_4
        OP_3
        OP_2
        OP_1
        OP_0
        OP_7
        OP_6
        OP_DUP
        OP_4
        OP_DUP
        OP_2
        OP_DUP
        OP_0
        OP_DUP
        OP_6
        OP_DUP
        OP_5
        OP_4
        OP_2DUP
        OP_1
        OP_0
        OP_2DUP
        OP_5
        OP_4
        OP_2DUP
        OP_DUP
        OP_2DUP
        OP_0
        OP_DUP
        OP_2DUP
        OP_4
        OP_DUP
        OP_2DUP
        OP_3
        OP_2
        OP_1
        OP_0
        OP_2OVER
        OP_2OVER
        OP_2OVER
        OP_2OVER
        OP_3
        OP_2
        OP_DUP
        OP_0
        OP_DUP
        OP_2
        OP_DUP
        OP_0
        OP_DUP
        OP_2
        OP_DUP
        OP_0
        OP_DUP
        OP_2
        OP_DUP
        OP_1
        OP_0
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_DUP
        OP_2DUP
        OP_3DUP
        OP_3DUP
        OP_3DUP
        OP_3DUP
    }
}

/// Drops half logic table
pub fn u4_drop_half_table() -> Script { u4_drop(136) }

/// Pushes the table to calculate the order of ordered pairs (a, b) satisfying the conditions a <= b and 0 <= a, b < 16
pub fn u4_push_half_lookup() -> Script {
    script! {
        136
        135
        133
        130
        126
        121
        115
        108
        100
        91
        81
        70
        58
        45
        31
        16
    }
}

/// Drops the table that calculates the order of ordered pairs (a, b) satisfying the condition a <= b
pub fn u4_drop_half_lookup() -> Script { u4_drop(16) }

/// Sorts the top 2 stack values
pub fn u4_sort() -> Script {
    script! {
        OP_2DUP
        OP_MIN
        OP_TOALTSTACK
        OP_MAX
        OP_FROMALTSTACK
    }
}

/// Calculates the logic operation with the given half table, lookup parameter denoting how many elements are there after the table including the two u4 elements
pub fn u4_half_table_operation(lookup: u32) -> Script {
    script! {
        { u4_sort() }
        { lookup - 1 }
        OP_ADD
        OP_PICK
        { lookup - 2 }
        OP_ADD
        OP_ADD
        OP_PICK
    }
}

/// Calculates the logic operation with the given full table, lookup parameter denoting how many elements are there after the table including the two u4 elements
pub fn u4_full_table_operation(lookup: u32, table: u32) -> Script {
    script! {
        { lookup }
        OP_ADD
        OP_PICK
        { table }
        OP_ADD
        OP_ADD
        OP_PICK
    }
}

/// Calculates the bitwise XOR of top 2 u4 values using half AND table, lookup parameter denoting how many elements are there after the table including the two u4 elements
/// Uses the formula a XOR b = (a + b) - 2 * (a AND b)
pub fn u4_xor_with_half_and_table(lookup: u32) -> Script {
    script! {
        OP_2DUP
        { u4_half_table_operation(lookup + 2) }
        OP_DUP
        OP_ADD
        OP_SUB
        OP_ADD
    }
}

/// Does bitwise operation with bases.len() elements at the top of the stack, both consisting of nibble_count u4's and at the positions of the bases vector (note that existing operations are commutative)
/// Expects a half logic operation table and offset parameter to locate it, which should be equal to the number of elements after the table including the inputs
/// Keeps the result at the altstack
pub fn u4_logic_nibs(nibble_count: u32, mut bases: Vec<u32>, offset: u32, do_xor_with_half_and_table: bool) -> Script {
    let numbers = bases.len() as u32;
    bases.sort();
    script! {
        { u4_arrange_nibbles(nibble_count, bases) }
        for nib in 0..nibble_count {
            for i in 0..numbers-1 {
                if do_xor_with_half_and_table {
                    { u4_xor_with_half_and_table( offset - i - nib * numbers ) }
                } else {
                    { u4_half_table_operation( offset - i - nib * numbers ) }
                }
            }
            OP_TOALTSTACK
        }
    }
}

/// Calculates the u32 xor of two elements with half and table, given their positions with the bases parameter
pub fn u4_xor_u32(bases: Vec<u32>, offset: u32, do_xor_with_and: bool) -> Script {
    u4_logic_nibs(8, bases, offset, do_xor_with_and)
}

#[cfg(test)]
mod tests {
    use rand::Rng;
    use crate::run;
    use crate::u4::u4_logic::*;
    use crate::u4::u4_shift::{u4_drop_rshift_tables, u4_push_rshift_tables};
    use crate::u4::u4_std::{u4_number_to_nibble, u4_u32_verify_from_altstack};
    
    #[test]
    fn test_xor_u32() {
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            let len: u32 = rng.gen_range(2..10);
            let vars: Vec<u32> = (0..len).map(|_| { rng.gen()}).collect();
            let script = script! {
                { u4_push_half_xor_table() }
                { u4_push_half_lookup()}
                for x in vars.clone() {
                    { u4_number_to_nibble(x) }
                }
                { u4_logic_nibs(8, (0..).step_by(8).take(len.try_into().unwrap()).collect(), 8 * len, false) }
                { u4_drop_half_lookup() }
                { u4_drop_half_table() }
                { u4_number_to_nibble(vars.iter().fold(0, |sum, &x| sum ^ x)) }
                { u4_u32_verify_from_altstack() }
                OP_TRUE
            };
            run(script);
        }
    }
    #[test]
    fn test_xor_u32_with_and() {
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            let len: u32 = rng.gen_range(2..10);
            let vars: Vec<u32> = (0..len).map(|_| { rng.gen()}).collect();
            let script = script! {
                { u4_push_half_and_table() }
                { u4_push_half_lookup()}
                for x in vars.clone() {
                    { u4_number_to_nibble(x) }
                }
                { u4_logic_nibs(8, (0..).step_by(8).take(len.try_into().unwrap()).collect(), 8 * len, true) }
                { u4_drop_half_lookup() }
                { u4_drop_half_table() }
                { u4_number_to_nibble(vars.iter().fold(0, |sum, &x| sum ^ x)) }
                { u4_u32_verify_from_altstack() }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_logic_u32_size() {
        let xor_x2 = u4_logic_nibs(8, vec![0, 8], 24, true);
        println!("{}", xor_x2.len());
        let xor_x3 = u4_logic_nibs(8, vec![0, 8, 16], 24, true);
        println!("{}", xor_x3.len());
        let xor_x2 = u4_logic_nibs(8, vec![0, 8], 24, false);
        println!("{}", xor_x2.len());
        let xor_x3 = u4_logic_nibs(8, vec![0, 8, 16], 24, false);
        println!("{}", xor_x3.len());
    }

    #[test]
    fn test_and_u32() {
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            let len: u32 = rng.gen_range(2..10);
            let vars: Vec<u32> = (0..len).map(|_| { rng.gen()}).collect();
            let script = script! {
                { u4_push_half_and_table() }
                { u4_push_half_lookup()}
                for x in vars.clone() {
                    { u4_number_to_nibble(x) }
                }
                { u4_logic_nibs(8, (0..).step_by(8).take(len.try_into().unwrap()).collect(), 8 * len, false) }
                { u4_drop_half_lookup() }
                { u4_drop_half_table() }
                { u4_number_to_nibble(vars.iter().fold(u32::MAX, |sum, &x| sum & x)) }
                { u4_u32_verify_from_altstack() }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_xor_half() {
        for x in 0..16 {
            for y in 0..16 {
                let script = script! {
                    { u4_push_half_and_table() }
                    { u4_push_half_lookup()}
                    {x}    
                    {y}      
                    { u4_xor_with_half_and_table(2)}
                    { x ^ y}
                    OP_EQUALVERIFY
                    { u4_drop_half_lookup() }
                    { u4_drop_half_table() }
                    OP_TRUE
                };
                run(script);
            }
        }
    }
    #[test]
    fn test_and_half() {
        for x in 0..16 {
            for y in 0..16 {
                let script = script! {
                    { u4_push_half_and_table() }
                    { u4_push_half_lookup()}
                    {x}      
                    {y}
                    { u4_half_table_operation(2)}
                    { x & y}
                    OP_EQUALVERIFY
                    { u4_drop_half_lookup() }
                    { u4_drop_half_table() }
                    OP_TRUE
                };
                run(script);
            }
        }
    }

    #[test]
    fn test_xor_func() {
        for a in 0..16 {
            for b in 0..16 {
                let script = script! {
                    { u4_push_full_xor_table() }
                    { u4_push_full_lookup()}
                    { a }
                    { b }
                    { u4_full_table_operation(1, 17)}
                    { a ^ b }
                    OP_EQUALVERIFY
                    { u4_drop_full_lookup() }
                    { u4_drop_full_logic_table() }
                    OP_TRUE
                };
                run(script);
            }
        }
    }

    #[test]
    fn test_lookup() {
        for i in 0..16 {
            let script = script! {
                { u4_push_full_lookup() }
                { i }
                OP_PICK
                { 16 * i }
                OP_EQUALVERIFY
                { u4_drop_full_lookup() }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_xor() {
        for a in 0..16 {
            for b in 0..16 {
                let script = script! {
                    { u4_push_full_xor_table() }
                    { u4_push_full_lookup()}
                    { u4_push_rshift_tables() } //shift table is not used and added just as an example test
                    { a }
                    { b }
                    { 1 + 1 + 32 }       // offset (X + rshift size is the offset)
                    OP_ADD
                    OP_PICK
                    { 1 + 32 }      // size of rshift
                    OP_ADD
                    OP_ADD
                    OP_PICK
                    { a ^ b }
                    OP_EQUALVERIFY
                    { u4_drop_rshift_tables() }
                    { u4_drop_full_lookup() }
                    { u4_drop_full_logic_table() }
                    OP_TRUE
                };
                run(script);
            }
        }
    }
}
