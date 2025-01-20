use crate::treepp::*;
use bitcoin::opcodes::all::*;
use super::u4_std::{u4_drop, CalculateOffset};

/// Pushes the table for calculating the quotient, i.e. floor(x / 16) for x < 65. i.e. 15 (max u4) * 4 (max # numbers to sum) + 4 (max carry)
pub fn u4_push_quotient_table() -> Script {
    script! {
        OP_4
        for i in (0..=3).rev() {
            { i }
            OP_DUP
            OP_2DUP
            OP_3DUP
            OP_3DUP
            OP_3DUP
            OP_3DUP
        }
    }
}

/// Pushes the table for calculating the quotient, i.e. floor(x / 16) for x < 80. i.e. 15 (max u4) * 5 (max # numbers to sum) + 4 (max carry)
pub fn u4_push_quotient_table_5() -> Script {
    script! {
        for i in (0..=4).rev() {
            { i }
            OP_DUP
            OP_2DUP
            OP_3DUP
            OP_3DUP
            OP_3DUP
            OP_3DUP
        }
    }
}

/// Drop quotient table
pub fn u4_drop_quotient_table() -> Script { u4_drop(65) }

/// Pushes the table for calculating the modulo, i.e. x % 16 for x < 65. i.e. 15 (max u4) * 4 (max # numbers to sum) + 4 (max carry)
pub fn u4_push_modulo_table() -> Script {
    script! {
        for i in (0..65).rev() {
            { i % 16 }
        }
    }
}

/// Pushes the table for calculating the modulo, i.e. x % 16 for x < 80. i.e. 15 (max u4) * 5 (max # numbers to sum) + 4 (max carry)
pub fn u4_push_modulo_table_5() -> Script {
    script! {
        for i in (0..80).rev() {
            { i % 16 }
        }
    }
}

/// Drops the modulo table
pub fn u4_drop_modulo_table() -> Script { u4_drop(65) }

/// Pushes both modulo and quotient tables for sums
pub fn u4_push_add_tables() -> Script {
    script! {
        { u4_push_modulo_table() }
        { u4_push_quotient_table() }
    }
}

/// Drops both modulo and quotient tables
pub fn u4_drop_add_tables() -> Script {
    script! {
        { u4_drop_quotient_table() }
        { u4_drop_modulo_table() }
    }
}

/// Arranges (zips) the given numbers (locations given by the parameters bases) each consisting of nibble_count u4's so each group of nibbles can be proccessed disceretly 
/// Does not preserve order as it's used with commutative operations
/// Assuming x_i denoting the i-th part of the x-th number and bases have two numbers a and b (a < b): 
/// Input:  ... (a elements) a_0 a_1 a_2 a_3 ... (b - a - 1 elements) b_0 b_1 b_2 b_3
/// Output: b_0 a_0 b_1 a_1 b_2 a_2 b_3 a_3 ... (b elements and the rest of stack)
pub fn u4_arrange_nibbles(nibble_count: u32, mut bases: Vec<u32>) -> Script {
    bases.sort();
    bases.reverse();
    for base_i in &mut bases {
        *base_i += nibble_count - 1;
    }
    script! {
        for i in 0..nibble_count {
            for (n, base) in bases.iter().enumerate() {
                {  (base - i)  +  ((n as u32 + 1) * (i + 1)) - 1 }
                OP_ROLL
            }
        }
    }
}

/// Calculates the modulo 16 of the u4 at the top of the stack also with the quotient, parameters being internal values
pub fn u4_add_carry_nested(current: u32, limit: u32) -> Script {
    script! {
        OP_DUP
        OP_16
        OP_GREATERTHANOREQUAL
        OP_IF
            OP_16
            OP_SUB
            if current + 1 == limit {
                { current }
            } else {
                { u4_add_carry_nested(current+1, limit)}
            }
        OP_ELSE
            { current }
        OP_ENDIF
    }
}

/// Calculates the modulo 16 of the u4 at the top of the stack, parameters being internal values
pub fn u4_add_nested(current: u32, limit: u32) -> Script {
    script! {
        OP_DUP
        OP_16
        OP_GREATERTHANOREQUAL
        OP_IF
            OP_16
            OP_SUB
            if current + 1 < limit {
                { u4_add_nested(current + 1, limit)}
            }
        OP_ENDIF
    }
}

/// Addition of zipped numbers consisting of nibble_count u4's, without the table
pub fn u4_add_no_table_internal(nibble_count: u32, number_count: u32) -> Script {
    script! {
        for i in 0..nibble_count {
            for _ in 0..number_count-1 {
                OP_ADD
            }
            if i < nibble_count - 1 {
                { u4_add_carry_nested(0, number_count) }
                OP_SWAP
                OP_TOALTSTACK
                OP_ADD
            } else {
                { u4_add_nested(0, number_count) }
                OP_TOALTSTACK
            }

        }
    }
}

/// Addition of zipped numbers consisting of nibble_count u4's
/// Requires the addition table and tables_offset to locate the table which should be equal to number of elements on top of the table including operating values
pub fn u4_add_internal(nibble_count: u32, number_count: u32, tables_offset: u32) -> Script {
    assert!(number_count < 5);
    let quotient_table_size = 65;
    //extra size on the stack
    let mut offset_calc: i32 = 0;
    script! {
        for i in 0..nibble_count {
            //extra add to add the carry from previous addition
            if i > 0 {
                { offset_calc.modify(OP_ADD) }
            }

            //add the column of nibbles (needs one less add than nibble count)
            for _ in 0..number_count-1 {
                { offset_calc.modify(OP_ADD) }
            }

            // duplicate the result to be used to get the carry except for the last nibble
            if i < nibble_count -1 {
                { offset_calc.modify( OP_DUP) }
            }

            //get the modulo of the addition
            {  (offset_calc - 1)  + tables_offset as i32 + quotient_table_size }   // this adds 1 to the calc
            OP_ADD                                                    // and this one consumes it
            { offset_calc.modify(OP_PICK) }
            { offset_calc.modify(OP_TOALTSTACK) }

            //we don't care about the last carry
            if i < nibble_count - 1 {
                //obtain the quotinent to be used as carry for the next addition
                { (offset_calc - 1) + tables_offset as i32 }
                OP_ADD
                { offset_calc.modify(OP_PICK) }
            }
        }
    }
}

/// Addition of numbers consisting of nibble_count u4's in the parameter bases locations
/// Requires the addition table and tables_offset to locate the table which should be equal to number of elements on top of the table including operating values
pub fn u4_add_with_table(nibble_count: u32, bases: Vec<u32>, tables_offset: u32) -> Script {
    let numbers = bases.len() as u32;
    script! {
        { u4_arrange_nibbles(nibble_count, bases)  }
        { u4_add_internal(nibble_count, numbers, tables_offset) }
    }
}

/// Addition of numbers consisting of nibble_count u4's in the parameter bases locations, without the table
pub fn u4_add_no_table(nibble_count: u32, bases: Vec<u32>) -> Script {
    let numbers = bases.len() as u32;
    script! {
        { u4_arrange_nibbles(nibble_count, bases)  }
        { u4_add_no_table_internal(nibble_count, numbers) }
    }
}

/// Addition of numbers consisting of nibble_count u4's in the parameter bases locations
/// The overflowing bit (if exists) is omitted
pub fn u4_add(nibble_count: u32, bases: Vec<u32>, tables_offset: u32, use_add_table: bool) -> Script {
    if use_add_table {
        u4_add_with_table(nibble_count, bases, tables_offset)
    } else {
        u4_add_no_table(nibble_count, bases)
    }
}

#[cfg(test)]
mod tests {
    use crate::treepp::*;
    use crate::u4::{u4_add::*, u4_std::u4_number_to_nibble};
    use rand::Rng;

    #[test]
    fn test_calc() {
        let x = u4_arrange_nibbles(8, vec![0, 1, 2, 4]);
        println!("{}", x.len());
        //let x = u4_add_with_table(8, vec![0, 8, 16, 24, 32], 100);
        //println!("{}", x.len());
        let x = u4_add_with_table(8, vec![0, 8, 16, 24], 100);
        println!("{}", x.len());
        let x = u4_add_no_table(8, vec![0, 8, 16, 24, 32]);
        println!("{}", x.len());
        let x = u4_add_no_table(8, vec![0, 8, 16, 24]);
        println!("{}", x.len());
        let x = u4_add_no_table(8, vec![0, 8, 16]);
        println!("{}", x.len());
        let x = u4_add_no_table(8, vec![0, 8]);
        println!("{}", x.len());
    }


    #[test]
    fn test_add_no_table() {
        let calc = script! {
            { u4_add_no_table(8, vec![0, 8, 16, 24]) }
        };
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            for len in 2..5 {
                let vars: Vec<u32> = (0..len).map(|_| { rng.gen()}).collect(); 
                let result = vars.iter().fold(0 as u64, |sum, &x| sum + x as u64) % ((1 as u64) << 32); 
                let script = script! {
                    for x in vars {
                        { u4_number_to_nibble(x) }
                    }
                    { u4_add_no_table(8,  (0..).step_by(8).take(len.try_into().unwrap()).collect()) }
                    { u4_number_to_nibble(result.try_into().unwrap()) }
                    for _ in 0..8 {
                        OP_FROMALTSTACK
                    }
                    for i in 0..8 {
                        { 8 - i }
                        OP_ROLL
                        OP_EQUALVERIFY
                    }
                    OP_TRUE
                };
                run(script);
            }
        }
        println!("{}", calc.len());
    }

    #[test]
    fn test_add_with_table() {
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            for len in 2..5 {
                let vars: Vec<u32> = (0..len).map(|_| { rng.gen()}).collect(); 
                let result = vars.iter().fold(0 as u64, |sum, &x| sum + x as u64) % ((1 as u64) << 32); 
                let script = script! {
                    { u4_push_add_tables() }
                    for x in vars {
                        { u4_number_to_nibble(x) }
                    }
                    { u4_add_with_table(8,  (0..).step_by(8).take(len.try_into().unwrap()).collect(), len * 8) }
                    { u4_drop_add_tables() }
                    { u4_number_to_nibble(result.try_into().unwrap()) }
                    for _ in 0..8 {
                        OP_FROMALTSTACK
                    }
                    for i in 0..8 {
                        { 8 - i }
                        OP_ROLL
                        OP_EQUALVERIFY
                    }
                    OP_TRUE
                };
                run(script);
            }
        }
    }

    #[test]
    fn test_quotient() {
        for i in 0..65 {
            let script = script! {
                { u4_push_quotient_table() }
                { i as u32 }
                OP_PICK
                { i / 16 }
                OP_EQUALVERIFY
                { u4_drop_quotient_table() }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_modulo() {
        for i in 0..65 {
            let script = script! {
                { u4_push_modulo_table() }
                { i as u32 }
                OP_PICK
                { i % 16 }
                OP_EQUALVERIFY
                { u4_drop_modulo_table() }
                OP_TRUE
            };
            run(script);
        }
    }
}
