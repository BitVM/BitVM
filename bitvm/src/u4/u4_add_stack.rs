use crate::treepp::*;
use bitcoin_script_stack::stack::{StackTracker, StackVariable};

use super::u4_add::{u4_push_modulo_table_5, u4_push_quotient_table_5};

/// Puts the table of the inner function to stack library
pub fn u4_push_quotient_table_stack(stack: &mut StackTracker) -> StackVariable {
    stack.var(80, u4_push_quotient_table_5(), "quotient_table")
}

/// Puts the table of the inner function to stack library
pub fn u4_push_modulo_table_stack(stack: &mut StackTracker) -> StackVariable {
    stack.var(80, u4_push_modulo_table_5(), "modulo_table")
}

/// Pushes the table for calculating the modulo, i.e. x % 16 for x < 48. i.e. 15 (max u4) * 3 (max # numbers to sum) + 2 (max carry)
pub fn u4_push_modulo_for_blake(stack: &mut StackTracker) -> StackVariable {
    stack.custom(
        script! {
            for i in (0..48).rev() {
                { i % 16 }
            }
        },
        0,
        false,
        0,
        "",
    );
    stack.define(48, "modulo")
}

/// Pushes the table for calculating the quotient, i.e. floor(x / 16) for x < 48. i.e. 15 (max u4) * 3 (max # numbers to sum) + 2 (max carry)
pub fn u4_push_quotient_for_blake(stack: &mut StackTracker) -> StackVariable {
    stack.custom(
        script! {
            for i in (0..=2).rev() {
                { i }
                OP_DUP
                OP_2DUP
                OP_3DUP
                OP_3DUP
                OP_3DUP
                OP_3DUP
            }
        },
        0,
        false,
        0,
        "",
    );
    stack.define(48, "quotient")
}

/// Arranges (zips) the given numbers (locations given by the parameters bases) each consisting of nibble_count u4's so each group of nibbles can be proccessed disceretly
/// Does not preserve order as it's used with commutative operations
/// Assuming x_i denoting the i-th part of the x-th number and bases have two numbers a and b (a < b):
/// Input:  ... (a elements) a_0 a_1 a_2 a_3 ... (b - a - 1 elements) b_0 b_1 b_2 b_3
/// Output: b_0 a_0 b_1 a_1 b_2 a_2 b_3 a_3 ... (b elements and the rest of stack)
pub fn u4_arrange_nibbles_stack(
    nibble_count: u32,
    stack: &mut StackTracker,
    to_copy: Vec<StackVariable>,
    mut to_move: Vec<&mut StackVariable>,
    constants: Vec<u32>,
) {
    let mut constant_parts: Vec<Vec<u32>> = Vec::new();

    for n in constants {
        let parts = (0..8).rev().map(|i| (n >> (i * 4)) & 0xF).collect();
        constant_parts.push(parts);
    }

    for i in 0..nibble_count {
        for var in to_copy.iter() {
            stack.copy_var_sub_n(*var, i);
        }

        for var in to_move.iter_mut() {
            stack.move_var_sub_n(var, 0);
        }

        for parts in constant_parts.iter() {
            stack.number(parts[i as usize]);
        }
    }
}

/// Addition of numbers consisting of nibble_count u4's in the parameter bases locations
/// The overflowing bit (if exists) is omitted
pub fn u4_add_internal_stack(
    stack: &mut StackTracker,
    nibble_count: u32,
    number_count: u32,
    quotient_table: StackVariable,
    modulo_table: StackVariable,
) {
    for i in 0..nibble_count {
        //extra add to add the carry from previous addition
        if i > 0 {
            stack.op_add();
        }

        //add the column of nibbles (needs one less add than nibble count)
        for _ in 0..number_count - 1 {
            stack.op_add();
        }

        // duplicate the result to be used to get the carry except for the last nibble
        if i < nibble_count - 1 {
            stack.op_dup();
        }

        //get the modulo of the addition
        stack.get_value_from_table(modulo_table, None);
        stack.to_altstack();

        //we don't care about the last carry
        if i < nibble_count - 1 {
            //obtain the quotinent to be used as carry for the next addition
            stack.get_value_from_table(quotient_table, None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::u4::u4_std::verify_n;

    #[test]
    fn test_arrange_stack() {
        let mut stack = StackTracker::new();

        let mut x = stack.number_u32(0x00112233);
        let y = stack.number_u32(0x99887766);
        u4_arrange_nibbles_stack(8, &mut stack, vec![y], vec![&mut x], vec![0xaabbccdd]);

        //0x998 877 66
        //0x001 12 233
        //0xaa bbc cdd

        stack.number_u32(0x90a90a81);
        stack.number_u32(0xb81b72c7);
        stack.number_u32(0x2c63d63d);

        stack.custom(verify_n(24), 24 + 3, false, 0, "verify");
        stack.drop(y);
        stack.op_true();

        let res = stack.run();
        assert!(res.success);
    }

    #[test]
    fn test_add_internal_stack() {
        let mut stack = StackTracker::new();

        let modulo = u4_push_modulo_table_stack(&mut stack);
        let quotient = u4_push_quotient_table_stack(&mut stack);

        let mut x = stack.number_u32(0x00112233);
        let y = stack.number_u32(0x99887766);
        u4_arrange_nibbles_stack(8, &mut stack, vec![y], vec![&mut x], vec![0xaabbccdd]);

        u4_add_internal_stack(&mut stack, 8, 3, quotient, modulo);

        let mut vars = stack.from_altstack_count(8);
        stack.join_count(&mut vars[0], 7);

        stack.number_u32(0x44556676);
        stack.custom(verify_n(8), 2, false, 0, "verify");
        stack.drop(y);
        stack.drop(quotient);
        stack.drop(modulo);
        stack.op_true();

        let res = stack.run();
        assert!(res.success);
    }

    #[test]
    fn test_add_for_blake() {
        let mut stack = StackTracker::new();

        let modulo = u4_push_modulo_for_blake(&mut stack);
        let quotient = u4_push_quotient_for_blake(&mut stack);

        let mut x = stack.number_u32(0x00112233);
        let y = stack.number_u32(0x99887766);
        u4_arrange_nibbles_stack(8, &mut stack, vec![y], vec![&mut x], vec![0xaabbccdd]);

        u4_add_internal_stack(&mut stack, 8, 3, quotient, modulo);

        let mut vars = stack.from_altstack_count(8);
        stack.join_count(&mut vars[0], 7);

        stack.number_u32(0x44556676);
        stack.custom(verify_n(8), 2, false, 0, "verify");
        stack.drop(y);
        stack.drop(quotient);
        stack.drop(modulo);
        stack.op_true();

        let res = stack.run();
        assert!(res.success);
    }

    #[test]
    fn test_quotient_for_blake_table() {
        for i in 0..48 {
            let mut stack = StackTracker::new();
            let quotient = u4_push_quotient_for_blake(&mut stack);
            stack.number(i);
            stack.op_pick();
            stack.number(i / 16);
            stack.op_equal();
            stack.op_verify();
            stack.drop(quotient);
            stack.op_true();
            let res = stack.run();
            assert!(res.success);
        }
    }
    #[test]
    fn test_modulo_for_blake_table() {
        for i in 0..48 {
            let mut stack = StackTracker::new();
            let modulo = u4_push_modulo_for_blake(&mut stack);
            stack.number(i);
            stack.op_pick();
            stack.number(i % 16);
            stack.op_equal();
            stack.op_verify();
            stack.drop(modulo);
            stack.op_true();
            let res = stack.run();
            assert!(res.success);
        }
    }
}
