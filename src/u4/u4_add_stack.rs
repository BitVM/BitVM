use crate::treepp::script;
use bitcoin_script_stack::stack::{StackTracker, StackVariable};

use super::u4_add::{u4_add_no_table_internal, u4_push_modulo_table_5, u4_push_quotient_table_5};

pub fn u4_push_quotient_table_stack(stack: &mut StackTracker) -> StackVariable {
    stack.var(80, u4_push_quotient_table_5(), "quotient_table")
}

pub fn u4_push_modulo_table_stack(stack: &mut StackTracker) -> StackVariable {
    stack.var(80, u4_push_modulo_table_5(), "modulo_table")
}

pub fn u4_push_modulo_for_blake(stack: &mut StackTracker) -> StackVariable {
    stack.custom(
        script! {
            OP_14
            OP_13
            OP_12
            OP_11
            OP_10
            OP_9
            OP_8
            OP_7
            OP_6
            OP_5
            OP_4
            OP_3
            OP_2
            OP_1
            OP_0
            OP_15
            OP_14
            OP_13
            OP_12
            OP_11
            OP_10
            OP_9
            OP_8
            OP_7
            OP_6
            OP_5
            OP_4
            OP_3
            OP_2
            OP_1
            OP_0
            OP_15
            OP_14
            OP_13
            OP_12
            OP_11
            OP_10
            OP_9
            OP_8
            OP_7
            OP_6
            OP_5
            OP_4
            OP_3
            OP_2
            OP_1
            OP_0
        },
        0,
        false,
        0,
        "",
    );
    stack.define(47, "modulo")
}

pub fn u4_push_quotient_for_blake(stack: &mut StackTracker) -> StackVariable {
    stack.custom(
        script! {
            OP_2
            OP_DUP
            OP_2DUP
            OP_2DUP
            OP_3DUP
            OP_3DUP
            OP_3DUP
            OP_1
            OP_DUP
            OP_2DUP
            OP_3DUP
            OP_3DUP
            OP_3DUP
            OP_3DUP
            OP_0
            OP_DUP
            OP_2DUP
            OP_3DUP
            OP_3DUP
            OP_3DUP
            OP_3DUP
        },
        0,
        false,
        0,
        "",
    );
    stack.define(47, "quotient")
}

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

pub fn u4_add_no_table_stack(stack: &mut StackTracker, nibble_count: u32, number_count: u32) {
    stack.custom(
        u4_add_no_table_internal(nibble_count, number_count),
        nibble_count * number_count,
        false,
        nibble_count,
        "add_no_table",
    );
}

pub fn u4_add_stack(
    stack: &mut StackTracker,
    nibble_count: u32,
    to_copy: Vec<StackVariable>,
    to_move: Vec<&mut StackVariable>,
    constants: Vec<u32>,
    quotient_table: StackVariable,
    modulo_table: StackVariable,
) {
    let number_count = to_copy.len() + to_move.len() + constants.len();
    let number_count = number_count as u32;
    u4_arrange_nibbles_stack(nibble_count, stack, to_copy, to_move, constants);
    if !modulo_table.is_null() && !quotient_table.is_null() {
        u4_add_internal_stack(
            stack,
            nibble_count,
            number_count,
            quotient_table,
            modulo_table,
        );
    } else {
        u4_add_no_table_stack(stack, nibble_count, number_count);
    }
}

#[cfg(test)]
mod tests {

    use crate::u4::{u4_add_stack::*, u4_std::verify_n};

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
    fn test_add_no_table_stack() {
        let mut stack = StackTracker::new();

        let mut x = stack.number_u32(0x00112233);
        let y = stack.number_u32(0x99887766);
        u4_arrange_nibbles_stack(8, &mut stack, vec![y], vec![&mut x], vec![0xaabbccdd]);

        u4_add_no_table_stack(&mut stack, 8, 3);

        let mut vars = stack.from_altstack_count(8);
        stack.join_count(&mut vars[0], 7);

        stack.number_u32(0x44556676);
        stack.custom(verify_n(8), 2, false, 0, "verify");
        stack.drop(y);
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
}
