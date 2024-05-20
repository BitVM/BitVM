use crate::treepp::{pushable, script, Script};
use bitcoin_script_stack::stack::{StackTracker, StackVariable};

use crate::u4::u4_logic::u4_sort;

use super::{
    u4_add_stack::u4_arrange_nibbles_stack,
    u4_logic::{u4_push_half_and_table, u4_push_half_xor_table, u4_push_lookup, u4_push_xor_table},
};

pub fn u4_push_and_table_stack(stack: &mut StackTracker) -> StackVariable {
    stack.var(136, u4_push_half_and_table(), "and_table")
}

pub fn u4_push_xor_table_stack(stack: &mut StackTracker) -> StackVariable {
    stack.var(136, u4_push_half_xor_table(), "xor_table")
}

pub fn u4_push_xor_full_table_stack(stack: &mut StackTracker) -> StackVariable {
    stack.var(256, u4_push_xor_table(), "xor_full_table")
}

pub fn u4_push_half_lookup_0_based() -> Script {
    script! {
        120
        119
        117
        114
        110
        105
        99
        92
        84
        75
        65
        54
        42
        29
        15
        0
    }
}

pub fn u4_push_lookup_table_stack(stack: &mut StackTracker) -> StackVariable {
    stack.var(16, u4_push_half_lookup_0_based(), "lookup_table")
}

pub fn u4_push_full_lookup_table_stack(stack: &mut StackTracker) -> StackVariable {
    stack.var(17, u4_push_lookup(), "full_lookup_table")
}

pub fn u4_logic_with_table_stack(
    stack: &mut StackTracker,
    lookup_table: StackVariable,
    logic_table: StackVariable,
    use_full_table: bool,
) -> StackVariable {
    if !use_full_table {
        stack.custom(u4_sort(), 0, false, 0, "sort");
    }
    stack.get_value_from_table(lookup_table, None);
    stack.op_add();
    stack.get_value_from_table(logic_table, None)
}

//(a xor b) = (a + b) - 2*(a & b)) = b - 2(a&b) + a
pub fn u4_xor_with_and_stack(
    stack: &mut StackTracker,
    lookup_table: StackVariable,
    logic_table: StackVariable,
) -> StackVariable {
    stack.op_2dup();
    u4_logic_with_table_stack(stack, lookup_table, logic_table, false);
    stack.op_dup();
    stack.op_add();
    stack.op_sub();
    stack.op_add()
}

pub fn u4_logic_stack_nib(
    stack: &mut StackTracker,
    lookup_table: StackVariable,
    logic_table: StackVariable,
    do_xor_with_and: bool,
) -> StackVariable {
    if do_xor_with_and {
        u4_xor_with_and_stack(stack, lookup_table, logic_table)
    } else {
        u4_logic_with_table_stack(stack, lookup_table, logic_table, logic_table.size() > 136)
    }
}

pub fn u4_logic_stack(
    stack: &mut StackTracker,
    nibble_count: u32,
    numbers: Vec<StackVariable>,
    lookup_table: StackVariable,
    logic_table: StackVariable,
    do_xor_with_and: bool,
) {
    let numnber_count = numbers.len();
    u4_arrange_nibbles_stack(nibble_count, stack, numbers, vec![], vec![]);

    for _ in 0..nibble_count {
        for _ in 0..numnber_count - 1 {
            if do_xor_with_and {
                u4_xor_with_and_stack(stack, lookup_table, logic_table);
            } else {
                u4_logic_with_table_stack(stack, lookup_table, logic_table, false);
            }
            stack.to_altstack();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin_script_stack::stack::StackTracker;

    #[test]
    fn test_xor() {
        for x in 0..16 {
            for y in 0..16 {
                let mut stack = StackTracker::new();
                let xor = u4_push_xor_full_table_stack(&mut stack);
                let lookup = u4_push_full_lookup_table_stack(&mut stack);

                stack.number(x);
                stack.number(y);

                u4_logic_with_table_stack(&mut stack, lookup, xor, true);

                stack.number(x ^ y);

                stack.op_equalverify();

                stack.drop(lookup);
                stack.drop(xor);

                stack.op_true();

                assert!(stack.run().success);
            }
        }
    }

    #[test]
    fn test_xor_half() {
        for x in 0..16 {
            for y in 0..16 {
                let mut stack = StackTracker::new();
                let xor = u4_push_xor_table_stack(&mut stack);
                let lookup = u4_push_lookup_table_stack(&mut stack);

                stack.number(x);
                stack.number(y);

                u4_logic_with_table_stack(&mut stack, lookup, xor, false);

                stack.number(x ^ y);

                stack.op_equalverify();

                stack.drop(lookup);
                stack.drop(xor);

                stack.op_true();

                assert!(stack.run().success);
            }
        }
    }

    #[test]
    fn test_xor_with_and_half() {
        for x in 0..16 {
            for y in 0..16 {
                let mut stack = StackTracker::new();
                let and = u4_push_and_table_stack(&mut stack);
                let lookup = u4_push_lookup_table_stack(&mut stack);

                stack.number(x);
                stack.number(y);

                u4_xor_with_and_stack(&mut stack, lookup, and);

                stack.number(x ^ y);

                stack.op_equalverify();

                stack.drop(lookup);
                stack.drop(and);

                stack.op_true();

                assert!(stack.run().success);
            }
        }
    }

    #[test]
    fn test_and_half() {
        for x in 0..16 {
            for y in 0..16 {
                let mut stack = StackTracker::new();
                let and = u4_push_and_table_stack(&mut stack);
                let lookup = u4_push_lookup_table_stack(&mut stack);

                stack.number(x);
                stack.number(y);

                u4_logic_with_table_stack(&mut stack, lookup, and, false);

                stack.number(x & y);

                stack.op_equalverify();

                stack.drop(lookup);
                stack.drop(and);

                stack.op_true();

                assert!(stack.run().success);
            }
        }
    }
}
