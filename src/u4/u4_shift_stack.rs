use super::u4_shift::{u4_push_lshift_tables, u4_push_rshift_tables};
use crate::treepp::{pushable, script};
use bitcoin_script_stack::stack::{StackTracker, StackVariable};

pub fn u4_push_shift_tables_stack(stack: &mut StackTracker) -> StackVariable {
    stack.var(
        16 * 6,
        script! { {u4_push_lshift_tables()} {u4_push_rshift_tables()}},
        "shift_tables",
    )
}

pub fn u4_rshift_stack(stack: &mut StackTracker, tables: StackVariable, n: u32) -> StackVariable {
    assert!(n > 0 && n <= 3);
    stack.get_value_from_table(tables, Some(16 * (n - 1)))
}

pub fn u4_lshift_stack(stack: &mut StackTracker, tables: StackVariable, n: u32) -> StackVariable {
    assert!(n > 0 && n <= 3);
    stack.get_value_from_table(tables, Some((16 * 3) + 16 * (n - 1)))
}

pub fn u4_push_shift_for_blake(stack: &mut StackTracker) -> StackVariable {
    stack.custom(
        script! {
            OP_14
            OP_12
            OP_10
            OP_8
            OP_6
            OP_4
            OP_2
            OP_0
            OP_14
            OP_12
            OP_10
            OP_8
            OP_6
            OP_4
            OP_2
            OP_0

            OP_1
            OP_DUP
            OP_2DUP
            OP_2DUP
            OP_2DUP
            OP_0
            OP_DUP
            OP_2DUP
            OP_2DUP
            OP_2DUP
        },
        0,
        false,
        0,
        "",
    );
    stack.define(32, "lshift1-rshift3")
}

// Assumes Y and X are on the stack and will produce YX >> n
// It calculates the offset doing (Y << (4-n)) & 15 + (X >> n) & 15
pub fn u4_2_nib_shift_stack(
    stack: &mut StackTracker,
    tables: StackVariable,
    n: u32,
) -> StackVariable {
    assert!(n > 0 && n <= 3);
    u4_lshift_stack(stack, tables, 4 - n);
    stack.op_swap();
    u4_rshift_stack(stack, tables, n);
    stack.op_add()
}

pub fn u4_2_nib_shift_blake(stack: &mut StackTracker, tables: StackVariable) -> StackVariable {
    stack.get_value_from_table(tables, None);
    stack.op_swap();
    stack.get_value_from_table(tables, Some(16));
    stack.op_add()
}

#[cfg(test)]
mod tests {

    use super::*;
    use bitcoin_script_stack::stack::StackTracker;

    #[test]
    fn test_lshift() {
        for n in 1..4 {
            for x in 0..16 {
                let mut stack = StackTracker::new();
                let tables = u4_push_shift_tables_stack(&mut stack);
                stack.number(x);
                u4_lshift_stack(&mut stack, tables, n);
                stack.number((x << n) % 16);
                stack.op_equalverify();
                stack.drop(tables);
                stack.op_true();
                assert!(stack.run().success);
            }
        }
    }

    #[test]
    fn test_rshift_func() {
        for n in 1..4 {
            for x in 0..16 {
                let mut stack = StackTracker::new();
                let tables = u4_push_shift_tables_stack(&mut stack);
                stack.number(x);
                u4_rshift_stack(&mut stack, tables, n);
                stack.number((x >> n) % 16);
                stack.op_equalverify();
                stack.drop(tables);
                stack.op_true();
                assert!(stack.run().success);
            }
        }
    }

    #[test]
    fn test_2_nib_rshift_function() {
        for n in 1..4 {
            for y in 0..16 {
                for x in 0..16 {
                    let mut stack = StackTracker::new();
                    let tables = u4_push_shift_tables_stack(&mut stack);
                    stack.number(x);
                    stack.number(y);
                    u4_2_nib_shift_stack(&mut stack, tables, n);
                    stack.number((((y << 4) + x) >> n) % 16);
                    stack.op_equalverify();
                    stack.drop(tables);
                    stack.op_true();
                    assert!(stack.run().success);
                }
            }
        }
    }

    #[test]
    fn test_2_nib_shift_blake() {
        for y in 0..16 {
            for x in 0..16 {
                let n = 3;
                let mut stack = StackTracker::new();
                let tables = u4_push_shift_for_blake(&mut stack);
                stack.number(y);
                stack.number(x);
                u4_2_nib_shift_blake(&mut stack, tables);
                stack.number((((y << 4) + x) >> n) % 16);
                stack.op_equalverify();
                stack.drop(tables);
                stack.op_true();
                assert!(stack.run().success);
            }
        }
    }
}
