use bitcoin_script::Script;
use bitcoin_script_stack::stack::{script, StackTracker, StackVariable};
use super::u4_shift::u4_push_lshift_tables;

/// Pushes the right shift table, which calculates (x >> b) for {b = 1, 0 <= x < 31 (sum of two numbers)} and {b = 2, 0 <= x < 16}
pub fn u4_push_rshift_tables() -> Script {
    script! {
        OP_3
        OP_DUP
        OP_2DUP
        OP_2
        OP_DUP
        OP_2DUP
        OP_1
        OP_DUP
        OP_2DUP
        OP_0
        OP_DUP
        OP_2DUP

        for i in (0..16).rev() {
            { i }
            OP_DUP
        }
    }
}

/// Pushes left and right shift tables
pub fn u4_push_shift_tables_stack(stack: &mut StackTracker) -> StackVariable {
    stack.var(
        16 * 6,
        script! { {u4_push_lshift_tables()} {u4_push_rshift_tables()}},
        "shift_tables",
    )
}

/// Calculates n'th right shift of the top u4 element with both tables
pub fn u4_rshift_stack(stack: &mut StackTracker, tables: StackVariable, n: u32) -> StackVariable {
    assert!((1..4).contains(&n));
    if n == 3 {
        stack.number(8);
        return stack.op_greaterthanorequal();
    }
    stack.get_value_from_table(tables, Some(32 * (n - 1)))
}

/// Calculates n'th left shift of the top u4 element with both tables
pub fn u4_lshift_stack(stack: &mut StackTracker, tables: StackVariable, n: u32) -> StackVariable {
    assert!((1..4).contains(&n));
    stack.get_value_from_table(tables, Some(16*3 + 16 * (n - 1)))
}

/// Table for multiplication by two
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
        },
        0,
        false,
        0,
        "",
    );
    stack.define(16, "lshift1")
}

/// Assuming the u4 numbers X and Y are on top of the stack, calculates (16 * Y + X) >> n modulo 16
pub fn u4_2_nib_shift_stack(stack: &mut StackTracker, tables: StackVariable, n: u32) -> StackVariable {
    assert!((1..4).contains(&n));
    u4_lshift_stack(stack, tables, 4 - n);
    stack.op_swap();
    u4_rshift_stack(stack, tables, n);
    stack.op_add()
}

/// Assuming the u4 numbers X and Y are on top of the stack, calculates (16 * Y + X) >> 3 modulo 16
pub fn u4_2_nib_shift_blake(stack: &mut StackTracker, tables: StackVariable) -> StackVariable {
    stack.number(8);
    stack.op_greaterthanorequal();
    stack.op_swap();
    stack.get_value_from_table(tables, None);
    stack.op_add()
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_rshift() {
        for n in 1..4 {
            let mut max_x = 15;
            if n == 1 {
                max_x = 30;
            }
            for x in 0..=max_x {
                let mut stack = StackTracker::new();
                let tables = u4_push_shift_tables_stack(&mut stack);
                stack.number(x);
                u4_rshift_stack(&mut stack, tables, n);
                stack.number(x >> n);
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
