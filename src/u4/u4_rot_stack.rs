//use crate::treepp::{script, Script};
//use sha2::digest::typenum::bit;

use bitcoin_script_stack::stack::{StackTracker, StackVariable};

use super::u4_shift_stack::{u4_2_nib_shift_stack, u4_rshift_stack};

pub fn u4_rrot_nib_from_u32(
    stack: &mut StackTracker,
    tables: StackVariable,
    number: StackVariable,
    nib: u32,
    shift: u32,
    is_shift: bool,
) -> StackVariable {
    let pos_shift = shift / 4;

    if pos_shift > nib && is_shift {
        return stack.number(0);
    }

    let y = (8 - pos_shift + nib - 1) % 8;
    let x = (8 - pos_shift + nib) % 8;

    stack.copy_var_sub_n(number, x);

    let bit_shift = shift % 4;

    if y == 7 && is_shift {
        u4_rshift_stack(stack, tables, bit_shift)
    } else {
        stack.copy_var_sub_n(number, y);
        u4_2_nib_shift_stack(stack, tables, bit_shift)
    }
}

pub fn u4_rrot_u32(
    stack: &mut StackTracker,
    tables: StackVariable,
    number: StackVariable,
    shift: u32,
    is_shift: bool,
) -> StackVariable {
    let vars: Vec<StackVariable> = (0..8)
        .map(|nib| u4_rrot_nib_from_u32(stack, tables, number, nib, shift, is_shift))
        .collect();
    let mut nib0 = vars[0];
    stack.join_count(&mut nib0, 7);
    nib0
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::treepp::script;
    use crate::u4::u4_shift_stack::u4_push_shift_tables_stack;
    use bitcoin_script_stack::stack::StackTracker;
    use rand::Rng;

    fn rrot(x: u32, n: u32) -> u32 {
        if n == 0 {
            return x;
        }
        (x >> n) | (x << (32 - n))
    }

    fn rshift(x: u32, n: u32) -> u32 {
        if n == 0 {
            return x;
        }
        x >> n
    }

    #[test]
    fn test_rshift_rand() {
        let mut rng = rand::thread_rng();
        for _ in 0..100 {
            let x: u32 = rng.gen();
            let mut n: u32 = rng.gen();
            n %= 32;
            if n % 4 == 0 {
                n += 1;
            }

            let mut stack = StackTracker::new();
            let tables = u4_push_shift_tables_stack(&mut stack);
            let pos = stack.number_u32(x);
            u4_rrot_u32(&mut stack, tables, pos, n, true);

            stack.number_u32(rshift(x, n));

            stack.custom(
                script! {
                    for i in 0..8 {
                        { 8 - i}
                        OP_ROLL
                        OP_EQUALVERIFY
                    }
                },
                2,
                false,
                0,
                "verify",
            );

            stack.drop(pos);
            stack.drop(tables);
            stack.op_true();

            assert!(stack.run().success);
        }
    }

    #[test]
    fn test_rrot_rand() {
        let mut rng = rand::thread_rng();
        for _ in 0..100 {
            let x: u32 = rng.gen();
            let mut n: u32 = rng.gen();
            n %= 32;
            if n % 4 == 0 {
                n += 1;
            }

            let mut stack = StackTracker::new();
            let tables = u4_push_shift_tables_stack(&mut stack);
            let pos = stack.number_u32(x);
            u4_rrot_u32(&mut stack, tables, pos, n, false);

            stack.number_u32(rrot(x, n));

            stack.custom(
                script! {
                    for i in 0..8 {
                        { 8 - i}
                        OP_ROLL
                        OP_EQUALVERIFY
                    }
                },
                2,
                false,
                0,
                "verify",
            );

            stack.drop(pos);
            stack.drop(tables);
            stack.op_true();

            assert!(stack.run().success);
        }
    }
}
