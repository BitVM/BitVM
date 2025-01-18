use crate::treepp::{script, Script};
use super::u4_std::u4_drop;

/// Pushes the u4 left shift table, which calculates (x << b) % 16 with OP_PICK'ing (x + 16 * (b - 1))
pub fn u4_push_lshift_tables() -> Script {
    script! {
        OP_8
        OP_0
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_12
        OP_8
        OP_4
        OP_0
        OP_2OVER
        OP_2OVER
        OP_2OVER
        OP_2OVER
        OP_2OVER
        OP_2OVER
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
    }
}

/// Drop the u4 left shift table
pub fn u4_drop_lshift_tables() -> Script { u4_drop(16 * 3) }

/// Pushes the right shift table, which calculates (x >> b) for b < 3 with OP_PICK'ing (x + 16 * (b - 1))
pub fn u4_push_rshift_tables() -> Script {
    //rshift3, rshift2, rshift1
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

        OP_7
        OP_DUP
        OP_6
        OP_DUP
        OP_5
        OP_DUP
        OP_4
        OP_DUP
        OP_3
        OP_DUP
        OP_2
        OP_DUP
        OP_1
        OP_DUP
        OP_0
        OP_DUP
    }
}

/// Drops the u4 right shift table
pub fn u4_drop_rshift_tables() -> Script { u4_drop(16 * 2) }

/// Pushes u4 left and right shift tables
pub fn u4_push_2_nib_rshift_tables() -> Script {
    script! {
       { u4_push_lshift_tables() }
       { u4_push_rshift_tables() }
    }
}

/// Drops u4 left and right shift tables
pub fn u4_drop_2_nib_rshift_tables() -> Script {
    script! {
       { u4_drop_rshift_tables() }
       { u4_drop_lshift_tables() }
    }
}

/// Calculates n'th left shift of the top u4 element with the u4_lshift_tables
pub fn u4_lshift(n: u32, lshift_offset: u32) -> Script {
    assert!((1..4).contains(&n));
    script! {
        { lshift_offset + (16 * (n - 1)) }
        OP_ADD
        OP_PICK
    }
}

/// Calculates n'th right shift of the top u4 element with the u4_rshift_tables
pub fn u4_rshift(n: u32, rshift_offset: u32) -> Script {
    assert!((1..4).contains(&n));
    script! {
        if n == 3 {
            8
            OP_GREATERTHANOREQUAL
        } else {
            { rshift_offset + (16 * (n - 1)) }
            OP_ADD
            OP_PICK
        }
    }
}

/// Assuming the u4 numbers X and Y are on top of the stack, calculates (16 * Y + X) >> n modulo 16
/// Expects 2_nib_shift_tables at the stack, and offset as a parameter to locate the table (which should be equal to number of elements after the tables not including X and Y)
pub fn u4_2_nib_rshift_n(n: u32, tables_offset: u32) -> Script {
    assert!((1..4).contains(&n));
    script! {
        { u4_lshift(4 - n, tables_offset + (16 * 2) + 1)  }
        OP_SWAP
        { u4_rshift(n, tables_offset + 1)  }
        OP_ADD
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{run, treepp::script};

    #[test]
    fn test_lshift() {
        for n in 1..4 {
            for x in 0..16 {
                let script = script! {
                    { u4_push_lshift_tables() }
                    { x }
                    { u4_lshift(n, 0)}
                    { (x << n) % 16 }
                    OP_EQUALVERIFY
                    { u4_drop_lshift_tables() }
                    OP_TRUE
                };
                run(script);
            }
        }
    }

    #[test]
    fn test_rshift() {
        for n in 1..4 {
            for x in 0..16 {
                let script = script! {
                    { u4_push_rshift_tables() }
                    { x }
                    { u4_rshift(n, 0) }
                    { x >> n }
                    OP_EQUALVERIFY
                    { u4_drop_rshift_tables() }
                    OP_TRUE
                };
                run(script);
            }
        }
    }

    #[test]
    fn test_2_nib_rshift_function() {
        for n in 1..4 {
            for y in 0..16 {
                for x in 0..16 {
                    let script = script! {
                        { u4_push_2_nib_rshift_tables() }
                        { x }
                        { y }         
                        { u4_2_nib_rshift_n(n, 0) }
                        { (((y << 4) + x) >> n) % 16 }
                        OP_EQUALVERIFY
                        { u4_drop_2_nib_rshift_tables() }
                        OP_TRUE
                    };
                    run(script);
                }
            }
        }
    }
}
