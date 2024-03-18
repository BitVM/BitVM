use bitcoin::ScriptBuf as Script;
use bitcoin_script::bitcoin_script as script;
use crate::scripts::opcodes::{pushable, unroll};


/// Verifies that the top two `item_count` many stack items are equal
pub fn vec_equalverify(item_count: u32) -> Script {
    script! {
        { unroll(item_count, |i| script! {
                {item_count - i} OP_ROLL OP_EQUALVERIFY
            })
        }
    }
}


/// Compares if the top two `item_count` many stack items are equal
pub fn vec_equal(item_count: u32) -> Script {
    script! {
        { unroll(item_count - 1, |i| script!{
                { item_count - i}
                OP_ROLL
                OP_EQUAL
                OP_TOALTSTACK
            })
        }
        OP_EQUAL
        { unroll(item_count - 1, |_| script!{
                OP_FROMALTSTACK
                OP_BOOLAND
            })
        }
    }
}

/// Compares if the top two `item_count` many stack items are not equal
pub fn vec_not_equal(item_count: u32) -> Script {
    script! {
        { unroll(item_count - 1, |i| script!{
                { item_count - i }
                OP_ROLL
                OP_EQUAL
                OP_NOT
                OP_TOALTSTACK
            })
        }
        OP_EQUAL
        OP_NOT
        { unroll(item_count - 1, |_| script!{
                OP_FROMALTSTACK
                OP_BOOLOR
            })
        }
    }
}


#[cfg(test)]
mod test {
    use crate::scripts::opcodes::execute_script;
    use super::*;

    #[test]
    fn test_vec_equalverify(){
        // Case: succeed
        let script = script! {
            1 2 3 4 5 6 7 8
            1 2 3 4 5 6 7 8
            { vec_equalverify(8) }
            1
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);

        // Case: fail
        let script = script! {
            1 2 3 4 5 6 7 8
            1 2 3 4 5 6 7 9
            { vec_equalverify(8) }
            1
        };
        let exec_result = execute_script(script);
        assert!(!exec_result.success)
    }

    #[test]
    fn test_vec_equal(){
        // Case: succeed
        let script = script! {
            1 2 3 4 5 6 7 8
            1 2 3 4 5 6 7 8
            { vec_equal(8) }
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);

        // Case: fail
        let script = script! {
            1 2 3 4 5 6 7 8
            1 2 3 4 5 6 7 9
            { vec_equal(8) }
        };
        let exec_result = execute_script(script);
        assert!(!exec_result.success);
    }


}

