use super::pushable;
use crate::opcodes::unroll;
use bitcoin::ScriptBuf as Script;
use bitcoin_script::bitcoin_script as script;

pub fn to_bitstring(n: u32) -> Script {
    script! {
        {
            unroll(n - 1, |i| {
                let a = 1 << (n - 1 - i);
                let b = a - 1;
                script! {
                    OP_DUP
                    { b } OP_GREATERTHAN
                    OP_SWAP OP_OVER
                    OP_IF 
                        { a } OP_SUB 
                    OP_ENDIF
                }
        })}
    }
}


mod test{
    use crate::opcodes::execute_script;
    use super::*;

    #[test]
    fn test_to_bitstring() {
        let script = script! {
            {0b11110101}
            {to_bitstring(8)}
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY

            1 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            1 OP_EQUAL
        };
        assert!(execute_script(script).success)        
    }

}

