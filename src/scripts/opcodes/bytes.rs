use bitcoin::ScriptBuf as Script;
use bitcoin_script::bitcoin_script as script;
use crate::scripts::opcodes::{pushable, unroll};

/// Verify that the top `byte_count` many stack items 
/// are in the 8-bit range from 0 to 255.
/// Does not drop the bytes
pub fn sanitize_bytes(byte_count: u32)  -> Script {
    script!{
        256
        { unroll(byte_count, |i| script!{ 
                {i+1} OP_PICK OP_OVER 0 OP_SWAP OP_WITHIN OP_VERIFY
            })
        }
        OP_DROP
    }
}






#[cfg(test)]
mod test {
    use crate::scripts::opcodes::execute_script;

    use super::*;

    #[test]
    fn test_santize_bytes__succeed() {

        let script = script! {
            { 0x22 }
            { 0x23 }
            { 0x24 }
            { 0x25 }
            { sanitize_bytes(2) }
            OP_2DROP OP_2DROP
            1
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success)
    }

    #[test]
    fn test_santize_bytes__fail() {

        let script = script! {
            { 0x256 }
            { sanitize_bytes(1) }
            OP_DROP
            1
        };
        let exec_result = execute_script(script);
        assert!(!exec_result.success)
    }

}

