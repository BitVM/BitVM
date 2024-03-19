use crate::opcodes::{pushable, unroll};
use bitcoin::ScriptBuf as Script;
use bitcoin_script::bitcoin_script as script;

/// Verify that the top `byte_count` many stack items
/// are in the 8-bit range from 0 to 255.
/// Does not drop the bytes
pub fn sanitize_bytes(byte_count: u32) -> Script {
    script! {
        256
        { unroll(byte_count, |i| script!{
                {i+1} OP_PICK OP_OVER 0 OP_SWAP OP_WITHIN OP_VERIFY
            })
        }
        OP_DROP
    }
}
