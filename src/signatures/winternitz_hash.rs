use crate::treepp::*;
use crate::signatures::winternitz::{sign, checksig_verify};
use crate::hash::blake3::blake3_160_var_length;
use blake3::hash;

const MESSAGE_HASH_LEN: u8 = 20;


/// Verify a Winternitz signature for the blake3 hash of the top `input_len` many bytes on the stack
/// Fails if the signature is invalid
pub fn check_hash_sig(sec_key: &str, input_len: usize) -> Script {
    script! {
        // 1. Verify the signature and compute the signed message
        { checksig_verify(sec_key) }
        for _ in 0..MESSAGE_HASH_LEN {
            OP_TOALTSTACK
        }

        // 2. Hash the inputs
        { blake3_160_var_length(input_len) }

        // 3. Compare signed message to the hash
        for _ in 0..MESSAGE_HASH_LEN / 4 {
            for j in 0..4 {
                { 3 - j }
                OP_ROLL
                OP_FROMALTSTACK
                OP_EQUALVERIFY
            }
        }
    }
}

/// Create a Winternitz signature for the blake3 hash of a given message
pub fn sign_hash(sec_key: &str, message: &[u8]) -> Script {
    let message_hash = hash(message);
    let message_hash_bytes = &message_hash.as_bytes()[0..20];
    script! {
        { sign(sec_key, message_hash_bytes) }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_check_hash_sig() {

        // My secret key 
        let my_sec_key = "b138982ce17ac813d505b5b40b665d404e9528e7";
        
        // The message to sign
        let message = *b"This is an arbitrary length input intended for testing purposes....";

        let script = script! {
            //
            // Unlocking Script
            //

            // 1. Push the message 
            for byte in message.iter().rev() {
                { *byte }
            }
            // 2. Push the signature
            { sign_hash(my_sec_key, &message) }
            
            
            //
            // Locking Script
            //
            { check_hash_sig(my_sec_key, message.len()) }
            OP_TRUE
        };

        
        let exec_result = execute_script(script);
        if !exec_result.success {
            println!("ERROR: {:?} <--- \n STACK: {:4} ", exec_result.last_opcode, exec_result.final_stack);
        }
        assert!(exec_result.success);
    }


}