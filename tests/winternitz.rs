#[cfg(test)]
mod test {
    use bitvm::treepp::{pushable, script, execute_script, unroll};
    use bitvm::winternitz::{checksig_verify, sign};
    
    // The secret key
    const MY_SECKEY: &str = "b138982ce17ac813d505b5b40b665d404e9528e7";

    #[test]
    fn test_winternitz() {
        // The message to sign
        const MESSAGE: [u8;20]  = [1,2,3,4,5, 6,7,8,9,0xa, 0xb,0xc,0xd,0xe,0xf, 0,0,0,0,0];

        let script = script!{
            { sign(MY_SECKEY, MESSAGE) }
            { checksig_verify(MY_SECKEY) }
            
            0x21 OP_EQUALVERIFY
            0x43 OP_EQUALVERIFY
            0x65 OP_EQUALVERIFY
            0x87 OP_EQUALVERIFY
            0xA9 OP_EQUALVERIFY
            0xCB OP_EQUALVERIFY
            0xED OP_EQUALVERIFY
            0x0F OP_EQUALVERIFY
            0x00 OP_EQUALVERIFY
            0x00 OP_EQUAL
        };

        println!("Winternitz signature size: {:?} bytes per 80 bits", script.as_bytes().len());
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

}