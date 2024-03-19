#[cfg(test)]
mod tests {
    use bitcoin_script::bitcoin_script as script;
    use scripts::opcodes::u32_std::{u32_equal, u32_equalverify, u32_push};
    use scripts::opcodes::{execute_script, unroll};
    use scripts::opcodes::blake3::*;
    use scripts::opcodes::pushable;

    #[test]
    fn test_permute() {
        let mut env = ptr_init();
        // println!("Start env: {}", round(&mut env, 16).to_hex_string());
        permute(&mut env);
        // println!("Permuted env: {:?}", env);
        assert!(env.ptr(M(0)) == 82);
        assert!(env.ptr(M(1)) == 86);
        assert!(env.ptr(M(2)) == 83);
        assert!(env.ptr(M(3)) == 90);
        assert!(env.ptr(M(4)) == 87);
        assert!(env.ptr(M(5)) == 80);
        assert!(env.ptr(M(6)) == 84);
        assert!(env.ptr(M(7)) == 93);
        assert!(env.ptr(M(8)) == 81);
        assert!(env.ptr(M(9)) == 91);
        assert!(env.ptr(M(10)) == 92);
        assert!(env.ptr(M(11)) == 85);
        assert!(env.ptr(M(12)) == 89);
        assert!(env.ptr(M(13)) == 94);
        assert!(env.ptr(M(14)) == 95);
        assert!(env.ptr(M(15)) == 88);
    }

    #[test]
    fn test_initial_state() {
        let script = script! {
            {initial_state(64)}
        };
        let res = execute_script(script);
        assert!(res.final_stack[17][0] == 79);
    }

    #[test]
    fn test_blake3() {
        let script = script! {
            {unroll(16, |_| u32_push(1))}
            blake3
            {u32_push(0x700e822d)}
            u32_equalverify
            {u32_push(0x98bd6b10)}
            u32_equalverify
            {u32_push(0xfcc2af6c)}
            u32_equalverify
            {u32_push(0xd6e55b11)}
            u32_equalverify
            {u32_push(0xc1a5488b)}
            u32_equalverify
            {u32_push(0xc7bcf99a)}
            u32_equalverify
            {u32_push(0x963deefd)}
            u32_equalverify
            {u32_push(0xae95ca86)}
            u32_equal
        };
        let res = execute_script(script);
        assert!(res.success);
    }

    #[test]
    fn test_blake3_160() {
        let script = script! {
            {unroll(10, |_| u32_push(1))}
            blake3_160
            {u32_push(0xa759f48b)}
            u32_equalverify
            {u32_push(0x3efce995)}
            u32_equalverify
            {u32_push(0x63eae235)}
            u32_equalverify
            {u32_push(0x48e63346)}
            u32_equalverify
            {u32_push(0x2cef0e29)}
            u32_equal
        };
        let res = execute_script(script);
        assert!(res.success);
    }
}
