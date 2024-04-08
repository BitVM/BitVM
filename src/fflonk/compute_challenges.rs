#[cfg(test)]
mod test {
    use crate::hash::blake3::blake3;
    use crate::treepp::*;
    use crate::u32::u32_std::{u32_equal, u32_equalverify, u32_push};

    #[test]
    fn test_blake3_beta_to_gamma() {
        // input: 13910503fa5680aefccee442d9548a7b7fb22bd46ced16828cee7b4112ca19c52d84597d0591f9f1a90a9f938ec15e50e0fb9de3e758041897896f03aa0b00a9
        // output: ca2eb6fba3ab9634d26bf71b7556b479dddacf9e40be95cbc4a3a2432a89f96b

        let script = script! {
            {u32_push(0xa9000baa)}
            {u32_push(0x036f8997)}
            {u32_push(0x180458e7)}
            {u32_push(0xe39dfbe0)}
            {u32_push(0x505ec18e)}
            {u32_push(0x939f0aa9)}
            {u32_push(0xf1f99105)}
            {u32_push(0x7d59842d)}
            {u32_push(0xc519ca12)}
            {u32_push(0x417bee8c)}
            {u32_push(0x8216ed6c)}
            {u32_push(0xd42bb27f)}
            {u32_push(0x7b8a54d9)}
            {u32_push(0x42e4cefc)}
            {u32_push(0xae8056fa)}
            {u32_push(0x03059113)}
            blake3
            {u32_push(0x6bf9892a)}
            {u32_equalverify()}
            {u32_push(0x43a2a3c4)}
            {u32_equalverify()}
            {u32_push(0xcb95be40)}
            {u32_equalverify()}
            {u32_push(0x9ecfdadd)}
            {u32_equalverify()}
            {u32_push(0x79b45675)}
            {u32_equalverify()}
            {u32_push(0x1bf76bd2)}
            {u32_equalverify()}
            {u32_push(0x3496aba3)}
            {u32_equalverify()}
            {u32_push(0xfbb62eca)}
            {u32_equal()}
        };

        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }
}
