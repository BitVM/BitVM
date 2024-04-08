#[cfg(test)]
mod test {
    use crate::hash::blake3::{blake3, blake3_hash_equalverify, blake3_var_length, push_bytes_hex};
    use crate::treepp::*;

    #[test]
    fn test_blake3_gamma() {
        let hex_in = "13910503fa5680aefccee442d9548a7b7fb22bd46ced16828cee7b4112ca19c5\
             2d84597d0591f9f1a90a9f938ec15e50e0fb9de3e758041897896f03aa0b00a9";
        let hex_out = "ca2eb6fba3ab9634d26bf71b7556b479dddacf9e40be95cbc4a3a2432a89f96b";

        let blake3_script = blake3_var_length(64);

        let script = script! {
            {push_bytes_hex(hex_in)}
            {blake3_script.clone()}
            {push_bytes_hex(hex_out)}
            {blake3_hash_equalverify()}
            OP_TRUE
        };
        println!(
            "fflonk.compute_challenges.gamma = {} bytes",
            blake3_script.len()
        );

        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_blake3_beta() {
        let hex_in = "80ab839f980b0b9674498047525c2620ec69b59914a384b6aedb99849fc54bbf\
             00000000000000000000000000000000b974ca610b172441d464158c95b2a0d1\
             00000000000000000000000000000000681949787a43d2a5e9cc7f591963a3ef\
             1001cbc201a45289689aba0178dd4ca34c5077b14d38f2665f679f60118cd3c1";
        let hex_out = "4b28a085aeca25c5a84058a0d65cc3994d975ba3dbca63b4fd332f3aa4d7716c";

        let blake3_script = blake3_var_length(128);

        let script = script! {
            {push_bytes_hex(hex_in)}
            {blake3_script.clone()}
            {push_bytes_hex(hex_out)}
            {blake3_hash_equalverify()}
            OP_TRUE
        };
        println!(
            "fflonk.compute_challenges.beta = {} bytes",
            blake3_script.len()
        );

        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }
}
