#[cfg(test)]
mod test {
    use crate::hash::blake3::{blake3_hash_equalverify, blake3_var_length, push_bytes_hex};
    use crate::treepp::*;

    #[test]
    fn test_blake3_gamma() {
        let hex_in = "13910503fa5680aefccee442d9548a7b7fb22bd46ced16828cee7b4112ca19c5
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
        let hex_in = "80ab839f980b0b9674498047525c2620ec69b59914a384b6aedb99849fc54bbf
             00000000000000000000000000000000b974ca610b172441d464158c95b2a0d1
             00000000000000000000000000000000681949787a43d2a5e9cc7f591963a3ef
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

    #[test]
    fn test_blake3_xi() {
        let hex_in = "13910503fa5680aefccee442d9548a7b7fb22bd46ced16828cee7b4112ca19c5
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
            "fflonk.compute_challenges.xi = {} bytes",
            blake3_script.len()
        );

        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_blake3_alpha() {
        let hex_in = "089d7d301ee5158df12ae0416f5153053d0b2e7c59d8d386b51bcbf36a89f967
             28e1f8e5e04e2b523cab6113239f3160e954bb9fafdd5771602b27a685132413
             2f87db199f48b15d478ea0b7df3fe5d2a705ad25394604dddc2f4b8722e61e48
             1bea9d790cadf15ae3fc5670efeecc15f25fbef32dafbdcbee44f7bad78d5959
             1fe3920c5988ac04cd606c2f27eb32f007dedfe0951dc4522e3ea2b34bdf677b
             24d0f94e68f3b8c618c1c2dd7a9c40b8cfb59a91d42359712ccffa53602ca2c6
             13f612131dd460e006e8564817699268ed708aca49e390169dd0c8fd9756d00b
             27eb73e3388514c1a165ad4ff2aed5520166029f25a66189ba5398d2e5f3fa86
             2e639b71f48cfb497c68d64bcaad1c1dbdc67feb7210bf2313575aa5c2949209
             2f93509e022e2daa6f8ec13b47479788155d5d68fb059e8e8ecb778c167e7679
             18a8272c671692ce0a64ef9056b848da582ef9e1f5b3b8bfc77f591c7d0aa112
             1f1195dff1159afa520702ae0f7c8a8c4b6e62a0a4e8809f3e9ab8dc3adddd47
             0d9622e707fb46e206be125f20cf6951190244f5bb35631cf778adaad4821755
             091fb9af32c68dc76e47fe317d7c2e7a23ba429bb284bb2a6e59da96d2e48f27
             2e868db2991e90501451dff759bb99a5d98c13c01c755698ad020c0bbd2ddcb6
             177710f0022f570cae817013dc52dc068b5699c58df79ffac5c8a561a3f9feaa";

        let hex_out = "cd21ae900d8d3c713241f879ef9eaf1850118b6e5ed74b4a1b08cafc9ab08f80";

        let blake3_script = blake3_var_length(512);

        let script = script! {
            {push_bytes_hex(hex_in)}
            {blake3_script.clone()}
            {push_bytes_hex(hex_out)}
            {blake3_hash_equalverify()}
            OP_TRUE
        };
        println!(
            "fflonk.compute_challenges.alpha = {} bytes",
            blake3_script.len()
        );

        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_blake3_y() {
        let hex_in = "0b9074c488c6bbca5100e19fe9994da3af41ea4c77f189050b80f4acdab08f7c
             2c2d53e9f1c0d7c3206f5e85166d516e5c4ef0778c92b4e75b6fa3fd08ee71a0";

        let hex_out = "74bac50d06464b6eb14ab597f443e2cfe7100b43f97736472a375910a25cd6ed";

        let blake3_script = blake3_var_length(64);

        let script = script! {
            {push_bytes_hex(hex_in)}
            {blake3_script.clone()}
            {push_bytes_hex(hex_out)}
            {blake3_hash_equalverify()}
            OP_TRUE
        };
        println!(
            "fflonk.compute_challenges.y = {} bytes",
            blake3_script.len()
        );

        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }
}
