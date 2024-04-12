#[cfg(test)]
mod test {
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::bn254::fr::Fr;
    use crate::hash::blake3::{blake3_hash_equalverify, blake3_var_length, push_bytes_hex};
    use crate::treepp::*;
    use num_bigint::BigUint;
    use std::str::FromStr;

    #[test]
    fn test_blake3_gamma() {
        let hex_in = "0112d68f3c1d66dbc8009a2654f262a7275e583a921d068fd4b167003365ce1d";
        let hex_out = "5af371034ff540ac876243113457de647144c164d8c70c67af54676decf693d1";

        let blake3_script = blake3_var_length(32);

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
             93e25277e4d66279eb15590b16e81e35b4130c1f821454620ced1e0dbbdb6041";

        let hex_out = "0112d68f3c1d66dbc8009a2654f262a7275e583a921d068fd4b167003365ce1d";

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
        let hex_in = "2a8f22906ec3a082cf11fd5ab2d686074910d91c5f0d9bd66b7271d9fcf693d0
             9051ae9396ddf88f2dc314d39d1ff26ab6c2847fc3f5a25e302e3ce4534ec7ac";

        let hex_out = "1c05f88897f3a21862982118dc49123d38dc19af31dc29f3cbc5efd53a19a280";

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
        let hex_in = "1c05f88897f3a21862982118dc49123d38dc19af31dc29f3cbc5efd53a19a280\
             0984dfd0eddd54c745567978028bfd897ab44557a92f25130aa43ee5930b374c\
             1b60bf3803e64a6522103442a33e20822b74fcdd821881b09049fa5d15915185\
             002fefbdf4a3d202927ca92136c802ad74e8c7cb5fe75e4d1b087a6ac610cb8d\
             08b635aa610f247299d9e166bf438dbaa60efc8494ecbe6a28c2bd25bd1d0b33\
             258007d2887e53cec1497173c2e27dcca5d26b0455ea6a0ff706b7d903c96f09\
             1b9447fd2f1ca01a45964f2c17246228677a10861a27ff0b532e0f8db4779015\
             015344999e4ee75ff64540473197134a729bfb4cf36283a5a893656bac5340e0\
             23dad6c00cfde33904f887053179d0f3553c6c3f7cb5a8c6c80c791c74b68ab3\
             0ff160760d22790f29df44b735429ff99d7297f145a7c4c41be0e15236582eb8\
             00007ae155c5aded04e6a1314cbe86cb6bf1188f6c4d863ad90b4fb8f5ce8b12\
             29ed17e27c4d9fb1797cdbe6102e4d5870a86a8192f5cd661dd948d640cd5dd0\
             055dcf9039f8428d9bb8e5f8c0af917cf418368c62d28e31c5cac650565979ca\
             13368d37a63346398f67a89e43065fd7abbaa24699a73b477da0fca9c373c49c\
             2df4d053f59a0817d26d5b3c97125bc858917279ca34eb3f1a98da409999361c\
             1abbe730af9166c08fd541c6f22eba2aeca426faa392391c7c1b1e61ab8f87e4";
        let hex_out = "4d9121c678b3807bc70ea48c60efd3a13c2f3e8309457835bb9a2d6c8103db4f";

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
        let hex_in = "1d2cd3539781e0520ebe5ed5df6e7b4413fb563a8f8c07a477b837d89103db4e\
             00127ac3c93c113bcfca62c3851d65f35ec78cce9bdf661c4379efc45b2a620e";
        let hex_out = "d0a7d5c415162d79b30566ec2aa0e94653f1139de9048b28588f77590615b05a";

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

    #[test]
    fn test_beta_from_hash() {
        let hex_in = "0112d68f3c1d66dbc8009a2654f262a7275e583a921d068fd4b167003365ce1d";
        let out = BigUint::from_str(
            "485596931070696584921673007746559446164232583596250406637950679013042540061",
        )
        .unwrap();

        let script = script! {
            {push_bytes_hex(hex_in)}
            {Fr::from_hash()}
            {Fr::push_u32_le(&out.to_u32_digits())}
            {Fr::equalverify(1, 0)}
            OP_TRUE
        };

        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_gamma_from_hash() {
        let hex_in = "5af371034ff540ac876243113457de647144c164d8c70c67af54676decf693d1";
        let out = BigUint::from_str(
            "19250037324033436581569284153336383290774316882310310865823706333327285195728",
        )
        .unwrap();

        let script = script! {
            {push_bytes_hex(hex_in)}
            {Fr::from_hash()}
            {Fr::push_u32_le(&out.to_u32_digits())}
            {Fr::equalverify(1, 0)}
            OP_TRUE
        };

        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_alpha_from_hash() {
        let hex_in = "4d9121c678b3807bc70ea48c60efd3a13c2f3e8309457835bb9a2d6c8103db4f";
        let out = BigUint::from_str(
            "13196272401875304388921830696024531900252495617961467853893732289110815791950",
        )
        .unwrap();

        let script = script! {
            {push_bytes_hex(hex_in)}
            {Fr::from_hash()}
            {Fr::push_u32_le(&out.to_u32_digits())}
            {Fr::equalverify(1, 0)}
            OP_TRUE
        };

        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_y_from_hash() {
        let hex_in = "d0a7d5c415162d79b30566ec2aa0e94653f1139de9048b28588f77590615b05a";
        let out = BigUint::from_str(
            "6824639836122392703554190210911349683223362245243195922653951653214183338070",
        )
        .unwrap();

        let script = script! {
            {push_bytes_hex(hex_in)}
            {Fr::from_hash()}
            {Fr::push_u32_le(&out.to_u32_digits())}
            {Fr::equalverify(1, 0)}
            OP_TRUE
        };

        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }
}
