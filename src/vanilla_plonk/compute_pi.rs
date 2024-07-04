#[cfg(test)]
mod test {
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::bn254::fr::Fr;
    use crate::vanilla_plonk::mock::Mock;
    use crate::treepp::*;

    #[test]
    fn test_compute_pi() {
        // hardcoding for now
        let lagrange =
            "13835661909005086584537585551111878845398600560444281018191450614994836187551";

        // initializing for plonk
        let mock = Mock::new();
        let pi = mock.get_plonk_proof().pi;

        let final_pi =
            "10021071990350671093045688305445916367264617343457315103161905320545395462791"
                .to_string();

        let script = script! {

            { Fr::push_dec(lagrange) }

            { Fr::push_dec(pi.as_str()) }

            { Fr::mul() }

            { Fr::push_zero() }

            { Fr::sub(0, 1) }

            { Fr::push_dec(final_pi.as_str()) }

            { Fr::equalverify(0, 1) }

            OP_TRUE
        };

        println!("plonk.compute_pi = {} bytes", script.len());

        let exec_result = execute_script(script.clone());
        assert!(exec_result.success);

        // script
    }
}
