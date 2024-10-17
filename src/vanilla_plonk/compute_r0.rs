#[cfg(test)]
mod test {
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::bn254::fr::Fr;
    use crate::vanilla_plonk::mock::Mock;
    use crate::treepp::*;

    #[test]
    fn test_compute_r0() {

        // initializing for plonk
        let mock = Mock::new();

        // hardcoding for now
        let lagrange =
            "13835661909005086584537585551111878845398600560444281018191450614994836187551";
        let alpha = "20524487875464908209490178628685531130495322118498633336472062372490596458160";
        let alpha2 = "15078006696392234695360259740636700679685160725546870868598180534190235322590";
        let beta = "1469297811652786173524431317518899500255817294137003269865683238937785575151";
        let gamma = "18662762454804078530469268494873062022326292981887766436251536958276002157418";
        let pi = "10021071990350671093045688305445916367264617343457315103161905320545395462791";
        let final_r0 = "19373036328879061590929829424883617780809305973559985398098131955881901596832";

        let a = mock.get_plonk_proof().eval_a;
        let b = mock.get_plonk_proof().eval_b;
        let c = mock.get_plonk_proof().eval_c;
        let s1 = mock.get_plonk_proof().eval_s1;
        let s2 = mock.get_plonk_proof().eval_s2;
        let zw = mock.get_plonk_proof().eval_zw;

        let script = script! {

            // e1 = pi
            { Fr::push_dec(lagrange) }

            { Fr::push_dec(alpha2) }

            { Fr::mul() }

            // pushing e2 to alt stack [e2]
            { Fr::toaltstack() }

            { Fr::push_dec(s1.as_str()) }

            { Fr::push_dec(beta) }

            { Fr::mul() }

            { Fr::push_dec(a.as_str()) }

            { Fr::add(0, 1) }

            { Fr::push_dec(gamma) }

            { Fr::add(0, 1) }

            // e3a to alt stack [e3a, e2]
            { Fr::toaltstack() }

            { Fr::push_dec(s2.as_str()) }

            { Fr::push_dec(beta) }

            { Fr::mul() }

            { Fr::push_dec(b.as_str()) }

            { Fr::add(0, 1) }

            { Fr::push_dec(gamma) }

            { Fr::add(0, 1) }

            // e3b to alt stack [e3b, e3a, e2]
            { Fr::toaltstack() }

            { Fr::push_dec(gamma) }

            { Fr::push_dec(c.as_str()) }

            { Fr::add(0, 1) }

            // e3c to alt stack [e3c, e3b, e3a, e2]
            { Fr::toaltstack() }

            { Fr::fromaltstack() }
            { Fr::fromaltstack() }

            { Fr::mul() }

            { Fr::fromaltstack() }
            // [e3c, e3b, e3a]

            { Fr::mul() }

            { Fr::push_dec(alpha) }

            { Fr::mul() }

            { Fr::push_dec(zw.as_str()) }

            { Fr::mul() }

            { Fr::fromaltstack() }
            // [e2, e3]

            { Fr::push_dec(pi) }

            // ri = e1 - e2
            { Fr::sub(0, 1) }

            // r0 = ri - e3
            { Fr::sub(0, 1) }

            { Fr::push_dec(final_r0) }

            { Fr::equalverify(0, 1) }

            OP_TRUE
        };

        println!("plonk.compute_r0 = {} bytes", script.len());

        let exec_result = execute_script(script.clone());
        assert!(exec_result.success);

        // script
    }
}
