#[cfg(test)]
mod test {
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::bn254::fr::Fr;
    use crate::vanilla_plonk::mock::Mock;
    use crate::treepp::*;

    #[test]
    fn test_compute_e() {

        // initializing for plonk
        let mock = Mock::new();

        // hardcoding values for now 
        let r0 = "19373036328879061590929829424883617780809305973559985398098131955881901596832";
        let u = "3671131478064498243238023262552279287106793140894919933179355516438710425648";
        let v1 = "14498287487861080416419858029046690078416135504177055334726844512695965479306";
        let v2 = "18486859084993980290861474858117854364521133753017300100785278076947352879482";
        let v3 = "14123602248794384244454650572711232922479511827410910736881997840343398040432";
        let v4 = "2148331607749528302422858560444633850556901391050132284183052763054829516667";
        let v5 = "4136526678804187529711616303688208869122242242984196786246124372892070082407";

        let a = mock.get_plonk_proof().eval_a;
        let b = mock.get_plonk_proof().eval_b;
        let c = mock.get_plonk_proof().eval_c;
        let s1 = mock.get_plonk_proof().eval_s1;
        let s2 = mock.get_plonk_proof().eval_s2;
        let zw = mock.get_plonk_proof().eval_zw;

        let final_s = "3632513726946846250052790963670169656207521712154784910302783043667760314953";

        let script = script! {

            { Fr::push_dec(r0) }

            { Fr::push_zero() }

            // s = -r0
            { Fr::sub(0, 1) }

            { Fr::push_dec(v1) }

            { Fr::push_dec(a.as_str()) }

            { Fr::mul() }

            { Fr::add(0, 1) }

            { Fr::push_dec(v2) }

            { Fr::push_dec(b.as_str()) }

            { Fr::mul() }

            { Fr::add(0, 1) }

            { Fr::push_dec(v3) }

            { Fr::push_dec(c.as_str()) }

            { Fr::mul() }

            { Fr::add(0, 1) }

            { Fr::push_dec(v4) }

            { Fr::push_dec(s1.as_str()) }

            { Fr::mul() }

            { Fr::add(0, 1) }

            { Fr::push_dec(v5) }

            { Fr::push_dec(s2.as_str()) }

            { Fr::mul() }

            { Fr::add(0, 1) }

            { Fr::push_dec(u) }

            { Fr::push_dec(zw.as_str()) }

            { Fr::mul() }

            { Fr::add(0, 1) }

            // checking s calculated 
            { Fr::push_dec(final_s) }

            { Fr::equalverify(0, 1) }

            OP_TRUE
        };

        println!("plonk.compute_e = {} bytes", script.len());

        let exec_result = execute_script(script.clone());
        assert!(exec_result.success);
    }
}
