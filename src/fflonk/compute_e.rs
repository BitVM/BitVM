#[cfg(test)]
mod test {
    use crate::bn254::curves::G1Projective;
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::bn254::fq::Fq;
    use crate::bn254::fr::Fr;
    use crate::treepp::*;

    #[test]
    fn test_compute_e() {
        let script = script! {
            // push G1x, G1y (3 elements)
            { Fq::push_dec("1") }
            { Fq::push_dec("2") }
            { Fq::push_dec("1") }

            // push the scalar
            { Fr::push_dec("20939596453786382856662891660365666437489374655427796935463148514894213437967") }
            { G1Projective::scalar_mul() }

            { Fq::push_dec("10905825615646575916826598897124608361270584984190374057529352166783343482862") }
            { Fq::push_dec("19290909793509893735943189519527824156597590461000288988451227768509803549366") }
            { Fq::push_dec("10334981607594421347972269000738063023881743479366183631046354259553646162574") }

            { G1Projective::equalverify() }
            OP_TRUE
        };

        println!("fflonk.compute_e = {} bytes", script.len());

        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }
}
