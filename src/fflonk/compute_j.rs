#[cfg(test)]
mod test {
    use crate::bn254::curves::G1Projective;
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::bn254::fq::Fq;
    use crate::bn254::fr::Fr;
    use crate::treepp::*;

    #[test]
    fn test_compute_j() {
        let script = script! {
            // push W1 (3 elements)
            { Fq::push_dec_montgomery("32650538602400348219903702316313439265244325226254563471430382441955222030") }
            { Fq::push_dec_montgomery("1102261574488401129043229793384018650738538286437537952751903719159654317199") }
            { Fq::push_dec_montgomery("1") }

            // push the scalar
            { Fr::push_dec_montgomery("1021979267781513382639867303596638615172285308777215242749714941672007413081") }
            { G1Projective::scalar_mul() }

            { Fq::push_dec_montgomery("2959562071167086018427906252728568621973040394868315776950851582459669551081") }
            { Fq::push_dec_montgomery("5248835691815263544471788309691308785423871173394577194626050104765380585421") }
            { Fq::push_dec_montgomery("19277062899702791882368245424983329716198384271778017207570439921049817477033") }

            { G1Projective::equalverify() }
            OP_TRUE
        };

        println!("fflonk.compute_j = {} bytes", script.len());

        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }
}
