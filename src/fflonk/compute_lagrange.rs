#[cfg(test)]
mod test {
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::bn254::fr::Fr;
    use crate::treepp::*;
    use ark_ff::Field;
    use num_bigint::BigUint;
    use std::str::FromStr;

    #[test]
    fn test_compute_lagrange() {
        let mut li_1_inv = ark_bn254::Fr::from_str(
            "2173335263468457880677030391603678787407318523287432531877773790452047235821",
        )
        .unwrap();
        li_1_inv.inverse_in_place().unwrap();

        let mut li_2_inv = ark_bn254::Fr::from_str(
            "3695504780263816985137938305786365026932326252410439503136485422302932463173",
        )
        .unwrap();
        li_2_inv.inverse_in_place().unwrap();

        let script = script! {
            // push zh
            { Fr::push_dec("9539499652122301619680560867461437153480631573357135330838514610439758374055") }

            // push the inverse of Li_1
            { Fr::push_u32_le(&BigUint::from(li_1_inv).to_u32_digits()) }

            { Fr::copy(1) }
            { Fr::toaltstack() }

            { Fr::mul() }

            // check L[1]
            { Fr::push_dec("19264250262515049392118907974032894668050943806280011767302681470321758079402") }
            { Fr::equalverify(1, 0) }

            // push the inverse of Li_2
            { Fr::push_u32_le(&BigUint::from(li_2_inv).to_u32_digits()) }
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::push_dec("11699596668367776675346610687704220591435078791727316319397053191800576917728") }
            { Fr::mul() }

            // check L[2]
            { Fr::push_dec("5147149846110622280763906966379810308773882279335494056719681880590330080749") }
            { Fr::equalverify(1, 0) }

            OP_TRUE
        };

        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }
}
