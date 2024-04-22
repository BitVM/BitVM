#[cfg(test)]
mod test {
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::bn254::fr::Fr;
    use crate::treepp::*;

    #[test]
    fn test_compute_pi() {
        let script = script! {
            // push L[1], L[2]
            { Fr::push_dec("19264250262515049392118907974032894668050943806280011767302681470321758079402") }
            { Fr::push_dec("5147149846110622280763906966379810308773882279335494056719681880590330080749") }

            // push the inputs
            { Fr::push_dec("246513590391103489634602289097178521809") }
            { Fr::push_dec("138371009144214353742010089705444713455") }

            { Fr::roll(2) }
            { Fr::mul() }
            { Fr::toaltstack() }

            { Fr::mul() }
            { Fr::fromaltstack() }
            { Fr::add(1, 0) }
            { Fr::neg(0) }

            { Fr::push_dec("12368363170870087162509434874521168463460384615249055347885673275750149676873") }
            { Fr::equalverify(1, 0) }
            OP_TRUE
        };

        println!("fflonk.compute_pi = {} bytes", script.len());

        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }
}
