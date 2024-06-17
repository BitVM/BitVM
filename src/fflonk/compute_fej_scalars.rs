#[cfg(test)]
mod test {
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::bn254::fr::Fr;
    use crate::treepp::*;
    use ark_ff::Field;
    use num_bigint::BigUint;
    use std::str::FromStr;

    #[test]
    fn test_compute_fej() {
        let mut denh1_inv = ark_bn254::Fr::from_str(
            "16119335534554612347069410224124107110204763328009905428743152543535476039579",
        )
        .unwrap();
        denh1_inv.inverse_in_place().unwrap();

        let mut denh2_inv = ark_bn254::Fr::from_str(
            "3243830272143196976292614075227959624327946119988523541753598495438231730971",
        )
        .unwrap();
        denh2_inv.inverse_in_place().unwrap();

        let script = script! {
            // push alpha, denh1, denh2, y (4 elements)
            { Fr::push_dec("13196272401875304388921830696024531900252495617961467853893732289110815791950") }
            { Fr::push_u32_le(&BigUint::from(denh1_inv).to_u32_digits()) }
            { Fr::push_u32_le(&BigUint::from(denh2_inv).to_u32_digits()) }
            { Fr::push_dec("6824639836122392703554190210911349683223362245243195922653951653214183338070") }

            // push R0, R1, R2 (3 elements)
            { Fr::push_dec("9984215396403043994941496429066900252890008119992652401049849633408576425336") }
            { Fr::push_dec("20094893460628001506464425210304996393341228871437567669976791505614033716878") }
            { Fr::push_dec("17870878740602377735172834182794916404148892013933556022942404950055827532212") }

            // push H0w8_0, H0w8_1, H0w8_2, H0w8_3, H0w8_4, H0w8_5, H0w8_6, H0w8_7 (8 elements)
            { Fr::push_dec("10210594730394925429746291702746561332060256679615545074401657104125756649578") }
            { Fr::push_dec("8372804009848668687759614171560040965977592547922202747919047620642117005104") }
            { Fr::push_dec("12018168561098599325315012321442861121728268008555918380929453858170772126806") }
            { Fr::push_dec("16309511826969302107699393610404172200913629782896950912885458723657982725366") }
            { Fr::push_dec("11677648141444349792500114042510713756488107720800489269296547082450051846039") }
            { Fr::push_dec("13515438861990606534486791573697234122570771852493831595779156565933691490513") }
            { Fr::push_dec("9870074310740675896931393423814413966820096391860115962768750328405036368811") }
            { Fr::push_dec("5578731044869973114547012134853102887634734617519083430812745462917825770251") }

            // roll y
            { Fr::roll(8 + 3) }

            // compute numerator entries
            for i in 0..8 {
                { Fr::copy(0) }
                { Fr::roll(7 - i + 2) }
                { Fr::sub(1, 0) }
                { Fr::toaltstack() }
            }

            // drop y
            { Fr::drop() }

            // compute numerator
            { Fr::fromaltstack() }
            for _ in 0..7 {
                { Fr::fromaltstack() }
                { Fr::mul() }
            }

            // copy the numerator in the altstack
            { Fr::copy(0) }
            { Fr::toaltstack() }

            // compute quotient1 = alpha * numerator * denh1
            { Fr::copy(0) }
            { Fr::copy(3 + 2 + 2) }
            { Fr::mul() }
            { Fr::roll(3 + 1 + 2) }
            { Fr::mul() }

            // compute quotient2 = alpha * alpha * numerator * denh2
            { Fr::roll(1) }
            { Fr::roll(3 + 2) }
            { Fr::mul() }
            { Fr::roll(3 + 2) }
            { Fr::square() }
            { Fr::mul() }

            // the stack now looks:
            //    R0, R1, R2
            //    quotient1, quotient2
            // altstack: numerator

            // compute the scalar = R0 + quotient1 * R1 + quotient2 * R2
            { Fr::copy(1) }
            { Fr::roll(2 + 1 + 1) }
            { Fr::mul() }
            { Fr::copy(1) }
            { Fr::roll(2 + 2) }
            { Fr::mul() }
            { Fr::add(1, 0) }
            { Fr::roll(2 + 1) }
            { Fr::add(1, 0) }

            { Fr::fromaltstack() }

            // J scalar
            { Fr::push_dec("1021979267781513382639867303596638615172285308777215242749714941672007413081") }
            { Fr::equalverify(1, 0) }

            // E scalar
            { Fr::push_dec("20939596453786382856662891660365666437489374655427796935463148514894213437967") }
            { Fr::equalverify(1, 0) }

            // F scalar
            { Fr::push_dec("9383905404220215760494220727835590239846562451983646600728203514340336934716") }
            { Fr::equalverify(1, 0) }
            { Fr::push_dec("8336823378405991273186613678056299833572545852849807089784419620701331198620") }
            { Fr::equalverify(1, 0) }

            OP_TRUE
        };

        println!("fflonk.compute_fej_scalars = {} bytes", script.len());

        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }
}
