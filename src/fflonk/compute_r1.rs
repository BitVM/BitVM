#[cfg(test)]
mod test {
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::bn254::fr::Fr;
    use crate::treepp::*;
    use ark_ff::Field;
    use num_bigint::BigUint;
    use std::str::FromStr;

    #[test]
    fn test_compute_r1() {
        let mut zh_inv = ark_bn254::Fr::from_str(
            "9539499652122301619680560867461437153480631573357135330838514610439758374055",
        )
        .unwrap();
        zh_inv.inverse_in_place().unwrap();

        let mut lis1_1_inv = ark_bn254::Fr::from_str(
            "14020133117267276520346758762568130957151367475598025622226445111246020829435",
        )
        .unwrap();
        lis1_1_inv.inverse_in_place().unwrap();

        let mut lis1_2_inv = ark_bn254::Fr::from_str(
            "11834191057204778210308675185625212949005795861807682697825227112830256931177",
        )
        .unwrap();
        lis1_2_inv.inverse_in_place().unwrap();

        let mut lis1_3_inv = ark_bn254::Fr::from_str(
            "20680494190286283051876076168766664571907823653512365023777159976480914701916",
        )
        .unwrap();
        lis1_3_inv.inverse_in_place().unwrap();

        let mut lis1_4_inv = ark_bn254::Fr::from_str(
            "978193378509506139667754000452307491505030866886673604480173788320870104557",
        )
        .unwrap();
        lis1_4_inv.inverse_in_place().unwrap();

        let script = script! {
            // push ql, qr, qm, qo, qc, a, b, c
            { Fr::push_dec("4305584171954448775801758618991977283131671407134816099015723841718827300684") }
            { Fr::push_dec("12383383973686840675128398394454489421896122330596726461131121746926747341189") }
            { Fr::push_dec("84696450614978050680673343346456326547032107368333805624994614151289555853") }
            { Fr::push_dec("3940439340424631873531863239669720717811550024514867065774687720368464792371") }
            { Fr::push_dec("16961785810060156933739931986193776143069216115530808410139185289490606944009") }
            { Fr::push_dec("7211168621666826182043583595845418959530786367587156242724929610231435505336") }
            { Fr::push_dec("848088075173937026388846472327431819307508078325359401333033359624801042") }
            { Fr::push_dec("18963734392470978715233675860777231227480937309534365140504133190694875258320") }

            // push pi, zhInv
            { Fr::push_dec("12368363170870087162509434874521168463460384615249055347885673275750149676873") }
            { Fr::push_u32_le(&BigUint::from(zh_inv).to_u32_digits()) }

            // push H1w4_0, H1w4_1, H1w4_2, H1w4_3
            { Fr::push_dec("1756820407515345004507058825871382296137098363972706405994173662850350774688") }
            { Fr::push_dec("16907152808936898292083477165412732098542037853664649778796264398384084027651") }
            { Fr::push_dec("20131422464323930217739346919385892792411266036443327937704030523725457720929") }
            { Fr::push_dec("4981090062902376930162928579844542990006326546751384564901939788191724467966") }

            // push LiS1Inv 1-4
            { Fr::push_u32_le(&BigUint::from(lis1_1_inv).to_u32_digits()) }
            { Fr::push_u32_le(&BigUint::from(lis1_2_inv).to_u32_digits()) }
            { Fr::push_u32_le(&BigUint::from(lis1_3_inv).to_u32_digits()) }
            { Fr::push_u32_le(&BigUint::from(lis1_4_inv).to_u32_digits()) }

            // push y
            { Fr::push_dec("6824639836122392703554190210911349683223362245243195922653951653214183338070") }
            // push xi
            { Fr::push_dec("14814634099415170872937750660683266261347419959225231219985478027287965492246") }

            // compute num = y^4 - xi, push to altstack
            { Fr::roll(1) }
            { Fr::square() }
            { Fr::square() }
            { Fr::sub(0, 1) }
            { Fr::toaltstack() }

            // compute t0

            // ql * evalA
            { Fr::copy(10 + 7) }
            { Fr::copy(10 + 2 + 1) }
            { Fr::mul() }
            { Fr::toaltstack() }

            // qr * evalB
            { Fr::copy(10 + 6) }
            { Fr::copy(10 + 1 + 1) }
            { Fr::mul() }
            { Fr::toaltstack() }

            // qm * evalA * evalB
            { Fr::copy(10 + 5) }
            { Fr::copy(10 + 2 + 1) }
            { Fr::mul() }
            { Fr::copy(10 + 1 + 1) }
            { Fr::mul() }
            { Fr::toaltstack() }

            // qo * evalC
            { Fr::copy(10 + 4) }
            { Fr::copy(10 + 1) }
            { Fr::mul() }

            // t0 := ql * evalA + qr * evalB + qm * evalA * evalB + qo * evalC + qc + pi
            { Fr::fromaltstack() }
            { Fr::add(1, 0) }
            { Fr::fromaltstack() }
            { Fr::add(1, 0) }
            { Fr::fromaltstack() }
            { Fr::add(1, 0) }
            { Fr::copy(10 + 3 + 1) }
            { Fr::add(1, 0) }
            { Fr::copy(8 + 1 + 1) }
            { Fr::add(1, 0) }

            // t0 := t0 * zhInv
            { Fr::copy(8 + 1) }
            { Fr::mul() }

            // the stack should look like:
            //    ql, qr, qm, qo, qc, a, b, c
            //    pi, zhInv
            //    H1w4_0, H1w4_1, H1w4_2, H1w4_3
            //    LiS1Inv 1-4
            //    t0
            //
            // altstack: num

            // pick H1w4_0, ..., H1w4_3 and compute the corresponding c1Value
            for i in 0..4 {
                { Fr::copy(1 + 4 + 3 - i) }

                { Fr::copy(0) } { Fr::copy(1) } { Fr::mul() }
                { Fr::copy(0) } { Fr::copy(2) } { Fr::mul() }

                for _ in 0..3 {
                    { Fr::toaltstack() }
                }

                // c1Value starts with a
                { Fr::copy(1 + 4 + 4 + 2 + 2) }
                { Fr::copy(1 + 4 + 4 + 2 + 1 + 1) } { Fr::fromaltstack() } { Fr::mul() } { Fr::add(1, 0) }
                { Fr::copy(1 + 4 + 4 + 2 + 1) } { Fr::fromaltstack() } { Fr::mul() } { Fr::add(1, 0) }
                { Fr::copy(1) } { Fr::fromaltstack() } { Fr::mul() } { Fr::add(1, 0) }

                // push this c1Value to the altstack
                { Fr::toaltstack() }
            }

            // get all the c1Values out
            for _ in 0..4 {
                { Fr::fromaltstack() }
            }

            // multiply the corresponding LiS1Inv
            for i in 0..4 {
                { Fr::roll(4 - i + 1 + 3 - i) }
                { Fr::mul() }
                { Fr::toaltstack() }
            }

            // drop all the intermediate values
            for _ in 0..(1 + 4 + 2 + 8) {
                { Fr::drop() }
            }

            // add all the c0Values together
            { Fr::fromaltstack() }
            for _ in 1..4 {
                { Fr::fromaltstack() }
                { Fr::add(1, 0) }
            }

            // multiply by the num
            { Fr::fromaltstack() }
            { Fr::mul() }

            { Fr::push_dec("20094893460628001506464425210304996393341228871437567669976791505614033716878") }
            { Fr::equalverify(1, 0) }
            OP_TRUE
        };

        println!("fflonk.compute_r1 = {} bytes", script.len());

        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }
}
