#[cfg(test)]
mod test {
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::bn254::fr::Fr;
    use crate::treepp::*;
    use ark_ff::Field;
    use num_bigint::BigUint;
    use std::str::FromStr;

    #[test]
    fn test_compute_r0() {
        let mut lis0_1_inv = ark_bn254::Fr::from_str(
            "15956404548953753015502565241304679000484076548059581562924872764096813859245",
        )
        .unwrap();
        lis0_1_inv.inverse_in_place().unwrap();

        let mut lis0_2_inv = ark_bn254::Fr::from_str(
            "9114366468980522899431022597914765424075108533625127448987363134676737768036",
        )
        .unwrap();
        lis0_2_inv.inverse_in_place().unwrap();

        let mut lis0_3_inv = ark_bn254::Fr::from_str(
            "4805205350560837475207388792928996841502521120538573943461389657486975511196",
        )
        .unwrap();
        lis0_3_inv.inverse_in_place().unwrap();

        let mut lis0_4_inv = ark_bn254::Fr::from_str(
            "10337098495972798453045437161191603828214396074717644472335031854871930659950",
        )
        .unwrap();
        lis0_4_inv.inverse_in_place().unwrap();

        let mut lis0_5_inv = ark_bn254::Fr::from_str(
            "9668364322474815684450293130850361880537576909329131041685929038205440212223",
        )
        .unwrap();
        lis0_5_inv.inverse_in_place().unwrap();

        let mut lis0_6_inv = ark_bn254::Fr::from_str(
            "16510402402448045800521835774240275456946544923763585155623438667625516303432",
        )
        .unwrap();
        lis0_6_inv.inverse_in_place().unwrap();

        let mut lis0_7_inv = ark_bn254::Fr::from_str(
            "20819563520867731224745469579226044039519132336850138661149412144815278560272",
        )
        .unwrap();
        lis0_7_inv.inverse_in_place().unwrap();

        let mut lis0_8_inv = ark_bn254::Fr::from_str(
            "15287670375455770246907421210963437052807257382671068132275769947430323411518",
        )
        .unwrap();
        lis0_8_inv.inverse_in_place().unwrap();

        let script = script! {
            // push ql, qr, qo, qm, qc, s1, s2, s3 evaluations
            // be careful: qo is before qm here
            { Fr::push_dec("4305584171954448775801758618991977283131671407134816099015723841718827300684") }
            { Fr::push_dec("12383383973686840675128398394454489421896122330596726461131121746926747341189") }
            { Fr::push_dec("3940439340424631873531863239669720717811550024514867065774687720368464792371") }
            { Fr::push_dec("84696450614978050680673343346456326547032107368333805624994614151289555853") }
            { Fr::push_dec("16961785810060156933739931986193776143069216115530808410139185289490606944009") }
            { Fr::push_dec("12474437127153975801320290893919924661315458586210754316226946498711086665749") }
            { Fr::push_dec("599434615255095347665395089945860172292558760398201299457995057871688253664") }
            { Fr::push_dec("16217604511932175446614838218599989473511950977205890369538297955449224727219") }

            // push H0w8_0, H0w8_1, H0w8_2, H0w8_3, H0w8_4, H0w8_5, H0w8_6, H0w8_7
            { Fr::push_dec("10210594730394925429746291702746561332060256679615545074401657104125756649578") }
            { Fr::push_dec("8372804009848668687759614171560040965977592547922202747919047620642117005104") }
            { Fr::push_dec("12018168561098599325315012321442861121728268008555918380929453858170772126806") }
            { Fr::push_dec("16309511826969302107699393610404172200913629782896950912885458723657982725366") }
            { Fr::push_dec("11677648141444349792500114042510713756488107720800489269296547082450051846039") }
            { Fr::push_dec("13515438861990606534486791573697234122570771852493831595779156565933691490513") }
            { Fr::push_dec("9870074310740675896931393423814413966820096391860115962768750328405036368811") }
            { Fr::push_dec("5578731044869973114547012134853102887634734617519083430812745462917825770251") }

            // push LiS0Inv 1-8
            { Fr::push_u32_le(&BigUint::from(lis0_1_inv).to_u32_digits()) }
            { Fr::push_u32_le(&BigUint::from(lis0_2_inv).to_u32_digits()) }
            { Fr::push_u32_le(&BigUint::from(lis0_3_inv).to_u32_digits()) }
            { Fr::push_u32_le(&BigUint::from(lis0_4_inv).to_u32_digits()) }
            { Fr::push_u32_le(&BigUint::from(lis0_5_inv).to_u32_digits()) }
            { Fr::push_u32_le(&BigUint::from(lis0_6_inv).to_u32_digits()) }
            { Fr::push_u32_le(&BigUint::from(lis0_7_inv).to_u32_digits()) }
            { Fr::push_u32_le(&BigUint::from(lis0_8_inv).to_u32_digits()) }

            // push y
            { Fr::push_dec("6824639836122392703554190210911349683223362245243195922653951653214183338070") }
            // push xi
            { Fr::push_dec("14814634099415170872937750660683266261347419959225231219985478027287965492246") }

            // compute num = y^8 - xi, push to altstack
            { Fr::roll(1) }
            { Fr::square() }
            { Fr::square() }
            { Fr::square() }
            { Fr::sub(0, 1) }
            { Fr::toaltstack() }

            // pick H0w8_0, ..., H0w8_7 and compute the corresponding c0Value
            for i in 0..8 {
                { Fr::copy(8 + 7 - i) }

                { Fr::copy(0) } { Fr::copy(1) } { Fr::mul() }
                { Fr::copy(0) } { Fr::copy(2) } { Fr::mul() }
                { Fr::copy(0) } { Fr::copy(3) } { Fr::mul() }
                { Fr::copy(0) } { Fr::copy(4) } { Fr::mul() }
                { Fr::copy(0) } { Fr::copy(5) } { Fr::mul() }
                { Fr::copy(0) } { Fr::copy(6) } { Fr::mul() }

                for _ in 0..7 {
                    { Fr::toaltstack() }
                }

                // c0Value starts with ql
                { Fr::copy(16 + 7) }
                { Fr::copy(16 + 6 + 1) } { Fr::fromaltstack() } { Fr::mul() } { Fr::add(1, 0) }
                { Fr::copy(16 + 5 + 1) } { Fr::fromaltstack() } { Fr::mul() } { Fr::add(1, 0) }
                { Fr::copy(16 + 4 + 1) } { Fr::fromaltstack() } { Fr::mul() } { Fr::add(1, 0) }
                { Fr::copy(16 + 3 + 1) } { Fr::fromaltstack() } { Fr::mul() } { Fr::add(1, 0) }
                { Fr::copy(16 + 2 + 1) } { Fr::fromaltstack() } { Fr::mul() } { Fr::add(1, 0) }
                { Fr::copy(16 + 1 + 1) } { Fr::fromaltstack() } { Fr::mul() } { Fr::add(1, 0) }
                { Fr::copy(16 + 0 + 1) } { Fr::fromaltstack() } { Fr::mul() } { Fr::add(1, 0) }

                // push this c0Value to the altstack
                { Fr::toaltstack() }
            }

            // get all the c0Values out
            for _ in 0..8 {
                { Fr::fromaltstack() }
            }

            // multiply the corresponding LiS0Inv
            for i in 0..8 {
                { Fr::roll(8 - i + 7 - i) }
                { Fr::mul() }
                { Fr::toaltstack() }
            }

            // drop all the intermediate values
            for _ in 0..16 {
                { Fr::drop() }
            }

            // add all the c0Values together
            { Fr::fromaltstack() }
            for _ in 1..8 {
                { Fr::fromaltstack() }
                { Fr::add(1, 0) }
            }

            // multiply by the num
            { Fr::fromaltstack() }
            { Fr::mul() }

            { Fr::push_dec("9984215396403043994941496429066900252890008119992652401049849633408576425336") }
            { Fr::equalverify(1, 0) }
            OP_TRUE
        };

        println!("fflonk.compute_r0 = {} bytes", script.len());

        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }
}
