#[cfg(test)]
mod test {
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::bn254::fr::Fr;
    use crate::treepp::*;
    use ark_ff::Field;
    use num_bigint::BigUint;
    use std::str::FromStr;

    #[test]
    fn test_compute_r2() {
        let mut zh_inv = ark_bn254::Fr::from_str(
            "9539499652122301619680560867461437153480631573357135330838514610439758374055",
        )
        .unwrap();
        zh_inv.inverse_in_place().unwrap();

        let mut lis2_1_inv = ark_bn254::Fr::from_str(
            "3093337848584598859019239395285698636013991558183047188123490283901254813860",
        )
        .unwrap();
        lis2_1_inv.inverse_in_place().unwrap();

        let mut lis2_2_inv = ark_bn254::Fr::from_str(
            "20657040851814184192491101400192407860657376306604707917505085770367913835835",
        )
        .unwrap();
        lis2_2_inv.inverse_in_place().unwrap();

        let mut lis2_3_inv = ark_bn254::Fr::from_str(
            "19967358551509656347901544077253903207276114223653090077162230657486295778552",
        )
        .unwrap();
        lis2_3_inv.inverse_in_place().unwrap();

        let mut lis2_4_inv = ark_bn254::Fr::from_str(
            "21800223472280064353933220303685416010271075398742978562230724357473593460561",
        )
        .unwrap();
        lis2_4_inv.inverse_in_place().unwrap();

        let mut lis2_5_inv = ark_bn254::Fr::from_str(
            "2883351026271900821141854554977492864766487799404625079971870711410039053769",
        )
        .unwrap();
        lis2_5_inv.inverse_in_place().unwrap();

        let mut lis2_6_inv = ark_bn254::Fr::from_str(
            "9551022927007589928168012516897412879701840127652630952681115227109825028798",
        )
        .unwrap();
        lis2_6_inv.inverse_in_place().unwrap();

        let script = script! {
            // push a, b, c, z, zw, s1, s2, s3, t1w, t2w (10 elements)
            { Fr::push_dec("7211168621666826182043583595845418959530786367587156242724929610231435505336") }
            { Fr::push_dec("848088075173937026388846472327431819307508078325359401333033359624801042") }
            { Fr::push_dec("18963734392470978715233675860777231227480937309534365140504133190694875258320") }
            { Fr::push_dec("2427313569771756255376235777000596702684056445296844486767054635200432142794") }
            { Fr::push_dec("8690328511114991742730387856275843464438882369629727414507275814599493141660") }
            { Fr::push_dec("12474437127153975801320290893919924661315458586210754316226946498711086665749") }
            { Fr::push_dec("599434615255095347665395089945860172292558760398201299457995057871688253664") }
            { Fr::push_dec("16217604511932175446614838218599989473511950977205890369538297955449224727219") }
            { Fr::push_dec("20786626696833495453279531623626288211765949258916047124642669459480728122908") }
            { Fr::push_dec("12092130080251498309415337127155404037148503145602589831662396526189421234148") }

            // push beta, y, xi, gamma, zhinv, L[1] which is from computeLagrange (6 elements)
            { Fr::push_dec("485596931070696584921673007746559446164232583596250406637950679013042540061")}
            { Fr::push_dec("6824639836122392703554190210911349683223362245243195922653951653214183338070") }
            { Fr::push_dec("14814634099415170872937750660683266261347419959225231219985478027287965492246") }
            { Fr::push_dec("19250037324033436581569284153336383290774316882310310865823706333327285195728") }
            { Fr::push_u32_le(&BigUint::from(zh_inv).to_u32_digits()) }
            { Fr::push_dec("19264250262515049392118907974032894668050943806280011767302681470321758079402") }

            // push H2w3_0, H2w3_1, H2w3_2, H3w3_0, H3w3_1, H3w3_2 (6 elements)
            { Fr::push_dec("8645910648030292747222447120598663930712351861448151482708581449066841434015") }
            { Fr::push_dec("2196608840183762817611603553419504245649898072887146050087043489198732467688") }
            { Fr::push_dec("11045723383625219657412355071239106912186114466080736810902579248310234593914") }
            { Fr::push_dec("21405568746311661929319138487394095463124289053215849061649274916682085734478") }
            { Fr::push_dec("16458699422327211795980147165837933894457139622322803085568450314170832928180") }
            { Fr::push_dec("5912217575039676719193525837282520819515300125293416540178683142298698328576") }

            // push LiS2Inv 1-6 (6 elements)
            { Fr::push_u32_le(&BigUint::from(lis2_1_inv).to_u32_digits()) }
            { Fr::push_u32_le(&BigUint::from(lis2_2_inv).to_u32_digits()) }
            { Fr::push_u32_le(&BigUint::from(lis2_3_inv).to_u32_digits()) }
            { Fr::push_u32_le(&BigUint::from(lis2_4_inv).to_u32_digits()) }
            { Fr::push_u32_le(&BigUint::from(lis2_5_inv).to_u32_digits()) }
            { Fr::push_u32_le(&BigUint::from(lis2_6_inv).to_u32_digits()) }

            // compute num2 := y^3
            { Fr::copy(6 + 6 + 4) }
            { Fr::copy(0) }
            { Fr::square() }
            { Fr::mul() }

            // compute num := num2^2 = y^6
            { Fr::copy(0) }
            { Fr::square() }

            // compute xi * w1 + xi = xi * (w1 + 1)
            { Fr::copy(6 + 6 + 3 + 2) }
            { Fr::push_dec("11699596668367776675346610687704220591435078791727316319397053191800576917728") }
            { Fr::push_one() }
            { Fr::add(1, 0) }
            { Fr::mul() }

            // compute num2 := num2 * (xi * (w1 + 1))
            { Fr::roll(2) }
            { Fr::mul() }

            // compute num := num - num2
            { Fr::sub(1, 0) }

            // compute xi^2 * w1
            { Fr::copy(6 + 6 + 3 + 1) }
            { Fr::square() }
            { Fr::push_dec("11699596668367776675346610687704220591435078791727316319397053191800576917728") }
            { Fr::mul() }

            // compute num := num +  xi^2 * w1 and move to altstack
            { Fr::add(1, 0) }
            { Fr::toaltstack() }

            // compute betaxi
            { Fr::copy(6 + 6 + 5) }
            { Fr::copy(6 + 6 + 3 + 1) }
            { Fr::mul() }

            // compute betaxi + gamma
            { Fr::copy(0) }
            { Fr::copy(6 + 6 + 2 + 2) }
            { Fr::add(1, 0) }

            // compute a + betaxi + gamma and send to altstack
            { Fr::copy(6 + 6 + 6 + 9 + 2) }
            { Fr::add(1, 0) }
            { Fr::toaltstack() }

            // compute betaxi * k1 + gamma for k1 = 2
            { Fr::copy(0) }
            { Fr::double(0) }
            { Fr::copy(6 + 6 + 2 + 2) }
            { Fr::add(1, 0) }

            // compute b + betaxi * k1 + gamma and send to altstack
            { Fr::copy(6 + 6 + 6 + 8 + 2) }
            { Fr::add(1, 0) }
            { Fr::toaltstack() }

            // compute betaxi * k2 + gamma for k2 = 3
            { Fr::copy(0) }
            { Fr::double(0) }
            { Fr::add(1, 0) }
            { Fr::copy(6 + 6 + 2 + 1) }
            { Fr::add(1, 0) }

            // compute c + betaxi * k2 + gamma and send to altstack
            { Fr::copy(6 + 6 + 6 + 7 + 1) }
            { Fr::add(1, 0) }

            // compute t2 = (a + betaxi + gamma) * (b + betaxi * k1 + gamma) * (c + betaxi * k2 + gamma) * z
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::copy(6 + 6 + 6 + 6 + 1) }
            { Fr::mul() }

            // send t2 to the altstack
            { Fr::toaltstack() }

            // compute beta * s1 + gamma + a
            { Fr::copy(6 + 6 + 5) }
            { Fr::copy(6 + 6 + 6 + 4 + 1) }
            { Fr::mul() }
            { Fr::copy(6 + 6 + 2 + 1) }
            { Fr::add(1, 0) }
            { Fr::copy(6 + 6 + 6 + 9 + 1) }
            { Fr::add(1, 0) }
            { Fr::toaltstack() }

            // compute beta * s2 + gamma + b
            { Fr::copy(6 + 6 + 5) }
            { Fr::copy(6 + 6 + 6 + 3 + 1) }
            { Fr::mul() }
            { Fr::copy(6 + 6 + 2 + 1) }
            { Fr::add(1, 0) }
            { Fr::copy(6 + 6 + 6 + 8 + 1) }
            { Fr::add(1, 0) }
            { Fr::toaltstack() }

            // compute beta * s3 + gamma + c
            { Fr::copy(6 + 6 + 5) }
            { Fr::copy(6 + 6 + 6 + 2 + 1) }
            { Fr::mul() }
            { Fr::copy(6 + 6 + 2 + 1) }
            { Fr::add(1, 0) }
            { Fr::copy(6 + 6 + 6 + 7 + 1) }
            { Fr::add(1, 0) }

            // compute t2' = (beta * s1 + gamma + a) * (beta * s2 + gamma + b) * (beta * s3 + gamma + c) * zw
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::copy(6 + 6 + 6 + 5 + 1) }
            { Fr::mul() }

            // compute t2 := t2 - t2'
            { Fr::fromaltstack() }
            { Fr::sub(0, 1) }

            // compute t2 := t2 * zhinv
            { Fr::copy(6 + 6 + 1 + 1) }
            { Fr::mul() }

            // send the updated t2 to the altstack
            { Fr::toaltstack() }

            // compute t1 = (z - 1) * L[1] * zhinv
            { Fr::copy(6 + 6 + 6 + 6) }
            { Fr::push_one() }
            { Fr::sub(1, 0) }
            { Fr::copy(6 + 6 + 1) }
            { Fr::mul() }
            { Fr::copy(6 + 6 + 1 + 1) }
            { Fr::mul() }

            // pull t2 from the altstack
            { Fr::fromaltstack() }

            // the stack now looks:
            //   10 + 6 + 6 + 6 Fr elements
            //   t1
            //   t2
            // altstack: num

            // pick H2w3_0, ..., H2w3_2 and compute the corresponding c2Value
            for i in 0..3 {
                { Fr::copy(2 + 6 + 5 - i) }

                { Fr::copy(0) } { Fr::square() }
                { Fr::toaltstack() } { Fr::toaltstack() }

                // c2Value starts with z
                { Fr::copy(2 + 6 + 6 + 6 + 6) }
                { Fr::copy(1 + 1) } { Fr::fromaltstack() } { Fr::mul() } { Fr::add(1, 0) }
                { Fr::copy(0 + 1) } { Fr::fromaltstack() } { Fr::mul() } { Fr::add(1, 0) }

                // push this c2Value to the altstack
                { Fr::toaltstack() }
            }

            // pick H3w3_0, ..., H3w3_2 and compute the corresponding c2Value
            for i in 0..3 {
                { Fr::copy(2 + 6 + 2 - i) }

                { Fr::copy(0) } { Fr::square() }
                { Fr::toaltstack() } { Fr::toaltstack() }

                // c2Value starts with zw
                { Fr::copy(2 + 6 + 6 + 6 + 5) }
                { Fr::copy(2 + 6 + 6 + 6 + 1 + 1) } { Fr::fromaltstack() } { Fr::mul() } { Fr::add(1, 0) }
                { Fr::copy(2 + 6 + 6 + 6 + 0 + 1) } { Fr::fromaltstack() } { Fr::mul() } { Fr::add(1, 0) }

                // push this c2Value to the altstack
                { Fr::toaltstack() }
            }

            // get all the c1Values out
            for _ in 0..6 {
                { Fr::fromaltstack() }
            }

            // multiply the corresponding LiS1Inv
            for i in 0..6 {
                { Fr::roll(6 - i + 2 + 5 - i) }
                { Fr::mul() }
                { Fr::toaltstack() }
            }

            // drop all the intermediate values
            for _ in 0..(2 + 6 + 6 + 10) {
                { Fr::drop() }
            }

            // add all the c0Values together
            { Fr::fromaltstack() }
            for _ in 1..6 {
                { Fr::fromaltstack() }
                { Fr::add(1, 0) }
            }

            // multiply by the num
            { Fr::fromaltstack() }
            { Fr::mul() }

            { Fr::push_dec("17870878740602377735172834182794916404148892013933556022942404950055827532212") }
            { Fr::equalverify(1, 0) }
            OP_TRUE
        };

        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }
}
