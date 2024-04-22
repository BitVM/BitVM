#[cfg(test)]
mod test {
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::bn254::fr::Fr;
    use crate::treepp::*;

    #[test]
    fn test_inversions() {
        let script = script! {
            // push Z_H
            { Fr::push_dec("9539499652122301619680560867461437153480631573357135330838514610439758374055") }
            { Fr::toaltstack() }

            // push y
            { Fr::push_dec("6824639836122392703554190210911349683223362245243195922653951653214183338070") }
            // push H1w4_0, H1w4_1, H1w4_2, H1w4_3
            { Fr::push_dec("1756820407515345004507058825871382296137098363972706405994173662850350774688") }
            { Fr::push_dec("16907152808936898292083477165412732098542037853664649778796264398384084027651") }
            { Fr::push_dec("20131422464323930217739346919385892792411266036443327937704030523725457720929") }
            { Fr::push_dec("4981090062902376930162928579844542990006326546751384564901939788191724467966") }

            { Fr::copy(4) }
            { Fr::sub(0, 1) }
            { Fr::copy(4) }
            { Fr::sub(0, 2) }
            { Fr::copy(4) }
            { Fr::sub(0, 3) }
            { Fr::copy(4) }
            { Fr::sub(0, 4) }

            { Fr::mul() }
            { Fr::mul() }
            { Fr::mul() }
            { Fr::toaltstack() }

            // push H2w3_0, H2w3_1, H2w3_2, H3w3_0, H3w3_1, H3w3_2
            { Fr::push_dec("8645910648030292747222447120598663930712351861448151482708581449066841434015") }
            { Fr::push_dec("2196608840183762817611603553419504245649898072887146050087043489198732467688") }
            { Fr::push_dec("11045723383625219657412355071239106912186114466080736810902579248310234593914") }
            { Fr::push_dec("21405568746311661929319138487394095463124289053215849061649274916682085734478") }
            { Fr::push_dec("16458699422327211795980147165837933894457139622322803085568450314170832928180") }
            { Fr::push_dec("5912217575039676719193525837282520819515300125293416540178683142298698328576") }

            { Fr::copy(6) }
            { Fr::sub(0, 1) }
            { Fr::copy(6) }
            { Fr::sub(0, 2) }
            { Fr::copy(6) }
            { Fr::sub(0, 3) }
            { Fr::copy(6) }
            { Fr::sub(0, 4) }
            { Fr::copy(6) }
            { Fr::sub(0, 5) }
            { Fr::copy(6) }
            { Fr::sub(0, 6) }

            { Fr::mul() }
            { Fr::mul() }
            { Fr::mul() }
            { Fr::mul() }
            { Fr::mul() }
            { Fr::toaltstack() }

            // push H0w8_0, H0w8_1, H0w8_2, H0w8_3, H0w8_4, H0w8_5, H0w8_6, H0w8_7
            { Fr::push_dec("10210594730394925429746291702746561332060256679615545074401657104125756649578") }
            { Fr::push_dec("8372804009848668687759614171560040965977592547922202747919047620642117005104") }
            { Fr::push_dec("12018168561098599325315012321442861121728268008555918380929453858170772126806") }
            { Fr::push_dec("16309511826969302107699393610404172200913629782896950912885458723657982725366") }
            { Fr::push_dec("11677648141444349792500114042510713756488107720800489269296547082450051846039") }
            { Fr::push_dec("13515438861990606534486791573697234122570771852493831595779156565933691490513") }
            { Fr::push_dec("9870074310740675896931393423814413966820096391860115962768750328405036368811") }
            { Fr::push_dec("5578731044869973114547012134853102887634734617519083430812745462917825770251") }

            // den1 = Fr.mul(Fr.e(len), Fr.exp(roots[0], len - 2)) = = 8 * H0w8_0 ^ 6
            { Fr::copy(7) }
            { Fr::square() }
            { Fr::copy(0) }
            { Fr::square() }
            { Fr::mul() }
            { Fr::double(0) }
            { Fr::double(0) }
            { Fr::double(0) }
            { Fr::toaltstack() }

            // den2 = roots[7 * 0 % 8] = roots[0]
            { Fr::copy(7) }
            { Fr::toaltstack() }

            // den3 = x - roots[0]
            { Fr::copy(8) }
            { Fr::toaltstack() }
            { Fr::copy(7) }
            { Fr::fromaltstack() }
            { Fr::sub(0, 1) }

            // LiS0_1 = den1 * den2 * den3, keep den1 in the altstack
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::fromaltstack() }
            { Fr::copy(0) }
            { Fr::roll(2) }
            { Fr::mul() }
            { Fr::toaltstack() }
            { Fr::toaltstack() }

            // den2 = roots[7 * 1 % 8] = roots[7]
            { Fr::copy(0) }
            { Fr::toaltstack() }

            // den3 = x - roots[1]
            { Fr::copy(8) }
            { Fr::toaltstack() }
            { Fr::copy(6) }
            { Fr::fromaltstack() }
            { Fr::sub(0, 1) }

            // LiS0_2 = den1 * den2 * den3, keep den1 in the altstack
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::fromaltstack() }
            { Fr::copy(0) }
            { Fr::roll(2) }
            { Fr::mul() }
            { Fr::toaltstack() }
            { Fr::toaltstack() }

            // den2 = roots[7 * 2 % 8] = roots[6]
            { Fr::copy(1) }
            { Fr::toaltstack() }

            // den3 = x - roots[2]
            { Fr::copy(8) }
            { Fr::toaltstack() }
            { Fr::copy(5) }
            { Fr::fromaltstack() }
            { Fr::sub(0, 1) }

            // LiS0_3 = den1 * den2 * den3, keep den1 in the altstack
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::fromaltstack() }
            { Fr::copy(0) }
            { Fr::roll(2) }
            { Fr::mul() }
            { Fr::toaltstack() }
            { Fr::toaltstack() }

            // den2 = roots[7 * 3 % 8] = roots[5]
            { Fr::copy(2) }
            { Fr::toaltstack() }

            // den3 = x - roots[3]
            { Fr::copy(8) }
            { Fr::toaltstack() }
            { Fr::copy(4) }
            { Fr::fromaltstack() }
            { Fr::sub(0, 1) }

            // LiS0_4 = den1 * den2 * den3, keep den1 in the altstack
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::fromaltstack() }
            { Fr::copy(0) }
            { Fr::roll(2) }
            { Fr::mul() }
            { Fr::toaltstack() }
            { Fr::toaltstack() }

            // den2 = roots[7 * 4 % 8] = roots[4]
            { Fr::copy(3) }
            { Fr::toaltstack() }

            // den3 = x - roots[4]
            { Fr::copy(8) }
            { Fr::toaltstack() }
            { Fr::copy(3) }
            { Fr::fromaltstack() }
            { Fr::sub(0, 1) }

            // LiS0_5 = den1 * den2 * den3, keep den1 in the altstack
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::fromaltstack() }
            { Fr::copy(0) }
            { Fr::roll(2) }
            { Fr::mul() }
            { Fr::toaltstack() }
            { Fr::toaltstack() }

            // den2 = roots[7 * 5 % 8] = roots[3]
            { Fr::copy(4) }
            { Fr::toaltstack() }

            // den3 = x - roots[5]
            { Fr::copy(8) }
            { Fr::toaltstack() }
            { Fr::copy(2) }
            { Fr::fromaltstack() }
            { Fr::sub(0, 1) }

            // LiS0_6 = den1 * den2 * den3, keep den1 in the altstack
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::fromaltstack() }
            { Fr::copy(0) }
            { Fr::roll(2) }
            { Fr::mul() }
            { Fr::toaltstack() }
            { Fr::toaltstack() }

            // den2 = roots[7 * 6 % 8] = roots[2]
            { Fr::copy(5) }
            { Fr::toaltstack() }

            // den3 = x - roots[6]
            { Fr::copy(8) }
            { Fr::toaltstack() }
            { Fr::copy(1) }
            { Fr::fromaltstack() }
            { Fr::sub(0, 1) }

            // LiS0_7 = den1 * den2 * den3, keep den1 in the altstack
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::fromaltstack() }
            { Fr::copy(0) }
            { Fr::roll(2) }
            { Fr::mul() }
            { Fr::toaltstack() }
            { Fr::toaltstack() }

            // den2 = roots[7 * 7 % 8] = roots[1]
            { Fr::copy(6) }
            { Fr::toaltstack() }

            // den3 = x - roots[7]
            { Fr::copy(8) }
            { Fr::toaltstack() }
            { Fr::copy(0) }
            { Fr::fromaltstack() }
            { Fr::sub(0, 1) }

            // LiS0_8 = den1 * den2 * den3, remove den1 in the altstack
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::toaltstack() }

            // drop H0w8_0, H0w8_1, H0w8_2, H0w8_3, H0w8_4, H0w8_5, H0w8_6, H0w8_7
            { Fr::drop() }
            { Fr::drop() }
            { Fr::drop() }
            { Fr::drop() }
            { Fr::drop() }
            { Fr::drop() }
            { Fr::drop() }
            { Fr::drop() }

            // push H1w4_0, H1w4_1, H1w4_2, H1w4_3
            { Fr::push_dec("1756820407515345004507058825871382296137098363972706405994173662850350774688") }
            { Fr::push_dec("16907152808936898292083477165412732098542037853664649778796264398384084027651") }
            { Fr::push_dec("20131422464323930217739346919385892792411266036443327937704030523725457720929") }
            { Fr::push_dec("4981090062902376930162928579844542990006326546751384564901939788191724467966") }

            // den1 = Fr.mul(Fr.e(len), Fr.exp(roots[0], len - 2)) = = 4 * H0w8_0 ^ 2
            { Fr::copy(3) }
            { Fr::square() }
            { Fr::double(0) }
            { Fr::double(0) }
            { Fr::toaltstack() }

            // den2 = roots[3 * 0 % 4] = roots[0]
            { Fr::copy(3) }
            { Fr::toaltstack() }

            // den3 = x - roots[0]
            { Fr::copy(4) }
            { Fr::toaltstack() }
            { Fr::copy(3) }
            { Fr::fromaltstack() }
            { Fr::sub(0, 1) }

            // LiS1_1 = den1 * den2 * den3, keep den1 in the altstack
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::fromaltstack() }
            { Fr::copy(0) }
            { Fr::roll(2) }
            { Fr::mul() }
            { Fr::toaltstack() }
            { Fr::toaltstack() }

            // den2 = roots[3 * 1 % 4] = roots[3]
            { Fr::copy(0) }
            { Fr::toaltstack() }

            // den3 = x - roots[1]
            { Fr::copy(4) }
            { Fr::toaltstack() }
            { Fr::copy(2) }
            { Fr::fromaltstack() }
            { Fr::sub(0, 1) }

            // LiS1_2 = den1 * den2 * den3, keep den1 in the altstack
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::fromaltstack() }
            { Fr::copy(0) }
            { Fr::roll(2) }
            { Fr::mul() }
            { Fr::toaltstack() }
            { Fr::toaltstack() }

            // den2 = roots[3 * 2 % 4] = roots[2]
            { Fr::copy(1) }
            { Fr::toaltstack() }

            // den3 = x - roots[2]
            { Fr::copy(4) }
            { Fr::toaltstack() }
            { Fr::copy(1) }
            { Fr::fromaltstack() }
            { Fr::sub(0, 1) }

            // LiS1_3 = den1 * den2 * den3, keep den1 in the altstack
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::fromaltstack() }
            { Fr::copy(0) }
            { Fr::roll(2) }
            { Fr::mul() }
            { Fr::toaltstack() }
            { Fr::toaltstack() }

            // den2 = roots[3 * 3 % 4] = roots[1]
            { Fr::copy(2) }
            { Fr::toaltstack() }

            // den3 = x - roots[3]
            { Fr::copy(4) }
            { Fr::toaltstack() }
            { Fr::copy(0) }
            { Fr::fromaltstack() }
            { Fr::sub(0, 1) }

            // LiS1_4 = den1 * den2 * den3, remove den1 in the altstack
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::toaltstack() }

            // drop H1w4_0, H1w4_1, H1w4_2, H1w4_3
            { Fr::drop() }
            { Fr::drop() }
            { Fr::drop() }
            { Fr::drop() }

            // push H2w3_0, H2w3_1, H2w3_2
            { Fr::push_dec("8645910648030292747222447120598663930712351861448151482708581449066841434015") }
            { Fr::push_dec("2196608840183762817611603553419504245649898072887146050087043489198732467688") }
            { Fr::push_dec("11045723383625219657412355071239106912186114466080736810902579248310234593914") }

            // push xi
            { Fr::push_dec("14814634099415170872937750660683266261347419959225231219985478027287965492246") }

            // compute xiw
            { Fr::copy(0) }
            { Fr::push_dec("11699596668367776675346610687704220591435078791727316319397053191800576917728") }
            { Fr::mul() }

            // compute xi - xiw
            { Fr::sub(1, 0) }
            { Fr::copy(0) }
            { Fr::toaltstack() }

            // move xi - xiw to before y
            { Fr::roll(4) }
            { Fr::roll(4) }
            { Fr::roll(4) }
            { Fr::roll(4) }

            // _3h2 = Fr.mul(Fr.e(len), Fr.exp(roots[0], len - 2)) = = 3 * H2w3_0
            { Fr::copy(2) }
            { Fr::copy(0) }
            { Fr::double(0) }
            { Fr::add(1, 0) }

            // compute den1 = _3h2 * (xi - xiw)
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::toaltstack() }

            // den2 = roots[2 * 0 % 3] = roots[0]
            { Fr::copy(2) }
            { Fr::toaltstack() }

            // den3 = x - roots[0]
            { Fr::copy(3) }
            { Fr::toaltstack() }
            { Fr::copy(2) }
            { Fr::fromaltstack() }
            { Fr::sub(0, 1) }

            // LiS2_1 = den1 * den2 * den3, keep den1 in the altstack
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::fromaltstack() }
            { Fr::copy(0) }
            { Fr::roll(2) }
            { Fr::mul() }
            { Fr::toaltstack() }
            { Fr::toaltstack() }

            // den2 = roots[2 * 1 % 3] = roots[2]
            { Fr::copy(0) }
            { Fr::toaltstack() }

            // den3 = x - roots[1]
            { Fr::copy(3) }
            { Fr::toaltstack() }
            { Fr::copy(1) }
            { Fr::fromaltstack() }
            { Fr::sub(0, 1) }

            // LiS2_2 = den1 * den2 * den3, keep den1 in the altstack
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::fromaltstack() }
            { Fr::copy(0) }
            { Fr::roll(2) }
            { Fr::mul() }
            { Fr::toaltstack() }
            { Fr::toaltstack() }

            // den2 = roots[2 * 2 % 3] = roots[1]
            { Fr::copy(1) }
            { Fr::toaltstack() }

            // den3 = x - roots[2]
            { Fr::copy(3) }
            { Fr::toaltstack() }
            { Fr::copy(0) }
            { Fr::fromaltstack() }
            { Fr::sub(0, 1) }

            // LiS2_3 = den1 * den2 * den3, keep den1 in the altstack
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::toaltstack() }

            // drop H2w3_0, H2w3_1, H2w3_2
            { Fr::drop() }
            { Fr::drop() }
            { Fr::drop() }

            // push H3w3_0, H3w3_1, H3w3_2
            { Fr::push_dec("21405568746311661929319138487394095463124289053215849061649274916682085734478") }
            { Fr::push_dec("16458699422327211795980147165837933894457139622322803085568450314170832928180") }
            { Fr::push_dec("5912217575039676719193525837282520819515300125293416540178683142298698328576") }

            // obtain xiw - xi
            { Fr::neg(4) }
            { Fr::toaltstack() }

            // _3h2 = Fr.mul(Fr.e(len), Fr.exp(roots[0], len - 2)) = = 3 * H3w3_0
            { Fr::copy(2) }
            { Fr::copy(0) }
            { Fr::double(0) }
            { Fr::add(1, 0) }

            // compute den1 = _3h2 * (xiw - xi)
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::toaltstack() }

            // den2 = roots[2 * 0 % 3] = roots[0]
            { Fr::copy(2) }
            { Fr::toaltstack() }

            // den3 = x - roots[0]
            { Fr::copy(3) }
            { Fr::toaltstack() }
            { Fr::copy(2) }
            { Fr::fromaltstack() }
            { Fr::sub(0, 1) }

            // LiS3_1 = den1 * den2 * den3, keep den1 in the altstack
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::fromaltstack() }
            { Fr::copy(0) }
            { Fr::roll(2) }
            { Fr::mul() }
            { Fr::toaltstack() }
            { Fr::toaltstack() }

            // den2 = roots[2 * 1 % 3] = roots[2]
            { Fr::copy(0) }
            { Fr::toaltstack() }

            // den3 = x - roots[1]
            { Fr::copy(3) }
            { Fr::toaltstack() }
            { Fr::copy(1) }
            { Fr::fromaltstack() }
            { Fr::sub(0, 1) }

            // LiS3_2 = den1 * den2 * den3, keep den1 in the altstack
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::fromaltstack() }
            { Fr::copy(0) }
            { Fr::roll(2) }
            { Fr::mul() }
            { Fr::toaltstack() }
            { Fr::toaltstack() }

            // den2 = roots[2 * 2 % 3] = roots[1]
            { Fr::copy(1) }
            { Fr::toaltstack() }

            // den3 = x - roots[2]
            { Fr::copy(3) }
            { Fr::toaltstack() }
            { Fr::copy(0) }
            { Fr::fromaltstack() }
            { Fr::sub(0, 1) }

            // LiS3_3 = den1 * den2 * den3, keep den1 in the altstack
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::toaltstack() }

            // drop H3w3_0, H3w3_1, H3w3_2
            { Fr::drop() }
            { Fr::drop() }
            { Fr::drop() }

            // drop y
            { Fr::drop() }

            // push xi again
            { Fr::push_dec("14814634099415170872937750660683266261347419959225231219985478027287965492246") }

            // Li_1 = 262144 * (xi - 1)
            { Fr::copy(0) }
            { Fr::push_one() }
            { Fr::sub(1, 0) }
            { Fr::push_dec("262144") }
            { Fr::mul() }
            { Fr::toaltstack() }

            // Li_2 = 262144 * (xi - w1)
            { Fr::push_dec("11699596668367776675346610687704220591435078791727316319397053191800576917728") }
            { Fr::sub(1, 0) }
            { Fr::push_dec("262144") }
            { Fr::mul() }
            { Fr::toaltstack() }

            // Get all the elements back to the stack
            for _ in 0..23 {
                { Fr::fromaltstack() }
            }

            // build up the accumulator
            { Fr::copy(0) }
            for i in 1..23 {
                { Fr::copy(0) }
                { Fr::copy(i + 1 + i) }
                { Fr::mul() }
            }

            // push the inv from the proof and verify the inv
            { Fr::copy(0) }
            { Fr::push_dec("21247383512588455895834686692756529012394058115069710447132959660051940541361") }
            { Fr::copy(0) } { Fr::toaltstack() }
            { Fr::mul() }
            { Fr::is_one(0) }
            OP_VERIFY
            { Fr::drop() } // is_one does not consume the input

            // current stack:
            //   inputs (Li_2 down to ZH)
            //   accumulators (ZH down to prod of all)
            // altstack:
            //   inv

            // compute the inverses now
            { Fr::drop() }
            { Fr::fromaltstack() }

            for i in 0..22 {
                { Fr::copy(0) }
                { Fr::roll(2) }
                { Fr::mul() }
                { Fr::toaltstack() }
                { Fr::roll(23 - 1 - i + 23 - 1 - i) }
                { Fr::mul() }
            }
            { Fr::roll(1) }
            { Fr::drop() }

            // ZH
            { Fr::push_dec("9539499652122301619680560867461437153480631573357135330838514610439758374055") }
            { Fr::mul() }
            { Fr::is_one(0) }
            OP_VERIFY
            { Fr::drop() } // is_one does not consume the input

            // DenH1
            { Fr::fromaltstack() }
            { Fr::push_dec("16119335534554612347069410224124107110204763328009905428743152543535476039579") }
            { Fr::mul() }
            { Fr::is_one(0) }
            OP_VERIFY
            { Fr::drop() } // is_one does not consume the input

            // DenH2
            { Fr::fromaltstack() }
            { Fr::push_dec("3243830272143196976292614075227959624327946119988523541753598495438231730971") }
            { Fr::mul() }
            { Fr::is_one(0) }
            OP_VERIFY
            { Fr::drop() } // is_one does not consume the input

            // LiS0_1
            { Fr::fromaltstack() }
            { Fr::push_dec("15956404548953753015502565241304679000484076548059581562924872764096813859245") }
            { Fr::mul() }
            { Fr::is_one(0) }
            OP_VERIFY
            { Fr::drop() } // is_one does not consume the input

            // LiS0_2
            { Fr::fromaltstack() }
            { Fr::push_dec("9114366468980522899431022597914765424075108533625127448987363134676737768036") }
            { Fr::mul() }
            { Fr::is_one(0) }
            OP_VERIFY
            { Fr::drop() } // is_one does not consume the input

            // LiS0_3
            { Fr::fromaltstack() }
            { Fr::push_dec("4805205350560837475207388792928996841502521120538573943461389657486975511196") }
            { Fr::mul() }
            { Fr::is_one(0) }
            OP_VERIFY
            { Fr::drop() } // is_one does not consume the input

            // LiS0_4
            { Fr::fromaltstack() }
            { Fr::push_dec("10337098495972798453045437161191603828214396074717644472335031854871930659950") }
            { Fr::mul() }
            { Fr::is_one(0) }
            OP_VERIFY
            { Fr::drop() } // is_one does not consume the input

            // LiS0_5
            { Fr::fromaltstack() }
            { Fr::push_dec("9668364322474815684450293130850361880537576909329131041685929038205440212223") }
            { Fr::mul() }
            { Fr::is_one(0) }
            OP_VERIFY
            { Fr::drop() } // is_one does not consume the input

            // LiS0_6
            { Fr::fromaltstack() }
            { Fr::push_dec("16510402402448045800521835774240275456946544923763585155623438667625516303432") }
            { Fr::mul() }
            { Fr::is_one(0) }
            OP_VERIFY
            { Fr::drop() } // is_one does not consume the input

            // LiS0_7
            { Fr::fromaltstack() }
            { Fr::push_dec("20819563520867731224745469579226044039519132336850138661149412144815278560272") }
            { Fr::mul() }
            { Fr::is_one(0) }
            OP_VERIFY
            { Fr::drop() } // is_one does not consume the input

            // LiS0_8
            { Fr::fromaltstack() }
            { Fr::push_dec("15287670375455770246907421210963437052807257382671068132275769947430323411518") }
            { Fr::mul() }
            { Fr::is_one(0) }
            OP_VERIFY
            { Fr::drop() } // is_one does not consume the input

            // LiS1_1
            { Fr::fromaltstack() }
            { Fr::push_dec("14020133117267276520346758762568130957151367475598025622226445111246020829435") }
            { Fr::mul() }
            { Fr::is_one(0) }
            OP_VERIFY
            { Fr::drop() } // is_one does not consume the input

            // LiS1_2
            { Fr::fromaltstack() }
            { Fr::push_dec("11834191057204778210308675185625212949005795861807682697825227112830256931177") }
            { Fr::mul() }
            { Fr::is_one(0) }
            OP_VERIFY
            { Fr::drop() } // is_one does not consume the input

            // LiS1_3
            { Fr::fromaltstack() }
            { Fr::push_dec("20680494190286283051876076168766664571907823653512365023777159976480914701916") }
            { Fr::mul() }
            { Fr::is_one(0) }
            OP_VERIFY
            { Fr::drop() } // is_one does not consume the input

             // LiS1_4
            { Fr::fromaltstack() }
            { Fr::push_dec("978193378509506139667754000452307491505030866886673604480173788320870104557") }
            { Fr::mul() }
            { Fr::is_one(0) }
            OP_VERIFY
            { Fr::drop() } // is_one does not consume the input

            // LiS2_1
            { Fr::fromaltstack() }
            { Fr::push_dec("3093337848584598859019239395285698636013991558183047188123490283901254813860") }
            { Fr::mul() }
            { Fr::is_one(0) }
            OP_VERIFY
            { Fr::drop() } // is_one does not consume the input

            // LiS2_2
            { Fr::fromaltstack() }
            { Fr::push_dec("20657040851814184192491101400192407860657376306604707917505085770367913835835") }
            { Fr::mul() }
            { Fr::is_one(0) }
            OP_VERIFY
            { Fr::drop() } // is_one does not consume the input

            // LiS2_3
            { Fr::fromaltstack() }
            { Fr::push_dec("19967358551509656347901544077253903207276114223653090077162230657486295778552") }
            { Fr::mul() }
            { Fr::is_one(0) }
            OP_VERIFY
            { Fr::drop() } // is_one does not consume the input

            // LiS2_4
            { Fr::fromaltstack() }
            { Fr::push_dec("21800223472280064353933220303685416010271075398742978562230724357473593460561") }
            { Fr::mul() }
            { Fr::is_one(0) }
            OP_VERIFY
            { Fr::drop() } // is_one does not consume the input

            // LiS2_5
            { Fr::fromaltstack() }
            { Fr::push_dec("2883351026271900821141854554977492864766487799404625079971870711410039053769") }
            { Fr::mul() }
            { Fr::is_one(0) }
            OP_VERIFY
            { Fr::drop() } // is_one does not consume the input

            // LiS2_6
            { Fr::fromaltstack() }
            { Fr::push_dec("9551022927007589928168012516897412879701840127652630952681115227109825028798") }
            { Fr::mul() }
            { Fr::is_one(0) }
            OP_VERIFY
            { Fr::drop() } // is_one does not consume the input

            // Li_1
            { Fr::fromaltstack() }
            { Fr::push_dec("2173335263468457880677030391603678787407318523287432531877773790452047235821") }
            { Fr::mul() }
            { Fr::is_one(0) }
            OP_VERIFY
            { Fr::drop() } // is_one does not consume the input

            // Li_2
            { Fr::fromaltstack() }
            { Fr::push_dec("3695504780263816985137938305786365026932326252410439503136485422302932463173") }
            { Fr::mul() }
            { Fr::is_one(0) }
            OP_VERIFY
            { Fr::drop() } // is_one does not consume the input

            OP_TRUE
        };

        println!("fflonk.compute_inversions = {} bytes", script.len());

        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }
}
