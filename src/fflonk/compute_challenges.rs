#[cfg(test)]
mod test {
    use crate::bn254::curves::G1Affine;
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::bn254::fq::Fq;
    use crate::bn254::fr::Fr;
    use crate::hash::blake3::blake3_var_length;
    use crate::treepp::*;

    #[test]
    fn test_compute_challenges_beta() {
        let blake3_script = blake3_var_length(128);

        let script = script! {
            // push C0
            { Fq::push_dec("303039279492065453055049758769758984569666029850327527958551993331680103359")}
            { Fq::push_dec("15061669176783843627135305167141360334623983780813847469326507992811672859575")}
            // push the public input
            { Fq::push_dec("246513590391103489634602289097178521809") }
            { Fq::push_dec("138371009144214353742010089705444713455") }
            // push C1
            { Fq::push_dec("8993820735255461694205287896466659762517378169680151817278189507219986014273") }
            { Fq::push_dec("20608602847008036615737932995836476570376266531776948091942386633580114403199") }

            // send C0 to altstack
            { Fq::roll(4) } { Fq::toaltstack() }
            { Fq::roll(4) } { Fq::toaltstack() }

            // send the public input to altstack
            { Fq::roll(3) } { Fq::toaltstack() }
            { Fq::roll(2) } { Fq::toaltstack() }

            // convert C1 into bytes
            { G1Affine::convert_to_compressed() }

            // convert the public input into bytes
            { Fq::fromaltstack() } { Fq::convert_to_be_bytes() }
            { Fq::fromaltstack() } { Fq::convert_to_be_bytes() }

            // convert C0 into bytes
            { Fq::fromaltstack() } { Fq::fromaltstack() }
            { G1Affine::convert_to_compressed() }

            // compute the hash
            {blake3_script.clone()}
            { Fr::from_hash() }
            { Fr::push_dec("485596931070696584921673007746559446164232583596250406637950679013042540061")}
            { Fr::equal(1, 0) }
        };

        println!("fflonk.compute_challenges.beta = {} bytes", script.len());

        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_compute_challenges_gamma() {
        let blake3_script = blake3_var_length(32);

        let script = script! {
            { Fr::push_dec("485596931070696584921673007746559446164232583596250406637950679013042540061")}
            { Fr::convert_to_be_bytes() }
            {blake3_script.clone()}
            { Fr::from_hash() }
            { Fr::push_dec("19250037324033436581569284153336383290774316882310310865823706333327285195728") }
            { Fr::equal(1, 0) }
        };

        println!("fflonk.compute_challenges.gamma = {} bytes", script.len());

        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_compute_challenges_alpha() {
        let blake3_script = blake3_var_length(512);

        let script = script! {
            // push xi seed
            { Fr::push_dec("12675309311304482509247823029963782393309524866265275290730041635615278736000") }

            // push the polynomial evaluations

            // ql
            { Fr::push_dec("4305584171954448775801758618991977283131671407134816099015723841718827300684") }

            // qr
            { Fr::push_dec("12383383973686840675128398394454489421896122330596726461131121746926747341189") }

            // qm
            { Fr::push_dec("84696450614978050680673343346456326547032107368333805624994614151289555853") }

            // qo
            { Fr::push_dec("3940439340424631873531863239669720717811550024514867065774687720368464792371") }

            // qc
            { Fr::push_dec("16961785810060156933739931986193776143069216115530808410139185289490606944009") }

            // s1
            { Fr::push_dec("12474437127153975801320290893919924661315458586210754316226946498711086665749") }

            // s2
            { Fr::push_dec("599434615255095347665395089945860172292558760398201299457995057871688253664") }

            // s3
            { Fr::push_dec("16217604511932175446614838218599989473511950977205890369538297955449224727219") }

            // a
            { Fr::push_dec("7211168621666826182043583595845418959530786367587156242724929610231435505336") }

            // b
            { Fr::push_dec("848088075173937026388846472327431819307508078325359401333033359624801042") }

            // c
            { Fr::push_dec("18963734392470978715233675860777231227480937309534365140504133190694875258320") }

            // z
            { Fr::push_dec("2427313569771756255376235777000596702684056445296844486767054635200432142794") }

            // zw
            { Fr::push_dec("8690328511114991742730387856275843464438882369629727414507275814599493141660") }

            // t1w
            { Fr::push_dec("20786626696833495453279531623626288211765949258916047124642669459480728122908") }

            // t2w
            { Fr::push_dec("12092130080251498309415337127155404037148503145602589831662396526189421234148") }

            for i in 1..16 {
                { Fr::roll(16 - i) } { Fr::toaltstack() }
            }

            { Fr::convert_to_be_bytes() }

            for _ in 0..15 {
                { Fr::fromaltstack() } { Fr::convert_to_be_bytes() }
            }

            {blake3_script.clone()}
            { Fr::from_hash() }
            { Fr::push_dec("13196272401875304388921830696024531900252495617961467853893732289110815791950") }
            { Fr::equal(1, 0) }
        };

        println!("fflonk.compute_challenges.alpha = {} bytes", script.len());

        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_compute_challenges_y() {
        let blake3_script = blake3_var_length(64);

        let script = script! {
            // alpha
            { Fr::push_dec("13196272401875304388921830696024531900252495617961467853893732289110815791950") }
            // W1
            { Fr::push_dec("32650538602400348219903702316313439265244325226254563471430382441955222030") }
            { Fr::push_dec("1102261574488401129043229793384018650738538286437537952751903719159654317199") }

            { Fr::roll(2) }
            { Fr::toaltstack() }

            { G1Affine::convert_to_compressed() }
            { Fr::fromaltstack() }
            { Fr::convert_to_be_bytes() }

            {blake3_script.clone()}
            { Fr::from_hash() }
            { Fr::push_dec("6824639836122392703554190210911349683223362245243195922653951653214183338070") }
            { Fr::equal(1, 0) }
        };

        println!("fflonk.compute_challenges.y = {} bytes", script.len());

        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_compute_challenges_xiseed() {
        let blake3_script = blake3_var_length(64);

        let script = script! {
            // gamma
            { Fr::push_dec("19250037324033436581569284153336383290774316882310310865823706333327285195728") }
            // C2
            { Fr::push_dec("7381325072443970270370678023564870071058744625357849943766655609499175274412") }
            { Fr::push_dec("15178578915928592705383893120230835636411008017183180871962629962483134367891") }

            { Fr::roll(2) }
            { Fr::toaltstack() }

            { G1Affine::convert_to_compressed() }
            { Fr::fromaltstack() }
            { Fr::convert_to_be_bytes() }

            {blake3_script.clone()}
            { Fr::from_hash() }
            { Fr::push_dec("12675309311304482509247823029963782393309524866265275290730041635615278736000") }
            { Fr::equal(1, 0) }
        };

        println!("fflonk.compute_challenges.xiseed = {} bytes", script.len());

        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_compute_challenges_xin() {
        let script = script! {
            // push xiseed
            { Fr::push_dec("12675309311304482509247823029963782393309524866265275290730041635615278736000") }
            // compute xiseed^2
            { Fr::copy(0) }
            { Fr::square() }
            { Fr::copy(0) }
            { Fr::toaltstack() }

            // pH0w8_0 = xiseed^3
            { Fr::mul() }

            // pH0w8_0
            { Fr::copy(0) }
            { Fr::push_dec("10210594730394925429746291702746561332060256679615545074401657104125756649578") }
            { Fr::equalverify(1, 0) }

            // pH0w8_1
            { Fr::copy(0) }
            // push constant w8_1
            { Fr::push_dec("19540430494807482326159819597004422086093766032135589407132600596362845576832") }
            { Fr::mul() }
            { Fr::push_dec("8372804009848668687759614171560040965977592547922202747919047620642117005104") }
            { Fr::equalverify(1, 0) }

            // pH0w8_2
            { Fr::copy(0) }
            // push constant w8_2
            { Fr::push_dec("21888242871839275217838484774961031246007050428528088939761107053157389710902") }
            { Fr::mul() }
            { Fr::push_dec("12018168561098599325315012321442861121728268008555918380929453858170772126806") }
            { Fr::equalverify(1, 0) }

            // pH0w8_3
            { Fr::copy(0) }
            // push constant w8_3
            { Fr::push_dec("13274704216607947843011480449124596415239537050559949017414504948711435969894") }
            { Fr::mul() }
            { Fr::push_dec("16309511826969302107699393610404172200913629782896950912885458723657982725366") }
            { Fr::equalverify(1, 0) }

            // pH0w8_4
            { Fr::copy(0) }
            // push constant w8_4
            { Fr::push_dec("21888242871839275222246405745257275088548364400416034343698204186575808495616") }
            { Fr::mul() }
            { Fr::push_dec("11677648141444349792500114042510713756488107720800489269296547082450051846039") }
            { Fr::equalverify(1, 0) }

            // pH0w8_5
            { Fr::copy(0) }
            // push constant w8_5
            { Fr::push_dec("2347812377031792896086586148252853002454598368280444936565603590212962918785") }
            { Fr::mul() }
            { Fr::push_dec("13515438861990606534486791573697234122570771852493831595779156565933691490513") }
            { Fr::equalverify(1, 0) }

            // pH0w8_6
            { Fr::copy(0) }
            // push constant w8_6
            { Fr::push_dec("4407920970296243842541313971887945403937097133418418784715") }
            { Fr::mul() }
            { Fr::push_dec("9870074310740675896931393423814413966820096391860115962768750328405036368811") }
            { Fr::equalverify(1, 0) }

            // pH0w8_7
            { Fr::copy(0) }
            // push constant w8_7
            { Fr::push_dec("8613538655231327379234925296132678673308827349856085326283699237864372525723") }
            { Fr::mul() }
            { Fr::push_dec("5578731044869973114547012134853102887634734617519083430812745462917825770251") }
            { Fr::equalverify(1, 0) }

            // pH1w4_0 = xiseed^6
            { Fr::square() }

            // pH1w4_0
            { Fr::copy(0) }
            { Fr::push_dec("1756820407515345004507058825871382296137098363972706405994173662850350774688") }
            { Fr::equalverify(1, 0) }

            // pH1w4_1
            { Fr::copy(0) }
            // push constant w4
            { Fr::push_dec("21888242871839275217838484774961031246007050428528088939761107053157389710902") }
            { Fr::mul() }
            { Fr::push_dec("16907152808936898292083477165412732098542037853664649778796264398384084027651") }
            { Fr::equalverify(1, 0) }

            // pH1w4_2
            { Fr::copy(0) }
            // push constant w4_1
            { Fr::push_dec("21888242871839275222246405745257275088548364400416034343698204186575808495616") }
            { Fr::mul() }
            { Fr::push_dec("20131422464323930217739346919385892792411266036443327937704030523725457720929") }
            { Fr::equalverify(1, 0) }

            // pH1w4_3
            { Fr::copy(0) }
            // push constant w4_2
            { Fr::push_dec("4407920970296243842541313971887945403937097133418418784715") }
            { Fr::mul() }
            { Fr::push_dec("4981090062902376930162928579844542990006326546751384564901939788191724467966") }
            { Fr::equalverify(1, 0) }

            // pH2w3_0 = xiseed^8
            { Fr::fromaltstack() }
            { Fr::mul() }
            { Fr::copy(0) }
            { Fr::toaltstack() }

            // pH2w3_0
            { Fr::copy(0) }
            { Fr::push_dec("8645910648030292747222447120598663930712351861448151482708581449066841434015") }
            { Fr::equalverify(1, 0) }

            // pH2w3_1
            { Fr::copy(0) }
            // push constant w3
            { Fr::push_dec("21888242871839275217838484774961031246154997185409878258781734729429964517155") }
            { Fr::mul() }
            { Fr::push_dec("2196608840183762817611603553419504245649898072887146050087043489198732467688") }
            { Fr::equalverify(1, 0) }

            // pH2w3_2
            { Fr::copy(0) }
            // push constant w3_2
            { Fr::push_dec("4407920970296243842393367215006156084916469457145843978461") }
            { Fr::mul() }
            { Fr::push_dec("11045723383625219657412355071239106912186114466080736810902579248310234593914") }
            { Fr::equalverify(1, 0) }

            // pH3w3_0 = xiseed^8 * ω^{1/3}
            { Fr::push_dec("19699792133865984655632994927951174943026102279822605383822362801478354085676") }
            { Fr::mul() }

            // pH3w3_0
            { Fr::copy(0) }
            { Fr::push_dec("21405568746311661929319138487394095463124289053215849061649274916682085734478") }
            { Fr::equalverify(1, 0) }

            // pH3w3_1
            { Fr::copy(0) }
            // push constant w3
            { Fr::push_dec("21888242871839275217838484774961031246154997185409878258781734729429964517155") }
            { Fr::mul() }
            { Fr::push_dec("16458699422327211795980147165837933894457139622322803085568450314170832928180") }
            { Fr::equalverify(1, 0) }

            // pH2w3_2
            // push constant w3_2
            { Fr::push_dec("4407920970296243842393367215006156084916469457145843978461") }
            { Fr::mul() }
            { Fr::push_dec("5912217575039676719193525837282520819515300125293416540178683142298698328576") }
            { Fr::equalverify(1, 0) }

            { Fr::fromaltstack() }

            // xi = xi_seeder^24
            { Fr::copy(0) }
            { Fr::square() }
            { Fr::mul() }

            // xi
            { Fr::copy(0) }
            { Fr::push_dec("14814634099415170872937750660683266261347419959225231219985478027287965492246") }
            { Fr::equalverify(1, 0) }

            // xiN
            { Fr::square() }
            { Fr::square() }
            { Fr::square() }
            { Fr::square() }
            { Fr::square() }
            { Fr::square() }
            { Fr::square() }
            { Fr::square() }
            { Fr::square() }

            { Fr::square() }
            { Fr::square() }
            { Fr::square() }
            { Fr::square() }
            { Fr::square() }
            { Fr::square() }
            { Fr::square() }
            { Fr::square() }
            { Fr::square() }

            // xin
            { Fr::copy(0) }
            { Fr::push_dec("9539499652122301619680560867461437153480631573357135330838514610439758374056") }
            { Fr::equalverify(1, 0) }

            // zh
            { Fr::push_one() }
            { Fr::sub(1, 0) }
            { Fr::push_dec("9539499652122301619680560867461437153480631573357135330838514610439758374055") }
            { Fr::equalverify(1, 0) }

            OP_TRUE
        };

        println!("fflonk.compute_challenges.xin = {} bytes", script.len());

        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }
}
