#[cfg(test)]
mod test {
    use crate::bn254::curves::G1Projective;
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::bn254::fq::Fq;
    use crate::bn254::fr::Fr;
    use crate::treepp::*;

    #[test]
    fn test_compute_f() {
        let script = script! {
            // push (C0x, C0y), C1, C2 (9 elements)
            { Fq::push_dec("303039279492065453055049758769758984569666029850327527958551993331680103359") }
            { Fq::push_dec("15061669176783843627135305167141360334623983780813847469326507992811672859575") }
            { Fq::push_dec("1") }

            { Fq::push_dec("8993820735255461694205287896466659762517378169680151817278189507219986014273") }
            { Fq::push_dec("20608602847008036615737932995836476570376266531776948091942386633580114403199") }
            { Fq::push_dec("1") }

            { Fq::push_dec("7381325072443970270370678023564870071058744625357849943766655609499175274412") }
            { Fq::push_dec("15178578915928592705383893120230835636411008017183180871962629962483134367891") }
            { Fq::push_dec("1") }

            // push quotient1, quotient2 (2 elements)
            { Fr::push_dec("8336823378405991273186613678056299833572545852849807089784419620701331198620") }
            { Fr::push_dec("9383905404220215760494220727835590239846562451983646600728203514340336934716") }

            { Fr::toaltstack() }
            { Fr::toaltstack() }

            { G1Projective::roll(1) }
            { Fr::fromaltstack() }
            { G1Projective::scalar_mul() }

            { G1Projective::roll(1) }
            { Fr::fromaltstack() }
            { G1Projective::scalar_mul() }

            { G1Projective::add() }
            { G1Projective::add() }

            { Fq::push_dec("10827057179016943379099096512257711381208881258335395636699788359889105647796") }
            { Fq::push_dec("15908485457276609870374048914742234656312588226903176268190825086381552148601") }
            { Fq::push_dec("10704903381596808863042656941383257630189957941456629442401491652278045385710") }

            { G1Projective::equalverify() }
            OP_TRUE
        };

        println!("fflonk.compute_f = {} bytes", script.len());

        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }
}
