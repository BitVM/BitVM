#[cfg(test)]
mod test {
    use crate::bn254::curves::G1;
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::bn254::fq::Fq;
    use crate::bn254::fr::Fr;
    use crate::treepp::*;
    use num_bigint::BigUint;
    use std::str::FromStr;

    #[test]
    fn test_check_format() {
        let script = script! {
            // C1
            { Fq::push_u32_le(&BigUint::from_str("11414956471147768131315932110271203458539230873345793189675206019144009916441").unwrap().to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from_str("10823081975643814089933974416408913336356022525911456025175504046592418333086").unwrap().to_u32_digits()) }
            { G1::affine_is_on_curve() }
            OP_VERIFY
            // C2
            { Fq::push_u32_le(&BigUint::from_str("11566795333200674631031275069327816917129959946409817102620081100923605294412").unwrap().to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from_str("20536176778443869947831422797426320625933462479414797443228665874616154440471").unwrap().to_u32_digits()) }
            { G1::affine_is_on_curve() }
            OP_VERIFY
            // W1
            { Fq::push_u32_le(&BigUint::from_str("6502766465356701153812948444952998478130909513786376499498225577472309611655").unwrap().to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from_str("16914450454915415813500918159574929168323519352150985171070774287274062848826").unwrap().to_u32_digits()) }
            { G1::affine_is_on_curve() }
            OP_VERIFY
            // W2
            { Fq::push_u32_le(&BigUint::from_str("916731453935501864678859334105133541844437685207875347653749360278750016241").unwrap().to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from_str("3299057735494863192502112144534924844598609614917169896233148722362272561721").unwrap().to_u32_digits()) }
            { G1::affine_is_on_curve() }
            OP_VERIFY
            // ql
            { Fr::push_u32_le(&BigUint::from_str("152861852038339951358680304931493054196495308891373419029404876818921669521").unwrap().to_u32_digits()) }
            { Fr::is_field() }
            OP_VERIFY
            // qr
            { Fr::push_u32_le(&BigUint::from_str("20812714604859070760973883001289450360676808417508582950240790438833365485043").unwrap().to_u32_digits()) }
            { Fr::is_field() }
            OP_VERIFY
            // qm
            { Fr::push_u32_le(&BigUint::from_str("21141486221091229747870395438440380939102665676917986561705629109630577779728").unwrap().to_u32_digits()) }
            { Fr::is_field() }
            OP_VERIFY
            // qo
            { Fr::push_u32_le(&BigUint::from_str("8436346521326153419219946958115701214355180399205644020019337322149598816913").unwrap().to_u32_digits()) }
            { Fr::is_field() }
            OP_VERIFY
            // qc
            { Fr::push_u32_le(&BigUint::from_str("1031628756002334763153359606083153691789729910413964548508380416865439907306").unwrap().to_u32_digits()) }
            { Fr::is_field() }
            OP_VERIFY
            // s1
            { Fr::push_u32_le(&BigUint::from_str("19203117768191891476631227975622877176338330048725230083884981725514565720781").unwrap().to_u32_digits()) }
            { Fr::is_field() }
            OP_VERIFY
            // s2
            { Fr::push_u32_le(&BigUint::from_str("6211896297189645663346180227917748159320128344269338146323534087184557298767").unwrap().to_u32_digits()) }
            { Fr::is_field() }
            OP_VERIFY
            // s3
            { Fr::push_u32_le(&BigUint::from_str("17521703481233561120726458054406408969115585302712080815952359316198401643411").unwrap().to_u32_digits()) }
            { Fr::is_field() }
            OP_VERIFY
            // a
            { Fr::push_u32_le(&BigUint::from_str("2855492261159971065193666224524165640794448639116326862800787915272479364383").unwrap().to_u32_digits()) }
            { Fr::is_field() }
            OP_VERIFY
            // b
            { Fr::push_u32_le(&BigUint::from_str("1148476378996519134759876928988902022101606819959188833291738594867390582115").unwrap().to_u32_digits()) }
            { Fr::is_field() }
            OP_VERIFY
            // c
            { Fr::push_u32_le(&BigUint::from_str("9353216755763076851233562676987496427594999801799239655038808419653082371440").unwrap().to_u32_digits()) }
            { Fr::is_field() }
            OP_VERIFY
            // z
            { Fr::push_u32_le(&BigUint::from_str("14509786733123226456809197784201229348771271005161599509974585518676141654914").unwrap().to_u32_digits()) }
            { Fr::is_field() }
            OP_VERIFY
            // zw
            { Fr::push_u32_le(&BigUint::from_str("17977914720844904880682105314100800543926000634008844598835389738415893953341").unwrap().to_u32_digits()) }
            { Fr::is_field() }
            OP_VERIFY
            // t1w
            { Fr::push_u32_le(&BigUint::from_str("4528395929994997079024562472862666946042190361808368242428808997471626248642").unwrap().to_u32_digits()) }
            { Fr::is_field() }
            OP_VERIFY
            // t2w
            { Fr::push_u32_le(&BigUint::from_str("13536652505521831229740334539648791216437098526034219511905729741117147167460").unwrap().to_u32_digits()) }
            { Fr::is_field() }
            OP_VERIFY
            // inv
            { Fr::push_u32_le(&BigUint::from_str("11434451420538908792451254307155013476237631457646404664660026873675798194979").unwrap().to_u32_digits()) }
            { Fr::is_field() }
        };
        println!("fflonk.check_format = {} bytes", script.len());
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }
}
