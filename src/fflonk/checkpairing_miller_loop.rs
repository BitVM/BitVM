#[cfg(test)]
mod test {
    use crate::bn254::ell_coeffs::G2Prepared;
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::bn254::fq::Fq;
    use crate::bn254::fq12::Fq12;
    use crate::bn254::pairing::Pairing;
    use crate::treepp::*;
    use ark_bn254::Bn254;
    use ark_ec::pairing::Pairing as ArkPairing;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::Field;
    use num_bigint::BigUint;
    use std::ops::Neg;
    use std::str::FromStr;

    fn fq12_push(element: ark_bn254::Fq12) -> Script {
        script! {
            for elem in element.to_base_prime_field_elements() {
                { Fq::push_u32_le(&BigUint::from(elem).to_u32_digits()) }
           }
        }
    }

    #[test]
    fn test_checkpairing_miller_loop() {
        let projective = ark_bn254::G1Projective::new(
            ark_bn254::Fq::from_str(
                "21025932300722401404248737517866966587837387913191004025854702115722286998035",
            )
            .unwrap(),
            ark_bn254::Fq::from_str(
                "5748766770337880144484917096976043621609890780406924686031233755006782215858",
            )
            .unwrap(),
            ark_bn254::Fq::from_str(
                "18747233771850556311508953762939425433543524671221692065979284256379095132287",
            )
            .unwrap(),
        );
        let affine = projective.into_affine();

        let a = ark_bn254::g2::G2Affine::new(
            ark_bn254::Fq2::new(
                ark_bn254::Fq::from_str(
                    "10857046999023057135944570762232829481370756359578518086990519993285655852781",
                )
                .unwrap(),
                ark_bn254::Fq::from_str(
                    "11559732032986387107991004021392285783925812861821192530917403151452391805634",
                )
                .unwrap(),
            ),
            ark_bn254::Fq2::new(
                ark_bn254::Fq::from_str(
                    "8495653923123431417604973247489272438418190587263600148770280649306958101930",
                )
                .unwrap(),
                ark_bn254::Fq::from_str(
                    "4082367875863433681332203403145435568316851327593401208105741076214120093531",
                )
                .unwrap(),
            ),
        );
        let a_prepared = G2Prepared::from(a);

        let b = ark_bn254::g2::G2Affine::new(
            ark_bn254::Fq2::new(
                ark_bn254::Fq::from_str(
                    "21831381940315734285607113342023901060522397560371972897001948545212302161822",
                )
                .unwrap(),
                ark_bn254::Fq::from_str(
                    "17231025384763736816414546592865244497437017442647097510447326538965263639101",
                )
                .unwrap(),
            ),
            ark_bn254::Fq2::new(
                ark_bn254::Fq::from_str(
                    "2388026358213174446665280700919698872609886601280537296205114254867301080648",
                )
                .unwrap(),
                ark_bn254::Fq::from_str(
                    "11507326595632554467052522095592665270651932854513688777769618397986436103170",
                )
                .unwrap(),
            ),
        );
        let b_prepared = G2Prepared::from(b);

        let dual_miller_loop = Pairing::dual_miller_loop(&a_prepared, &b_prepared);

        let w2 = ark_bn254::g1::G1Affine::new(
            ark_bn254::Fq::from_str(
                "11695827642347470645483614914520090101440686332033956264171712726147972703435",
            )
            .unwrap(),
            ark_bn254::Fq::from_str(
                "8930092616903485317239646434389939466400752538134075201209141980838088395614",
            )
            .unwrap(),
        );

        let c = Bn254::multi_miller_loop([affine.neg(), w2], [a, b]).0;

        let script = script! {
            // push A1
            { Fq::push_u32_le(&BigUint::from(*affine.x().unwrap()).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(*affine.y().unwrap()).to_u32_digits()) }
            { Fq::neg(0) }

            // push W2
            { Fq::push_dec("11695827642347470645483614914520090101440686332033956264171712726147972703435") }
            { Fq::push_dec("8930092616903485317239646434389939466400752538134075201209141980838088395614") }

            { dual_miller_loop.clone() }
            { fq12_push(c) }
            { Fq12::equalverify() }
            OP_TRUE
        };

        println!("fflonk.checkpairing_miller_loop = {} bytes", script.len());

        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }
}
