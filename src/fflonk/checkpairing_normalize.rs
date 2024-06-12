#[cfg(test)]
mod test {
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::bn254::fq::Fq;
    use crate::bn254::fr::Fr;
    use crate::treepp::*;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::Field;
    use num_bigint::BigUint;
    use std::str::FromStr;

    #[test]
    fn test_checkpairing_normalize() {
        // note: this is not necessarily the point that the verifier obtains

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

        let mut inv = ark_bn254::Fq::from_str(
            "18747233771850556311508953762939425433543524671221692065979284256379095132287",
        )
        .unwrap();
        inv.inverse_in_place().unwrap();

        let script = script! {
            { Fq::push_dec_montgomery("21025932300722401404248737517866966587837387913191004025854702115722286998035") }
            { Fq::push_dec_montgomery("5748766770337880144484917096976043621609890780406924686031233755006782215858") }
            { Fq::push_dec_montgomery("18747233771850556311508953762939425433543524671221692065979284256379095132287") }

            { Fq::inv() }

            { Fq::copy(0) }
            { Fq::square() }
            { Fq::copy(0) } { Fr::toaltstack() }

            { Fq::roll(3) }
            { Fq::mul() }

            { Fq::fromaltstack() }
            { Fq::roll(2) }
            { Fq::mul() }
            { Fq::roll(2) }
            { Fq::mul() }

            // y
            { Fq::push_u32_le_montgomery(&BigUint::from(*affine.y().unwrap()).to_u32_digits()) }
            { Fq::equalverify(1, 0) }

            // x
            { Fq::push_u32_le_montgomery(&BigUint::from(*affine.x().unwrap()).to_u32_digits()) }
            { Fq::equalverify(1, 0) }

            OP_TRUE
        };

        println!("fflonk.checkpairing_normalize = {} bytes", script.len());

        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }
}
