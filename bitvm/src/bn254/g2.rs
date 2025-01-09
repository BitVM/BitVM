use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::fq::Fq;
use crate::bn254::fq2::Fq2;
use crate::treepp::{script, Script};
use super::utils::Hint;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{AdditiveGroup, Field};
use std::ops::{Add, Div, Mul, Sub};
use bitcoin::ScriptBuf;

pub struct G2Affine;

//B = Fq2(19485874751759354771024239261021720505790618469301721065564631296452457478373,
//266929791119991161246907387137283842545076965332900288569378510910307636690)
impl G2Affine {
    pub fn is_on_curve() -> Script {
        script! {
            { Fq2::copy(2) }
            { Fq2::square() }
            { Fq2::roll(4) }
            { Fq2::mul(2,0) }
            { Fq::push_dec("19485874751759354771024239261021720505790618469301721065564631296452457478373") }
            { Fq::push_dec("266929791119991161246907387137283842545076965332900288569378510910307636690") }
            { Fq2::add(2, 0) }
            { Fq2::roll(2) }
            { Fq2::square() }
            { Fq2::equal() }
        }
    }

    pub fn hinted_is_on_curve(x: ark_bn254::Fq2, y: ark_bn254::Fq2) -> (Script, Vec<Hint>) {
        let (x_sq, x_sq_hint) = Fq2::hinted_square(x);
        let (x_cu, x_cu_hint) = Fq2::hinted_mul(0, x, 2, x*x);
        let (y_sq, y_sq_hint) = Fq2::hinted_square(y);

        let mut hints = Vec::new();
        hints.extend(x_sq_hint);
        hints.extend(x_cu_hint);
        hints.extend(y_sq_hint);

        let scr = script! {
            { Fq2::copy(2) }
            { x_sq }
            { Fq2::roll(4) }
            { x_cu }
            { Fq::push_dec_not_montgomery("19485874751759354771024239261021720505790618469301721065564631296452457478373") }
            { Fq::push_dec_not_montgomery("266929791119991161246907387137283842545076965332900288569378510910307636690") }
            { Fq2::add(2, 0) }
            { Fq2::roll(2) }
            { y_sq }
            { Fq2::equal() }
        };
        (scr, hints)
    }

    pub fn push_not_montgomery(element: ark_bn254::G2Affine) -> Script {
        script! {
            { Fq2::push_not_montgomery(element.x) }
            { Fq2::push_not_montgomery(element.y) }
        }
    }

    pub fn read_from_stack_not_montgomery(witness: Vec<Vec<u8>>) -> ark_bn254::G2Affine {
        assert_eq!(witness.len() as u32, Fq::N_LIMBS * 4);
        let x = Fq2::read_from_stack_not_montgomery(witness[0..2 * Fq::N_LIMBS as usize].to_vec());
        let y = Fq2::read_from_stack_not_montgomery(
            witness[2 * Fq::N_LIMBS as usize..4 * Fq::N_LIMBS as usize].to_vec(),
        );
        ark_bn254::G2Affine {
            x,
            y,
            infinity: false,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct ScriptContext<F: ark_ff::Field> {
    pub inputs: Vec<F>,
    pub outputs: Vec<F>,
    pub auxiliary: Vec<usize>,
}

#[derive(Debug, Clone, Default)]
pub struct SplitScript {
    pub script: ScriptBuf,
    pub input_len: u32,
    pub output_len: u32,
}

pub struct PairingNative;

impl PairingNative {
    // Reference: https://github.com/arkworks-rs/algebra/blob/master/curves/bn254/src/curves/g2.rs#L59
    // https://github.com/BitVM/BitVM/issues/109
    pub fn witness_g2_subgroup_check(
        point: &ark_bn254::g2::G2Affine,
        constants: [ark_bn254::Fq2; 2],
        scalar_bit: Vec<bool>,
    ) -> (bool, Vec<ScriptContext<ark_bn254::Fq2>>) {
        let mut script_contexts = vec![];

        let mut script_context = ScriptContext::default();

        // Maps (x,y) -> (x^p * (u+9)^((p-1)/3), y^p * (u+9)^((p-1)/2))
        script_context
            .inputs
            .push(point.clone().x().unwrap().to_owned());
        script_context
            .inputs
            .push(point.clone().y().unwrap().to_owned());

        let mut p_times_point = *point;
        p_times_point.x.frobenius_map_in_place(1);
        p_times_point.y.frobenius_map_in_place(1);

        p_times_point.x *= constants[0];
        p_times_point.y *= constants[1];

        script_context
            .outputs
            .push(p_times_point.clone().x().unwrap().to_owned());
        script_context
            .outputs
            .push(p_times_point.clone().y().unwrap().to_owned());

        script_contexts.push(script_context);

        let (x_times_point, witness) = Self::witness_split_scalar_mul_g2(point, &scalar_bit);

        assert_eq!(p_times_point, x_times_point);

        script_contexts.extend(witness);

        (true, script_contexts)
    }
    
    pub fn witness_split_scalar_mul_g2(
        base: &ark_bn254::G2Affine,
        scalar: &[bool],
    ) -> (ark_bn254::G2Affine, Vec<ScriptContext<ark_bn254::Fq2>>) {
        let res = base.to_owned();
        let mut tmp = base.to_owned();

        let mut script_contexts = vec![];

        for b in scalar.iter().skip(1) {

            let (lambda, miu, res_x, res_y) = PairingNative::line_double_g2(&tmp);

            let mut script_context = ScriptContext::default();

            script_context.inputs.push(lambda);
            script_context.inputs.push(miu);
            script_context.inputs.push(tmp.x().unwrap().to_owned());
            script_context.inputs.push(tmp.y().unwrap().to_owned());
            script_context.outputs.push(res_x);
            script_context.outputs.push(res_y);

            tmp = tmp.add(tmp).into_affine();

            assert_eq!(res_x, tmp.x().unwrap().clone());
            assert_eq!(res_y, tmp.y().unwrap().clone());

            // ecc_double_add_data_set.push(ecc_double_add_data_tmp);
            script_contexts.push(script_context);

            if *b {
                let mut script_context = ScriptContext::default();

                let (lambda, miu, res_x, res_y) = PairingNative::line_add_g2(&res, &tmp);

                script_context.inputs.push(lambda);
                script_context.inputs.push(miu);
                script_context.inputs.push(res.x().unwrap().to_owned());
                script_context.inputs.push(res.y().unwrap().to_owned());
                script_context.inputs.push(tmp.x().unwrap().to_owned());
                script_context.inputs.push(tmp.y().unwrap().to_owned());
                script_context.outputs.push(res_x);
                script_context.outputs.push(res_y);

                tmp = tmp.add(res).into_affine();

                assert_eq!(res_x, tmp.x().unwrap().clone());
                assert_eq!(res_y, tmp.y().unwrap().clone());

                script_contexts.push(script_context);
            }
        }

        (tmp, script_contexts)
    }

    pub fn line_add_g2(
        point1: &ark_bn254::G2Affine,
        point2: &ark_bn254::G2Affine,
    ) -> (
        ark_bn254::Fq2,
        ark_bn254::Fq2,
        ark_bn254::Fq2,
        ark_bn254::Fq2,
    ) {
        let (x1, y1) = (point1.x, point1.y);
        let (x2, y2) = (point2.x, point2.y);

        // slope: alpha = (y2-y1)/(x2-x1)
        let alpha = (y2.sub(y1)).div(x2.sub(x1));
        // bias = y1 - alpha * x1
        let bias = y1 - alpha * x1;

        let x3 = alpha.square() - x1 - x2;
        let y3 = -(bias + alpha * x3);

        (alpha, bias, x3, y3)
    }

    pub fn line_double_g2(
        point: &ark_bn254::G2Affine,
    ) -> (
        ark_bn254::Fq2,
        ark_bn254::Fq2,
        ark_bn254::Fq2,
        ark_bn254::Fq2,
    ) {
        let (x, y) = (point.x, point.y);

        // slope: alpha = 3 * x ^ 2 / (2 * y)
        let alpha = x
            .square()
            .mul(ark_bn254::Fq2::from(3))
            .div(y.mul(ark_bn254::Fq2::from(2)));
        // bias = y - alpha * x
        let bias = y - alpha * x;

        let x3 = alpha.square() - x.double();
        let y3 = -(bias + alpha * x3);

        (alpha, bias, x3, y3)
    }
}
pub struct PairingSplitScript;

impl PairingSplitScript {
    pub fn scalar_mul_split_g2(scalar_bit: Vec<bool>) -> Vec<Script> {
        let mut script_chunks: Vec<Script> = vec![];

        for bit in scalar_bit.iter().skip(1) {
            script_chunks.push(Self::double_line_g2());

            if *bit {
                script_chunks.push(Self::add_line_g2());
            }
        }

        script_chunks
    }

    // Stack top: [Q.x, Q.y]
    // Stack top: [Q.x, Q.y * fro]
    // Stack top: [Q.x, Q.y * fro * constant_1]
    // Stack top: [Q.x] | [Q.y * fro * constant_1]
    // Stack top: [Q.x * fro] | [Q.y * fro * constant_1]
    // Stack top: [Q.x * fro * constant_0] | [Q.y * fro * constant_1]
    // Stack top: [Q.x * fro * constant_0, Q.y * fro * constant_1]
    pub fn g2_subgroup_check(constants: [ark_bn254::Fq2; 2], scalar_bit: Vec<bool>) -> Vec<Script> {
        let mut res = vec![];

        res.push(script! {

            { Fq2::frobenius_map(1)}
            { Fq2::mul_by_constant(&constants[1])}
            { Fq2::toaltstack()}
            { Fq2::frobenius_map(1)}
            { Fq2::mul_by_constant(&constants[0])}
            { Fq2::fromaltstack()}

        });

        res.extend(Self::scalar_mul_split_g2(scalar_bit));

        res
    } // Stack top: [lamda, mu,   Q.x, Q.y ]
      // Type:      [Fq2,   Fq2, (Fq2, Fq2)]
    pub fn double_line_g2() -> Script {
        script! {
            // check 2*lamda*y == 3 * q.x^2
            // [lamda, mu, x, y, y ]
            { Fq2::copy(0) }
            // [lamda, mu, x, y, y, lamda ]
            { Fq2::copy(8) }
            // [lamda, mu, x, y, y * lamda ]
            { Fq2::mul(0, 2) }
            // [lamda, mu, x, y, 2 *y * lamda ]
            { Fq2::double(0) }
            // [lamda, mu, x, y] | [ 2 *y * lamda ]
            { Fq2::toaltstack() }
            // 2 * lamda * y == 3 * x^2
            // [lamda, mu, x, y, x] | [ 2 *y * lamda ]
            { Fq2::copy(2) }
            // [lamda, mu, x, y, x^2] | [ 2 *y * lamda ]
            { Fq2::square() }
            // [lamda, mu, x, y, x^2, x^2] | [ 2 *y * lamda ]
            { Fq2::copy(0) }
            // [lamda, mu, x, y, x^2, 2x^2] | [ 2 *y * lamda ]
            { Fq2::double(0) }
            // [lamda, mu, x, y, 3x^2] | [ 2 *y * lamda ]
            { Fq2::add(0, 2) }
            // [lamda, mu, x, y, 3x^2, 2 *y * lamda ]
            { Fq2::fromaltstack() }
            // [lamda, mu, x, y]
            { Fq2::equalverify() }
            // check y - lamda * x _ mu == 0
            // [lamda, mu, x, y, mu]
            { Fq2::copy(4) }
            // [lamda, mu, x, y - mu]
            { Fq2::sub(2, 0) }
            // [lamda, mu, x, y - mu, x]
            { Fq2::copy(2) }
            // [lamda, mu, x, y - mu, x, lamda]
            { Fq2::copy(8) }
            // [lamda, mu, x, y - mu, x * lamda]
            { Fq2::mul(0, 2) }
            // [lamda, mu, x, y - mu - x * lamda]
            { Fq2::sub(2, 0) }
            // [lamda, mu, x, y - mu - x * lamda, 0]
            { Fq2::push_zero() }
            // [lamda, mu, x]
            { Fq2::equalverify() }
            // calcylate x_3 = lamda^2 - 2x
            // [lamda, mu, x, lamda]
            { Fq2::copy(4) }
            // [lamda, mu, x, lamda^2]
            { Fq2::square() }
            // [lamda, mu, lamda^2, 2x]
            { Fq2::double(2) }
            // [lamda, mu, lamda^2 - 2x]
            { Fq2::sub(2, 0) }
            // [lamda, mu, x3, x3 ]
            { Fq2::copy(0) }
            // [mu, x3, lamda * x3 ]
            { Fq2::mul(0, 6) }
            // [x3, lamda * x3 + mu ]
            { Fq2::add(0, 4) }
            // [x3, y3 ]
            { Fq2::neg(0) }
        }
    }

    // Stack top: [lamda, mu,  Q.x1, Q.y1, Q.x2, Q.y2 ]
    // Type:      [Fq2,   Fq2, (Fq2, Fq2), (Fq2, Fq2)]
    pub fn add_line_g2() -> Script {
        script! {
            // check y2 - lamda * x2 - mu == 0
            // [lamda, mu, x1, y1, x2, y2, mu]
            { Fq2::copy(8) }
            // [lamda, mu, x1, y1, x2, y2 - mu]
            { Fq2::sub(2, 0) }
            // [lamda, mu, x1, y1, x2, y2 - mu, x2]
            { Fq2::copy(2) }
            // [lamda, mu, x1, y1, x2, y2 - mu, x2, lambda]
            { Fq2::copy(12) }
            // [lamda, mu, x1, y1, x2, y2 - mu, x2 * lambda]
            { Fq2::mul(0, 2) }
            // [lamda, mu, x1, y1, x2, y2 - mu - x2 * lambda]
            { Fq2::sub(2, 0) }
            // [lamda, mu, x1, y1, x2, y2 - mu - x2 * lambda, 0]
            { Fq2::push_zero() }
            // [lamda, mu, x1, y1, x2]
            { Fq2::equalverify() }
            // check y1 - lamda * x1 - mu == 0
            // [lamda, mu, x1, y1, x2, mu]
            { Fq2::copy(6) }
            // [lamda, mu, x1, x2, y1 - mu]
            { Fq2::sub(4, 0) }
            // [lamda, mu, x1, x2, y1 - mu, x1]
            { Fq2::copy(4) }
            // [lamda, mu, x1, x2, y1 - mu, x1, lambda]
            { Fq2::copy(10) }
            // [lamda, mu, x1, x2, y1 - mu, x1 * lambda]
            { Fq2::mul(0, 2) }
            // [lamda, mu, x1, x2, y1 - mu - x1 * lambda]
            { Fq2::sub(2, 0) }
            // [lamda, mu, x1, x2, y1 - mu - x2 * lambda, 0]
            { Fq2::push_zero() }
            // [lamda, mu, x1, x2]
            { Fq2::equalverify() }
            // calcylate x_3 = lamda^2 - x1 - x2
            // [lamda, mu, x1 + x2]
            {Fq2::add(0, 2)}
            // [lamda, mu, x1 + x2, lamda]
            { Fq2::copy(4) }
            // [lamda, mu, x1 + x2, lamda^2]
            { Fq2::square() }
            // [lamda, mu, lamda^2 - (x1 + x2)]
            { Fq2::sub(0, 2) }
            // [lamda, mu, x3, x3 ]
            { Fq2::copy(0) }
            // [mu, x3, lamda * x3 ]
            { Fq2::mul(0, 6) }
            // [x3, lamda * x3 + mu ]
            { Fq2::add(0, 4) }
            // [x3, y3 ]
            { Fq2::neg(0) }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::bn254::g1::G1Affine;
    use crate::bn254::g2::G2Affine;
    use crate::bn254::fq::Fq;
    use crate::bn254::fq2::Fq2;
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::chunker::common::extract_witness_from_stack;
    use crate::{execute_script, run, treepp::*};
    use super::*;
    use ark_std::UniformRand;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::str::FromStr;
    use ark_std::end_timer;
    use ark_std::start_timer;
    use num_bigint::BigUint;

    #[test]
    fn test_read_from_stack() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let a = ark_bn254::G1Affine::rand(&mut prng);
        let script = script! {
            {G1Affine::push_not_montgomery(a)}
        };

        let res = execute_script(script);
        let witness = extract_witness_from_stack(res);
        let recovered_a = G1Affine::read_from_stack_not_montgomery(witness);

        assert_eq!(a, recovered_a);

        let b = ark_bn254::G2Affine::rand(&mut prng);
        let script = script! {
            {G2Affine::push_not_montgomery(b)}
        };

        let res = execute_script(script);
        let witness = extract_witness_from_stack(res);
        let recovered_b = G2Affine::read_from_stack_not_montgomery(witness);

        assert_eq!(b, recovered_b);
    }

    #[test]
    fn test_g2_affine_is_on_curve() {
        let affine_is_on_curve = G2Affine::is_on_curve();

        println!("G2.affine_is_on_curve: {} bytes", affine_is_on_curve.len());

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..3 {
            let point = ark_bn254::G2Affine::rand(&mut prng);

            let script = script! {
                { Fq2::push(point.x) }
                { Fq2::push(point.y) }
                { affine_is_on_curve.clone()}
            };
            println!("curves::test_affine_is_on_curve = {} bytes", script.len());
            run(script);

            let script = script! {
                { Fq2::push(point.x) }
                { Fq2::push(point.y) }
                { Fq2::double(0) }
                { affine_is_on_curve.clone()}
                OP_NOT
            };
            println!("curves::test_affine_is_on_curve = {} bytes", script.len());
            run(script);
        }
    }

    #[test]
    fn test_hinted_g2_affine_is_on_curve() {

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..3 {
            let point = ark_bn254::G2Affine::rand(&mut prng);
            let (scr, hints) = G2Affine::hinted_is_on_curve(point.x, point.y);
            let script = script! {
                for hint in hints { 
                    { hint.push() }
                }
                { Fq2::push_not_montgomery(point.x) }
                { Fq2::push_not_montgomery(point.y) }
                { scr}
            };
            println!("curves::test_affine_is_on_curve = {} bytes", script.len());
            let res = execute_script(script);
            assert!(res.success);

            let (scr, hints) = G2Affine::hinted_is_on_curve(point.x, point.y + point.y);
            let script = script! {
                for hint in hints { 
                    { hint.push() }
                }
                { Fq2::push_not_montgomery(point.x) }
                { Fq2::push_not_montgomery(point.y) }
                {Fq2::double(0)}
                { scr}
                OP_NOT
            };
            println!("curves::test_affine_is_on_curve = {} bytes", script.len());
            let res = execute_script(script);
            assert!(res.success);
        }
    }

    #[test]
    fn test_g2_subgroup_check() {

        let mut prng = ChaCha20Rng::seed_from_u64(0);
        
        #[allow(non_snake_case)]
        for _ in 0..1 {
            let P_POWER_ENDOMORPHISM_COEFF_0 = ark_bn254::Fq2::new(
                ark_bn254::Fq::from_str("21575463638280843010398324269430826099269044274347216827212613867836435027261").unwrap(),
                ark_bn254::Fq::from_str("10307601595873709700152284273816112264069230130616436755625194854815875713954").unwrap()
            );

            // PSI_Y = (u+9)^((p-1)/2) = TWIST_MUL_BY_Q_Y
            let P_POWER_ENDOMORPHISM_COEFF_1 = ark_bn254::Fq2::new(
                ark_bn254::Fq::from_str("2821565182194536844548159561693502659359617185244120367078079554186484126554").unwrap(),
                ark_bn254::Fq::from_str("3505843767911556378687030309984248845540243509899259641013678093033130930403").unwrap(),
            );

            let scalar_bit: Vec<bool> = ark_ff::BitIteratorBE::without_leading_zeros(&[17887900258952609094, 8020209761171036667]).collect();

            let p = ark_bn254::G2Affine::rand(&mut prng);

            let scripts = PairingSplitScript::g2_subgroup_check([P_POWER_ENDOMORPHISM_COEFF_0, P_POWER_ENDOMORPHISM_COEFF_1], scalar_bit.clone());

            println!(
                "curves::test_g2_subgroup_check script chunk num = {}",
                scripts.len()
            );

            // **************** prepare witness data ******************

            let (res, witness) = PairingNative::witness_g2_subgroup_check(&p, [P_POWER_ENDOMORPHISM_COEFF_0, P_POWER_ENDOMORPHISM_COEFF_1], scalar_bit.clone());

            assert!(res);

            println!(
                "curves::test_g2_subgroup_check witness data len = {}",
                witness.len()
            );

            //********** Check ech script chunk with witness data *************//

            // execute for each msm-script and witness
            for (i, (wit, scp)) in witness.iter().zip(scripts).enumerate() {
                let final_script = script! {
                    for input in wit.inputs.iter() {
                        { Fq::push_u32_le(&BigUint::from(input.c0).to_u32_digits()) }
                        { Fq::push_u32_le(&BigUint::from(input.c1).to_u32_digits()) }
                    }
                    { scp.clone() }
                    for output in wit.outputs.iter() {
                        { Fq::push_u32_le(&BigUint::from(output.c0).to_u32_digits()) }
                        { Fq::push_u32_le(&BigUint::from(output.c1).to_u32_digits()) }

                    }
                    { Fq::equalverify(4,0) }
                    { Fq::equalverify(3,0) }
                    { Fq::equalverify(2,0) }
                    { Fq::equalverify(1,0) }
                    OP_TRUE
                };
                let start = start_timer!(|| "execute_test_g2_subgroup_check_script");
                let exec_result = execute_script(final_script);
                assert!(exec_result.success);
                println!("subscript[{}] runs successfully!", i);
                end_timer!(start);
            }
        }
    }
}

