use crate::bn254::ell_coeffs::{EllCoeff, G2Prepared};
use crate::bn254::fq12::Fq12;
use crate::bn254::fq2::Fq2;
use crate::bn254::pairing::Pairing;
use crate::bn254::utils;
use crate::treepp::*;
use ark_ec::bn::BnConfig;
pub struct QuadPairing;

impl QuadPairing {
    fn process_check_tangent_line<'a>(constant_iter: &mut impl Iterator<Item = &'a EllCoeff>) -> Script {
        let tangent_line_element = constant_iter.next().unwrap();
        let script = script! {
            // check whether the line through T4 is tangent
            // consume T4(4), return none to stack, exection stop if check failed
            { utils::check_tangent_line(tangent_line_element.1, tangent_line_element.2) }
        };
        script
    }
    /// input on stack:
    ///     [P1, P2, P3, P4, Q4, T4]
    ///     [2,  2,  2,  2,  4,  4] (16 stack elements in total)
    ///     P1, P2, P3, P4 are in affine form, such as P1: (-p1.x / p1.y, 1 / p1.y)
    ///     2 means 2 Fq elements, 4 means 4 fp elements
    ///     Q1, Q2 and Q3 are fixed, Q4 is provided by prover
    ///     T4 is accumulator for Q4, initial T4 = Q4, will do double and add operations for T4

    /// input of parameters:
    ///     [L(Q1), L(Q2), L(Q3), L(Q4)] (line coefficients)
    pub fn quad_miller_loop(constants: &Vec<G2Prepared>) -> Script {
        assert_eq!(constants.len(), 4);
        let num_constant = 3;

        let mut constant_iters = constants
            .iter()
            .map(|item| item.ell_coeffs.iter())
            .collect::<Vec<_>>();

        let script = script! {
            // initiate f = fp12(1) and push to stack
            { Fq12::push_one() }
            // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]

            for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
                if i != ark_bn254::Config::ATE_LOOP_COUNT.len() - 1 {
                    // square f in place
                    { Fq12::square() }
                }
                // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]

                ////////////////////////////////////////////////////// double line
                for j in 0..constants.len() {
                    ////////////////////////////// constant part
                    // copy P_i
                    // offset = 26, 24, 22, 20, are the postions of P1(2), P2(2), P3(2), P4(2)
                    { Fq2::copy((26 - j * 2).try_into().unwrap()) }
                    // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12), P_i(2)]
                    // compute new f: consume f(12), P_i(2) return new f(12) to stack
                    { Pairing::ell_by_constant_affine(&constant_iters[j].next().unwrap().clone()) }
                    // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]

                    ///////////////////////////// non-constant part
                    if j == num_constant {
                        // check line coeff is satisfied with T4

                        // copy T4(4), T4(4) = (T4.x(2), T4.y(2))
                        // copy T4.x(2)
                        { Fq2::copy(14) }
                        // [P1(2), P2(2), P3(2), P4(2), Q4(4), f(12), T4.x(2)]
                        // copy T4.y(2)
                        { Fq2::copy(14) }
                        // [P1(2), P2(2), P3(2), P4(2), Q4(4), f(12), T4(4)]
                        // check whether the line through T4 is tangent
                        // consume T4(4), return none to stack, exection stop if check failed
                        // { utils::check_tangent_line(constant_iters[j].next().unwrap().1, constant_iters[j].next().unwrap().1) }
                        { QuadPairing::process_check_tangent_line(&mut constant_iters[j]) }
                        // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]

                        // update T4
                        // Pop f(12) from the main stack onto the alt stack.
                        { Fq12::toaltstack() }
                        // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4) | f(12)]
                        // [main stack ----------------------------- | alt stack]
                        // drop T4.y
                        { Fq2::drop() }
                        // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4.x | f(12)]

                        // double line: consume T4.x, double it, return new T4(accumulator) to main stack
                        { utils::affine_double_line(constant_iters[j].next().unwrap().1, constant_iters[j].next().unwrap().2) }
                        // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4) | f(12)]
                        // Pop f(12) from the alt stack onto the main stack.
                        { Fq12::fromaltstack() }
                        // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]
                    }
                }

                //////////////////////////////////////////////////////// add line
                if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == 1 || ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == -1 {
                    for j in 0..constants.len() {
                        ///////////////////////////////////// constant part
                        { Fq2::copy((26 - j * 2).try_into().unwrap()) }
                        // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12), P_i(2)]
                        // compute new f: consume f(12), P_i(2) return new f(12) to stack
                        { Pairing::ell_by_constant_affine(&constant_iters[j].next().unwrap().clone()) }
                        // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]

                        ///////////////////////////////////// non-constant part
                        if j == num_constant {
                            // copy Q4
                            { Fq2::copy(18) }
                            // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12), Q4.x(2)]
                            { Fq2::copy(18) }
                            // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12), Q4(4)]
                            // copy T4
                            { Fq2::copy(18) }
                            // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12), Q4(4), T4.x(2)]
                            { Fq2::copy(18) }
                            // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12), Q4(4), T4(4)]

                            // check whether the line through T4 and Q4 is chord
                            // consume T4 and Q4, return none to stack, exection stop if check failed
                            { utils::check_chord_line(constant_iters[j].next().unwrap().1, constant_iters[j].next().unwrap().2) }
                            // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]

                            // update T4
                            { Fq12::toaltstack() }
                            // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4) | f(12)]
                            // drop T4.y
                            { Fq2::drop() }
                            // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4.x(2) | f(12)]
                            // copy Q4.x(2)
                            { Fq2::copy(4) }
                            // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4.x(2), Q4.x(2) | f(12)]

                            // add line: consume T4.x and Q4.x, return new T4(accumulator) to main stack
                            { utils::affine_add_line(constant_iters[j].next().unwrap().1, constant_iters[j].next().unwrap().2) }
                            // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4) | f(12)]
                            // Pop f(12) from the alt stack onto the main stack.
                            { Fq12::fromaltstack() }
                            // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]
                        }
                    }
                }
            }

            // one-time of frobenius map
            for j in 0..constants.len() {
                ///////////////////////////////////// constant part
                { Fq2::copy((26 - j * 2).try_into().unwrap()) }
                // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12), P_i(2)]
                // compute new f: consume f(12), P_i(2) return new f(12) to stack
                { Pairing::ell_by_constant_affine(&constant_iters[j].next().unwrap().clone()) }
                // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]

                ///////////////////////////////////// non-constant part
                if j == num_constant {
                    // copy Q4
                    { Fq2::copy(18) }
                    { Fq2::copy(18) }
                    // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12), Q4(4)]
                    // copy T4
                    { Fq2::copy(18) }
                    { Fq2::copy(18) }
                    // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12), Q4(4), T4(4)]

                    // check whether the line through T4 and Q4 is chord
                    // consume T4 and Q4, return none to stack, exection stop if check failed
                    { utils::check_chord_line(constant_iters[j].next().unwrap().1, constant_iters[j].next().unwrap().2) }
                    // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]

                    // update T4
                    { Fq12::toaltstack() }
                    // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4) | f(12)]
                    { Fq2::drop() }
                    // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4.x(2) | f(12)]
                    { Fq2::copy(4) }
                    // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4.x(2), Q4.x(2) | f(12)]
                    { utils::affine_add_line(constant_iters[j].next().unwrap().1, constant_iters[j].next().unwrap().2) }
                    // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4) | f(12)]
                    { Fq12::fromaltstack() }
                    // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]
                }
            }

            // two-times of frobenius map
            for j in 0..constants.len() {
                ///////////////////////////////////// constant part
                // Compute final f: Loop 4 times, each time will comsume one P_i(2) element, return new f(12) to stack
                // [P2(2), P3(2), P4(2), Q4(4), T4(4), f(12), P1(2)] -> [P2(2), P3(2), P4(2), Q4(4), T4(4), f(12)]
                // [       P3(2), P4(2), Q4(4), T4(4), f(12), P2(2)] -> [       P3(2), P4(2), Q4(4), T4(4), f(12)]
                // [              P4(2), Q4(4), T4(4), f(12), P3(2)] -> [              P4(2), Q4(4), T4(4), f(12)]
                // [                     Q4(4), T4(4), f(12), P4(2)] -> [                     Q4(4), T4(4), f(12)]
                { Fq2::copy((26 - j * 2).try_into().unwrap()) }
                { Pairing::ell_by_constant_affine(&constant_iters[j].next().unwrap().clone()) }
                // [Q4(4), T4(4), f(12)]
                // Compute final f end
                ///////////////////////////////////// non-constant part
                if j == num_constant {
                    // roll Q4
                    { Fq2::roll(18) }
                    { Fq2::roll(18) }
                    // [T4(4), f(12), Q4(4)]
                    // roll T4
                    { Fq2::roll(18) }
                    { Fq2::roll(18) }
                    // [f(12), Q4(4), T4(4)]

                    // check whether the line through T4 and Q4 is chord
                    // consume T4 and Q4, return none to stack, exection stop if check failed
                    { utils::check_chord_line(constant_iters[j].next().unwrap().1, constant_iters[j].next().unwrap().2) }
                    // [f(12)]

                    // { Fq12::toaltstack() }
                    // { Fq2::drop() }
                    // { Fq2::copy(4) }
                    // // [P1(2), P2(2), P3(2), P4(2), Q4(4), T4.x(2), Q4.x(2) | f(12)]
                    // { utils::affine_add_line(constant_iters[j].next().unwrap().1, constant_iters[j].next().unwrap().2) }
                    // { Fq12::fromaltstack() }
                }
            }
        };
        for i in 0..num_constant {
            assert_eq!(constant_iters[i].next(), None);
        }
        script
    }
}

#[cfg(test)]
mod test {
    use crate::{
        bn254::{
            ell_coeffs::G2Prepared,
            fq12::Fq12,
            quad_pairing::QuadPairing,
            utils::{self, fq12_push, fq2_push},
        },
        execute_script_without_stack_limit,
        treepp::*,
    };
    use ark_bn254::Bn254;
    use ark_ec::pairing::Pairing as _;
    use ark_ff::UniformRand;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_quad_miller_loop() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let p1 = ark_bn254::G1Affine::rand(&mut prng);
        let p2 = ark_bn254::G1Affine::rand(&mut prng);
        let p3 = ark_bn254::G1Affine::rand(&mut prng);
        let p4 = ark_bn254::G1Affine::rand(&mut prng);

        let q1 = ark_bn254::g2::G2Affine::rand(&mut prng);
        let q2 = ark_bn254::g2::G2Affine::rand(&mut prng);
        let q3 = ark_bn254::g2::G2Affine::rand(&mut prng);
        let q4 = ark_bn254::g2::G2Affine::rand(&mut prng);
        let q1_prepared = G2Prepared::from_affine(q1);
        let q2_prepared = G2Prepared::from_affine(q2);
        let q3_prepared = G2Prepared::from_affine(q3);
        let q4_prepared = G2Prepared::from_affine(q4);

        let t4 = q4;

        let quad_miller_loop = QuadPairing::quad_miller_loop(
            &[q1_prepared, q2_prepared, q3_prepared, q4_prepared].to_vec(),
        );
        println!("Pairing.quad_miller_loop: {} bytes", quad_miller_loop.len());
        let q1_affine = q1;
        let q2_affine = q2;
        let q3_affine = q3;
        let q4_affine = q4;

        let hint =
            Bn254::multi_miller_loop_affine([p1, p2, p3, p4], [q1_affine, q2_affine, q3_affine, q4_affine]).0;
        println!("Bn254::multi_miller_loop_affine done!");
        println!("Accumulated f done!");

        // [p1, p2, p3, p4, q4, t4]: p1-p4: (-p.x / p.y, 1 / p.y)
        let script = script! {
            { utils::from_eval_point(p1) }
            { utils::from_eval_point(p2) }
            { utils::from_eval_point(p3) }
            { utils::from_eval_point(p4) }

            { fq2_push(q4.x) }
            { fq2_push(q4.y) }

            { fq2_push(t4.x) }
            { fq2_push(t4.y) }

            { quad_miller_loop.clone() }

            { fq12_push(hint) }
            { Fq12::equalverify() }

            OP_TRUE
        };
        let exec_result = execute_script_without_stack_limit(script);
        println!("{}", exec_result);
        assert!(exec_result.success);
    }
}
