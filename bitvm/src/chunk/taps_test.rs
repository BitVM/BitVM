
#[cfg(test)]
mod test {

    use crate::bn254::g1::G1Affine;
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::bn254::fq::Fq;
    use crate::bn254::fq2::Fq2;
    use crate::bn254::utils::{Hint};
    use crate::chunk::blake3compiled::hash_messages;
    use crate::chunk::element::*;
    use crate::chunk::norm_fp12::{chunk_final_verify, chunk_hash_c, chunk_verify_fq6_is_on_field};
    use crate::chunk::primitives::extern_nibbles_to_limbs;
    use crate::chunk::taps_premiller::*;
    use ark_ff::Field;
    use ark_std::UniformRand;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use crate::treepp::*;



    #[test]
    fn test_tap_hash_c() {

        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq6::rand(&mut prng);
        let fqvec = f.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>();

        let (hint_out, tap_hash_c, hint_script) = chunk_hash_c(fqvec.clone().into_iter().map(|f| f.into()).collect::<Vec<ElemU256>>());

        let bitcom_scr = script!{
            for i in extern_nibbles_to_limbs(hint_out.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}
            for f in fqvec.iter().rev() {
                {Fq::push(*f)}
                {Fq::toaltstack()}                
            }
        };
        let hash_scr = script!(
            {hash_messages(vec![ElementType::Fp6])}
            OP_TRUE
        );

        let tap_len = tap_hash_c.len() + hash_scr.len();
        let script = script! {
            for h in hint_script {
                { h.push() }
            }
            {bitcom_scr}
            {tap_hash_c}
            {hash_scr}
        };
        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(!res.success && res.final_stack.len() == 1);
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }

    #[test]
    fn test_tap_verify_fq6() {
        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq6::rand(&mut prng);
        let fqvec = f.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>();

        let (is_valid, tap_hash_c, hint_script) = chunk_verify_fq6_is_on_field(fqvec.clone().into_iter().map(|f| f.into()).collect::<Vec<ElemU256>>());
        assert!(is_valid);
        let bitcom_scr = script!{
            for f in fqvec.iter().rev() {
                {Fq::push(*f)}
                {Fq::toaltstack()}                
            }
        };

        let tap_len = tap_hash_c.len();
        let script = script! {
            for h in hint_script {
                { h.push() }
            }
            {bitcom_scr}
            {tap_hash_c}
        };
        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(!res.success && res.final_stack.len() == 1);
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }

    #[test]
    fn test_chunk_verify_g2_on_curve() {
        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let q = ark_bn254::G2Affine::rand(&mut prng);
        let (hint_out, init_t4_tap, hint_script) = chunk_verify_g2_on_curve(q.y.c1.into(), q.y.c0.into(), q.x.c1.into(), q.x.c0.into());
        assert_eq!(hint_out, q.is_on_curve());
        let bitcom_script = script!{
            {Fq::push(q.y.c1)}
            {Fq::toaltstack()}
            {Fq::push(q.y.c0)}
            {Fq::toaltstack()}
            {Fq::push(q.x.c1)}
            {Fq::toaltstack()}
            {Fq::push(q.x.c0)}
            {Fq::toaltstack()}
        };
        let tap_len = init_t4_tap.len();
        let script = script! {
            for h in hint_script {
                { h.push() }
            }
            {bitcom_script}
            {init_t4_tap}
        };

        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(!res.success && res.final_stack.len() == 1);
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }

    #[test]
    fn test_tap_precompute_p() {
        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let p = ark_bn254::G1Affine::rand(&mut prng);

        let (hint_out, tap_prex, hint_script) = chunk_precompute_p(p.y.into(), p.x.into());

        let bitcom_scr = script!{
            for i in extern_nibbles_to_limbs(hint_out.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}    
            {G1Affine::push(p)}
            {Fq2::toaltstack()}     
        };
        let hash_scr = script!(
            {hash_messages(vec![ElementType::G1])}
            OP_TRUE     
        );

        let tap_len = tap_prex.len();
        let script = script! {
            for h in hint_script {
                { h.push() }
            }
            {bitcom_scr}
            {tap_prex}
            {hash_scr}
        };
        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(!res.success);
        assert!(res.final_stack.len() == 1);
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }

    #[test]
    fn test_tap_precompute_p_from_hash() {
        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let p = ark_bn254::G1Affine::rand(&mut prng);

        let (hint_out, tap_prex, hint_script) = chunk_precompute_p_from_hash(p);

        let bitcom_scr = script!{
            for i in extern_nibbles_to_limbs(hint_out.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}    
            for i in extern_nibbles_to_limbs(p.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}
        };
        let preim_hints = Element::G1(p).get_hash_preimage_as_hints(ElementType::G1);
        let hash_scr = script!(
            {hash_messages(vec![ElementType::G1, ElementType::G1])}
            OP_TRUE     
        );

        let tap_len = tap_prex.len();
        let script = script! {
            for h in hint_script {
                { h.push() }
            }
            for h in preim_hints {
                {h.push()}
            }
            {bitcom_scr}
            {tap_prex}
            {hash_scr}
        };
        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(!res.success);
        assert!(res.final_stack.len() == 1);
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }


    #[test]
    fn test_tap_verify_p_is_on_curve() {
        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let p = ark_bn254::G1Affine::rand(&mut prng);
        let (is_valid_point, tap_prex, hint_script) = chunk_verify_g1_is_on_curve(p.y.into(), p.x.into());
        assert_eq!(p.is_on_curve(), is_valid_point);
        let bitcom_scr = script!{
            {G1Affine::push(p)}
            {Fq2::toaltstack()}     
        };

        let tap_len = tap_prex.len();
        let script = script! {
            for h in hint_script {
                { h.push() }
            }
            {bitcom_scr}
            {tap_prex}
        };
        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(!res.success);
        assert!(res.final_stack.len() == 1);
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }

    #[test]
    fn test_tap_verify_phash_is_on_curve() {
        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let p = ark_bn254::G1Affine::rand(&mut prng);
        let (is_valid_point, tap_prex, hint_script) = chunk_verify_g1_hash_is_on_curve(p);
        assert_eq!(p.is_on_curve(), is_valid_point);
        let bitcom_scr = script!{
            for i in extern_nibbles_to_limbs(p.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}     
        };
        let preim_hints = Element::G1(p).get_hash_preimage_as_hints(ElementType::G1);

        let tap_len = tap_prex.len();
        let script = script! {
            for h in hint_script {
                { h.push() }
            }
            for h in preim_hints {
                {h.push()}
            }
            {bitcom_scr}
            {tap_prex}
        };
        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(!res.success);
        assert!(res.final_stack.len() == 1);
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }

    #[test]
    fn test_tap_verify_fp12_is_unity() {
        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let g = f.inverse().unwrap();
        let f =  ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1/f.c0);
        let g =  ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, g.c1/g.c0);

        let (_, tap_scr, mut hint_script) = chunk_final_verify(f.c1, g.c1);

        let fvec = f.c1.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>();
        for f in &fvec {
            hint_script.push(Hint::Fq(*f));
        } 

        let bitcom_scr = script!{
            for i in extern_nibbles_to_limbs(f.c1.hashed_output()) {
                {i}
            }
            {Fq::toaltstack()}
        };

        let tap_len = tap_scr.len();
        let script = script! {
            for h in hint_script {
                { h.push() }
            }
            {bitcom_scr}
            {tap_scr}
        };
        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(!res.success && res.final_stack.len() == 1);
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }

}
