use crate::treepp::{pushable, script, Script};

#[cfg(test)]
mod test{
    use crate::bn254::curves::G1Projective;
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::bn254::fr::Fr;
    use crate::bn254::fq::Fq;
    use crate::vanilla_plonk::mock::Mock;
    use crate::treepp::*;


    #[test]
    fn test_compute_d() {
    
        let mock = Mock::new();
    
        // gamma: Fp256<FrParameters>, 
    //         betaxi: Fp256<FrParameters>, 
    //         k2: Fp256<FrParameters>, 
    //         eval_l1: Fp256<FrParameters>, 
    //         alpha: Fp256<FrParameters>, 
    //         alpha2: Fp256<FrParameters>, 
    //         u: Fp256<FrParameters>,
    //         beta: Fp256<FrParameters>,
    //         proof: PlonkProof,
    //         xin: Fp256<FrParameters>,
    //         zh: Fp256<FrParameters>
        let gamma = "0";
        let betaxi = "0";
        let k2 = "0";
        let eval_l1 = "0";
        let alpha = "0";
        let alpha2 = "0";
        let u = "0";
        let beta = "0";
        let xin = "0";
        let zh = "0";
    
        let qc_x = "0";
        let qc_y = "0";
    
        let eval_a = mock.get_plonk_proof().eval_a;
        let eval_b = mock.get_plonk_proof().eval_b;
        let eval_c = mock.get_plonk_proof().eval_c;
    
    
        
        let script = script! {
            
            { Fr::push_dec(eval_a.as_str())}
    
            { Fr::push_dec(eval_b.as_str())}
    
            { Fr::mul() }
    
            //pushing qm into the stack
            { Fr::push_dec("19151686162665193639218175163708172641368045642989460974532342422984533758298") }
    
            { Fr::push_dec("16425900297592082064122235865674265321861003269908656946806802359646002523562") }
    
            { Fr::push_dec("1") }
    
            { G1Projective::scalar_mul() }

            // current d, pushing it to altstack
            { Fr::toaltstack() }

            //pushing ql into the stack

            { Fr::push_dec("20835273517253247507278161354140085192179560558424391762960775729600393482750") }
    
            { Fr::push_dec("16191201213275001001200617578554070333626688786050641588918630575263395623273") }
    
            { Fr::push_dec("1") }

            { Fr::push_dec(eval_a.as_str())}

            //mul eval_a and ql
            { Fr::mul() }

            // add this value to earlier d
            { Fr::fromaltstack() }

            { Fr::add(0, 1) }

            // current d, pushing it to altstack
            { Fr::toaltstack() }

            //d = d.add( qr_affine.mul(eval_b).into_affine());

            //pushing qr into the stack

            { Fr::push_dec("6900030744989144129848893583598672235257204177548311761347544245788955028280") }
    
            { Fr::push_dec("8155125105494137927083991839474623324411895145542585614480259473774672439508") }
    
            { Fr::push_dec("1") }

            { Fr::push_dec(eval_b.as_str())}

            //mul eval_b and qr
            { Fr::mul() }

            // add this value to earlier d
            { Fr::fromaltstack() }

            { Fr::add(0, 1) }

            // current d, pushing it to altstack
            { Fr::toaltstack() }

            //             d = d.add(qo_affine.mul(eval_c).into_affine());

            //pushing qo into the stack

            { Fr::push_dec("15946180093115511093353920492758773804069483402874922499479809500987551267911") }
    
            { Fr::push_dec("10782711402358324053795706160377115050675566507577901529557399547946751276930") }
    
            { Fr::push_dec("1") }

            { Fr::push_dec(eval_c.as_str())}

            //mul eval_c and qo
            { Fr::mul() }

            // add this value to earlier d
            { Fr::fromaltstack() }

            { Fr::add(0, 1) }
        
    
            OP_TRUE
    
        };
    
    
    }

}

