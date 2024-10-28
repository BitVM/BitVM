use super::elements::{DataType::FqData, DataType::Fq2Data, DataType::Fq12Data,  ElementTrait, FqType, Fq2Type, Fq12Type};
use super::{assigner::BCAssigner, segment::Segment};
use crate::bn254::{ell_coeffs::EllCoeff,fp254impl::Fp254Impl, fq::Fq,fq12::Fq12};
use crate::treepp::*;
use ark_ff::Field;


pub fn ell_wrapper<T: BCAssigner>(
    assigner: &mut T,
    prefix: &str,
    f: ark_bn254::Fq12,
    x: ark_bn254::Fq,
    y: ark_bn254::Fq,
    constant: &EllCoeff,
) -> (Vec<Segment>, Fq12Type)  {
    let mut tf = Fq12Type::new(assigner, &format!("{}{}",prefix,"f"));
    tf.fill_with_data(Fq12Data(f));
    let mut tx = FqType::new(assigner, &format!("{}{}",prefix,"x"));
    tx.fill_with_data(FqData(x));
    let mut ty = FqType::new(assigner, &format!("{}{}",prefix,"y"));
    ty.fill_with_data(FqData(y));

    ell(assigner, prefix, tf,tx,ty,f,x,y,constant)
}

pub fn ell<T: BCAssigner>(
    assigner: &mut T,
    prefix: &str,
    tf: Fq12Type,
    tx: FqType,
    ty: FqType,
    f: ark_bn254::Fq12,
    x: ark_bn254::Fq,
    y: ark_bn254::Fq,
    constant: &EllCoeff,
) -> (Vec<Segment>, Fq12Type)  {
    assert_eq!(constant.0, ark_bn254::Fq2::ONE);

    let (hinted_script1, hint1) = Fq::hinted_mul_by_constant(x, &constant.1.c0);
    let (hinted_script2, hint2) = Fq::hinted_mul_by_constant(x, &constant.1.c1);
    let (hinted_script3, hint3) = Fq::hinted_mul_by_constant(y, &constant.2.c0);
    let (hinted_script4, hint4) = Fq::hinted_mul_by_constant(y, &constant.2.c1);
    let mut c1 = constant.1;
    c1.mul_assign_by_fp(&x);
    let mut c2 = constant.2;
    c2.mul_assign_by_fp(&y);

    let script_lines_0 = vec![
        // [x', y']
        // update c1, c1' = x' * c1
        Fq::copy(1),
        hinted_script1,
        // [ x', y', x' * c1.0]
        Fq::roll(2),
        hinted_script2,
        // [y', x' * c1.0, x' * c1.1]
        // [y', x' * c1]

        // update c2, c2' = -y' * c2
        Fq::copy(2),
        hinted_script3, // Fq::mul_by_constant(&constant.2.c0),
        // [y', x' * c1, y' * c2.0]
        Fq::roll(3),
        hinted_script4,
        // [x' * c1, y' * c2.0, y' * c2.1]
        // [x' * c1, y' * c2]
        // [c1', c2']
    ];
    let mut script_0 = script! {};
    for script_line_0 in script_lines_0 {
        script_0 = script_0.push_script(script_line_0.compile());
    }
    let mut hints_0 = Vec::new();
    hints_0.extend(hint1);
    hints_0.extend(hint2);
    hints_0.extend(hint3);
    hints_0.extend(hint4);
    //
    let mut tc1 = Fq2Type::new(assigner, &format!("{}{}",prefix,"c1"));
    let mut tc2 = Fq2Type::new(assigner, &format!("{}{}",prefix,"c2"));
    tc1.fill_with_data(Fq2Data(c1));
    tc2.fill_with_data(Fq2Data(c2));

    let segment0 = Segment::new(script_0)
        .add_parameter(&tx)
        .add_parameter(&ty)
        .add_result(&tc1)
        .add_result(&tc2)
        .add_hint(hints_0);

    let mut f1 = f;
    f1.mul_by_034(&constant.0, &c1, &c2);
    let c = f1;
    let mut tc = Fq12Type::new(assigner, &format!("{}{}",prefix,"c"));
    tc.fill_with_data(Fq12Data(c));

    let (script_1, hint_1) = Fq12::hinted_mul_by_34(f, c1, c2);
    //  // compute the new f with c1'(c3) and c2'(c4), where c1 is trival value 1
    //  script_1,
    // // [f, c1', c2']
    //  // [f]
    let segment1 = Segment::new(script_1)
    .add_parameter(&tf)
    .add_parameter(&tc1)
    .add_parameter(&tc2)
    .add_result(&tc)
    .add_hint(hint_1);

    (
        vec![segment0, segment1],
        tc,
    )
}

#[cfg(test)]
mod test {
    
}
