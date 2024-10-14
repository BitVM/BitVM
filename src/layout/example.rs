use crate::bn254::curves::G1Projective;

use super::{Chunk, HashedInput, Layout};

// Size of a G1 Point in projective format
const G1P: usize = 27;

// Splits input from one chunk to two other chunks
pub fn example_split_layout() -> Layout {
    let mut layout = Layout::new();
    layout.push_serial_chunk(vec![G1P], vec![], G1Projective::push_zero());
    layout.push_serial_chunk(vec![2 * G1P], vec![], G1Projective::push_zero());
    layout.push_serial_chunk(vec![3 * G1P], vec![], G1Projective::push_zero());
    // Split input into two outputs in the next chunk
    let last_push_zero_chunk =
        layout.push_serial_chunk(vec![2 * G1P, 2 * G1P], vec![], G1Projective::push_zero());

    let mut sub_layout_1 = Layout::new();
    sub_layout_1.push_serial_chunk(vec![], vec![], G1Projective::equalverify());

    let mut sub_layout_2 = Layout::new();
    sub_layout_2.push_serial_chunk(vec![], vec![], G1Projective::equalverify());

    // Specify to which output each sub layout is linked and integrate them into the layout
    let _chunk_a = layout.push_partial_parallel_layout(sub_layout_1, vec![(last_push_zero_chunk.clone(), 0)]);
    let _chunk_b = layout.push_partial_parallel_layout(sub_layout_2, vec![(last_push_zero_chunk, 1)]);
    // Since the push_partial_parallel_layout function returns the last chunk after the update we
    // can store it for later and use _chunk_a or _chunk_b to combine their outputs (if they had
    // outputs) again in a
    // later chunk.
    layout
}

// Combines outputs from two chunks into one chunk
pub fn example_combine_layout() -> Layout {
    let mut layout = Layout::new();
    let chunk_a = layout.push(Chunk::new(
        vec![],
        vec![G1P],
        vec![],
        G1Projective::push_zero(),
    ));
    let chunk_b = layout.push(Chunk::new(
        vec![],
        vec![G1P],
        vec![],
        G1Projective::push_zero(),
    ));

    let combined_input_chunk = Chunk::new(
        // This chunk expects the first output of chunk_a and the first output of chunk_b as input
        vec![HashedInput::new(chunk_a, 0), HashedInput::new(chunk_b, 0)],
        vec![],
        vec![],
        G1Projective::equalverify(),
    );
    layout.push(combined_input_chunk);
    layout
}

#[cfg(test)]
mod test {
    use std::rc::Rc;

    use super::example_combine_layout;

    #[test]
    fn test_combine() {
        let layout = example_combine_layout();
        assert!(Rc::ptr_eq(&layout.chunks[2].borrow().inputs[0].outputting_chunk, &layout.chunks[0]));
        assert!(Rc::ptr_eq(&layout.chunks[2].borrow().inputs[1].outputting_chunk, &layout.chunks[1]));
    }

}
