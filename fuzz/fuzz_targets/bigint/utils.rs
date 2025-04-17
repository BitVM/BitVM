use bitvm::treepp::*;

// Verifies two bigints of n_element size on the stack
pub fn bigint_verify_output_script(n_elements: u32) -> Script {
    script! {
        for i in (2..n_elements + 1).rev() {
            {i}
            OP_ROLL
            OP_EQUALVERIFY
        }
        OP_EQUAL
    }
}
