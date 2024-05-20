use crate::treepp::{pushable, script, Script};

#[derive(Clone, Copy, Debug)]
pub struct Pairing {}

impl Pairing {
    pub fn final_exponentiation() -> Script {
        script! {
            1
        }
    }
}
