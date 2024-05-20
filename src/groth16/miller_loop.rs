use crate::treepp::{pushable, script, Script};

#[derive(Clone, Copy, Debug)]
pub struct MillerLoop {}

impl MillerLoop {
    pub fn multi_miller_loop() -> Script {
        script! {
            1
        }
    }
}
