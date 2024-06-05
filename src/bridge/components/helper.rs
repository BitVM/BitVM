use crate::treepp::*;
use bitcoin::XOnlyPublicKey;

pub fn generate_pre_sign_script(n_of_n_pubkey: XOnlyPublicKey) -> Script {
  script! {
      { n_of_n_pubkey }
      OP_CHECKSIG
  }
}

pub const NUM_BLOCKS_PER_WEEK: i64 = 1008;
