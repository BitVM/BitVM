use crate::treepp::*;
use bitcoin::XOnlyPublicKey;

pub fn generate_pre_sign_script(n_of_n_pubkey: XOnlyPublicKey) -> Script {
  script! {
      { n_of_n_pubkey }
      OP_CHECKSIG
  }
}
