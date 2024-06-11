use crate::treepp::*;
use bitcoin::{
  Amount, OutPoint, XOnlyPublicKey
};

pub fn generate_pre_sign_script(n_of_n_pubkey: XOnlyPublicKey) -> Script {
  script! {
      { n_of_n_pubkey }
      OP_CHECKSIG
  }
}

pub fn generate_burn_script() -> Script {
  script! {
      OP_RETURN
  }
}

pub fn generate_timelock_script(n_of_n_pubkey: XOnlyPublicKey, weeks: i64) -> Script {
  script! {
    { NUM_BLOCKS_PER_WEEK * weeks }
    OP_CSV
    OP_DROP
    { n_of_n_pubkey }
    OP_CHECKSIG
  }
}

pub fn generate_pay_to_operator_script(operator_pubkey: XOnlyPublicKey) -> Script {
  script! {
      { operator_pubkey }
      OP_CHECKSIG
  }
}

pub type Input = (OutPoint, Amount, Option<ScriptBuf>);

pub const NUM_BLOCKS_PER_WEEK: i64 = 1008;
