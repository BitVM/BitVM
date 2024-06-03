use bitcoin::{
    ScriptBuf, XOnlyPublicKey,
};

// Currently only connector B.
pub fn generate_kickoff_leaves(
  n_of_n_pubkey: XOnlyPublicKey,
  operator_pubkey: XOnlyPublicKey,
) -> Vec<ScriptBuf> {
  // TODO: Single script with n_of_n_pubkey (Does something break if we don't sign with
  // operator_key?). Spendable by revealing all commitments
  todo!()
}
