use bitcoin::{
  key::{Keypair, Secp256k1},
  secp256k1::All,
  XOnlyPublicKey,
};

pub struct BridgeContext {
  pub secp: Secp256k1<All>,
  operator_key: Option<Keypair>,
  pub n_of_n_pubkey: Option<XOnlyPublicKey>,
  pub unspendable_pubkey: Option<XOnlyPublicKey>,
  // TODO: current_height: Height,
  // TODO: participants secret for the n-of-n keypair
  // TODO: Store learned preimages here
}

impl Default for BridgeContext {
  fn default() -> Self {
      Self::new()
  }
}

impl BridgeContext {
  pub fn new() -> Self {
      BridgeContext {
          secp: Secp256k1::new(),
          operator_key: None,
          n_of_n_pubkey: None,
          unspendable_pubkey: None,
      }
  }

  pub fn set_operator_key(&mut self, operator_key: Keypair) {
      self.operator_key = Some(operator_key);
  }

  pub fn set_n_of_n_pubkey(&mut self, n_of_n_pubkey: XOnlyPublicKey) {
      self.n_of_n_pubkey = Some(n_of_n_pubkey);
  }

  pub fn set_unspendable_pubkey(&mut self, unspendable_pubkey: XOnlyPublicKey) {
    self.unspendable_pubkey = Some(unspendable_pubkey);
  }
}
