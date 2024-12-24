use super::{
    super::{scripts::*, transactions::base::Input},
    base::*,
};
use crate::bridge::{
    graphs::peg_out::CommitmentMessageId,
    transactions::signing_winternitz::{winternitz_message_checksig_verify, WinternitzPublicKey},
};
use bitcoin::{Address, Network, PublicKey, ScriptBuf, TxIn};
use bitcoin_script::script;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct ConnectorE {
    pub network: Network,
    pub operator_public_key: PublicKey,
    pub commitment_public_keys: BTreeMap<CommitmentMessageId, WinternitzPublicKey>,
}

impl ConnectorE {
    pub fn new(
        network: Network,
        operator_public_key: &PublicKey,
        commitment_public_keys: &BTreeMap<CommitmentMessageId, WinternitzPublicKey>,
    ) -> Self {
        ConnectorE {
            network,
            operator_public_key: *operator_public_key,
            commitment_public_keys: commitment_public_keys.clone(),
        }
    }
}

impl P2wshConnector for ConnectorE {
    fn generate_script(&self) -> ScriptBuf {
        let mut script = script! {};
        for (message, pk) in self.commitment_public_keys.iter() {
            match message {
                CommitmentMessageId::Groth16IntermediateValues((str, size)) => {
                    script =
                        script.push_script(winternitz_message_checksig_verify(pk, *size).compile());
                }
                _ => {
                    panic!("connector e only reveal intermediate value of groth16")
                }
            }
        }
        script.compile()
    }

    fn generate_address(&self) -> Address {
        Address::p2wsh(&self.generate_script(), self.network)
    }

    fn generate_tx_in(&self, input: &Input) -> TxIn {
        generate_default_tx_in(input)
    }
}
