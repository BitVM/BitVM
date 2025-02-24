use std::str::FromStr;

use bitcoin::{hashes::hash160::Hash, Amount, OutPoint, PubkeyHash, PublicKey};

use crate::client::chain::{
    chain::{Chain, PegOutEvent},
    mock_adaptor::{MockAdaptor, MockAdaptorConfig},
};

pub fn get_mock_chain_service(outpoint: OutPoint, operator_public_key: PublicKey) -> Chain {
    let mock_adaptor_config = MockAdaptorConfig {
        peg_out_init_events: Some(vec![PegOutEvent {
            source_outpoint: outpoint,
            amount: Amount::from_sat(0),
            timestamp: 1722328130u32,
            withdrawer_chain_address: "0x0000000000000000000000000000000000000000".to_string(),
            withdrawer_destination_address: "0x0000000000000000000000000000000000000000"
                .to_string(),
            withdrawer_public_key_hash: PubkeyHash::from_raw_hash(
                Hash::from_str("0e6719ac074b0e3cac76d057643506faa1c266b3").unwrap(),
            ),
            operator_public_key: operator_public_key,
            tx_hash: [0u8; 32].into(),
        }]),
        peg_out_burnt_events: None,
        peg_out_minted_events: None,
    };
    let mock_adaptor = MockAdaptor::new(Some(mock_adaptor_config));
    Chain::new(Box::new(mock_adaptor))
}
