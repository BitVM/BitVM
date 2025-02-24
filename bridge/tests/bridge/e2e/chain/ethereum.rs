use alloy::{
    eips::BlockNumberOrTag, primitives::Address as EvmAddress, transports::http::reqwest::Url,
};
use bridge::client::chain::{
    chain_adaptor::ChainAdaptor,
    ethereum_adaptor::{EthereumAdaptor, EthereumInitConfig},
};

#[ignore]
#[tokio::test]
async fn test_ethereum_peg_out_init() {
    let adaptor = EthereumAdaptor::new(None);
    let result = adaptor.get_peg_out_init_event().await;
    assert!(result.is_ok());

    let events = result.unwrap();
    for event in events {
        println!("{:?}", event);
    }
}

#[ignore]
#[tokio::test]
async fn test_ethereum_peg_out_burnt() {
    let adaptor = EthereumAdaptor::new(Some(EthereumInitConfig {
        rpc_url: "http://127.0.0.1:8545".parse::<Url>().unwrap(),
        bridge_address: "0x76d05F58D14c0838EC630C8140eDC5aB7CD159Dc"
            .parse::<EvmAddress>()
            .unwrap(),
        bridge_creation_block: 20588300,
        to_block: Some(BlockNumberOrTag::Latest),
    }));
    let result = adaptor.get_peg_out_burnt_event().await;
    assert!(result.is_ok());

    let events = result.unwrap();
    for event in events {
        println!("{:?}", event);
    }
}
