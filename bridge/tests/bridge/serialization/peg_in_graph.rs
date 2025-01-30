use bitcoin::Amount;

use bridge::{
    graphs::peg_in::PegInGraph,
    scripts::generate_pay_to_pubkey_script_address,
    serialization::{deserialize, serialize},
    transactions::base::{Input, MIN_RELAY_FEE_PEG_IN_CONFIRM, MIN_RELAY_FEE_PEG_IN_DEPOSIT},
};

use crate::bridge::{
    faucet::{Faucet, FaucetType},
    helper::generate_stub_outpoint,
    setup::{setup_test, INITIAL_AMOUNT},
};

#[tokio::test]
async fn test_peg_in_graph_serialization() {
    let config = setup_test().await;
    let faucet = Faucet::new(FaucetType::EsploraRegtest);

    let amount = Amount::from_sat(
        INITIAL_AMOUNT + MIN_RELAY_FEE_PEG_IN_DEPOSIT + MIN_RELAY_FEE_PEG_IN_CONFIRM,
    );
    let address = generate_pay_to_pubkey_script_address(
        config.depositor_context.network,
        &config.depositor_context.depositor_public_key,
    );
    faucet.fund_input(&address, amount).await.wait().await;

    let outpoint = generate_stub_outpoint(&config.client_0, &address, amount).await;

    let peg_in_graph = PegInGraph::new(
        &config.depositor_context,
        Input { outpoint, amount },
        &config.depositor_evm_address,
    );

    let json = serialize(&peg_in_graph);
    assert!(!json.is_empty());
    let deserialized_peg_in_graph = deserialize::<PegInGraph>(&json);
    assert!(peg_in_graph == deserialized_peg_in_graph);
}
