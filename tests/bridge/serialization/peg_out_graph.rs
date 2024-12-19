use bitcoin::{Address, Amount};

use bitvm::bridge::{
    graphs::{base::FEE_AMOUNT, peg_in::PegInGraph, peg_out::PegOutGraph},
    scripts::generate_pay_to_pubkey_script_address,
    serialization::{deserialize, serialize},
    transactions::base::Input,
};

use crate::bridge::{
    faucet::{Faucet, FaucetType},
    helper::generate_stub_outpoint,
    setup::{setup_test, INITIAL_AMOUNT},
};

#[tokio::test]
async fn test_peg_out_graph_serialization() {
    let config = setup_test().await;
    let faucet = Faucet::new(FaucetType::EsploraRegtest);

    let mut funding_inputs: Vec<(&Address, Amount)> = vec![];
    let amount = Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT);
    let address = generate_pay_to_pubkey_script_address(
        config.depositor_context.network,
        &config.depositor_context.depositor_public_key,
    );
    funding_inputs.push((&address, amount));

    let kick_off_amount = Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT); // Arbitrary amount
    let kick_off_address = generate_pay_to_pubkey_script_address(
        config.operator_context.network,
        &config.operator_context.operator_public_key,
    );
    funding_inputs.push((&kick_off_address, kick_off_amount));
    faucet
        .fund_inputs(&config.client_0, &funding_inputs)
        .await
        .wait()
        .await;

    let outpoint = generate_stub_outpoint(&config.client_0, &address, amount).await;

    let peg_in_graph = PegInGraph::new(
        &config.depositor_context,
        Input { outpoint, amount },
        &config.depositor_evm_address,
    );

    let kick_off_outpoint =
        generate_stub_outpoint(&config.client_0, &kick_off_address, kick_off_amount).await;

    let (peg_out_graph, _) = PegOutGraph::new(
        &config.operator_context,
        &peg_in_graph,
        Input {
            outpoint: kick_off_outpoint,
            amount: kick_off_amount,
        },
    );

    let json = serialize(&peg_out_graph);
    assert!(!json.is_empty());
    let deserialized_peg_out_graph = deserialize::<PegOutGraph>(&json);
    assert!(peg_out_graph == deserialized_peg_out_graph);
}
