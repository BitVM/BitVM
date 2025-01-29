use bitcoin::{Address, Amount};

use bridge::{
    graphs::{base::PEG_OUT_FEE, peg_in::PegInGraph, peg_out::PegOutGraph},
    scripts::generate_pay_to_pubkey_script_address,
    serialization::{deserialize, serialize},
    transactions::base::{Input, MIN_RELAY_FEE_PEG_IN_CONFIRM},
};

use crate::bridge::{
    faucet::{Faucet, FaucetType},
    helper::{generate_stub_outpoint, get_reward_amount},
    setup::{setup_test, ONE_HUNDRED},
};

#[tokio::test]
async fn test_peg_out_graph_serialization() {
    let config = setup_test().await;
    let faucet = Faucet::new(FaucetType::EsploraRegtest);

    let mut funding_inputs: Vec<(&Address, Amount)> = vec![];
    let amount = Amount::from_sat(ONE_HUNDRED + MIN_RELAY_FEE_PEG_IN_CONFIRM);
    let address = generate_pay_to_pubkey_script_address(
        config.depositor_context.network,
        &config.depositor_context.depositor_public_key,
    );
    funding_inputs.push((&address, amount));

    let kick_off_amount = Amount::from_sat(get_reward_amount(ONE_HUNDRED) + PEG_OUT_FEE);
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

    let peg_out_graph = PegOutGraph::new(
        &config.operator_context,
        &peg_in_graph,
        Input {
            outpoint: kick_off_outpoint,
            amount: kick_off_amount,
        },
        &config.commitment_secrets,
    );

    let json = serialize(&peg_out_graph);
    assert!(!json.is_empty());
    let deserialized_peg_out_graph = deserialize::<PegOutGraph>(&json);
    assert!(peg_out_graph == deserialized_peg_out_graph);
}
