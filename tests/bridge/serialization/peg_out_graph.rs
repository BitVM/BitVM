use bitcoin::Amount;

use bitvm::bridge::{
    graphs::{
        base::{FEE_AMOUNT, INITIAL_AMOUNT},
        peg_in::PegInGraph,
        peg_out::PegOutGraph,
    },
    scripts::generate_pay_to_pubkey_script_address,
    serialization::{deserialize, serialize},
    transactions::base::Input,
};

use super::super::{helper::generate_stub_outpoint, setup::setup_test};

#[tokio::test]
async fn test_peg_out_graph_serialization() {
    let config = setup_test().await;

    let amount = Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT);

    let outpoint = generate_stub_outpoint(
        &config.client_0,
        &generate_pay_to_pubkey_script_address(
            config.depositor_context.network,
            &config.depositor_context.depositor_public_key,
        ),
        amount,
    )
    .await;

    let peg_in_graph = PegInGraph::new(
        &config.depositor_context,
        Input { outpoint, amount },
        &config.depositor_evm_address,
    );

    let kick_off_amount = Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT); // Arbitrary amount

    let kick_off_outpoint = generate_stub_outpoint(
        &config.client_0,
        &generate_pay_to_pubkey_script_address(
            config.operator_context.network,
            &config.operator_context.operator_public_key,
        ),
        kick_off_amount,
    )
    .await;

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
