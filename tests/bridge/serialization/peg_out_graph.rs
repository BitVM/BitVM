use bitcoin::Amount;

use bitvm::bridge::{
    graphs::{
        base::{FEE_AMOUNT, INITIAL_AMOUNT},
        peg_in::PegInGraph,
        peg_out::PegOutGraph,
    },
    scripts::generate_pay_to_pubkey_script_address,
    transactions::base::{deserialize, serialize, Input},
};

use super::super::{helper::generate_stub_outpoint, setup::setup_test};

#[tokio::test]
async fn test_peg_out_graph_serialization() {
    let (client, depositor_context, operator_context, _, _, _, _, _, _, _, _, _, _, evm_address) =
        setup_test();

    let input_amount = Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT);
    let funding_address = generate_pay_to_pubkey_script_address(
        depositor_context.network,
        &depositor_context.depositor_public_key,
    );

    let outpoint = generate_stub_outpoint(&client, &funding_address, input_amount).await;

    let peg_in_graph = PegInGraph::new(
        &depositor_context,
        Input {
            outpoint: outpoint,
            amount: input_amount,
        },
        &evm_address,
    );

    let kick_off_input_amount = Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT); // Arbitrary amount
    let kick_off_funding_address = generate_pay_to_pubkey_script_address(
        operator_context.network,
        &operator_context.operator_public_key,
    );

    let kick_off_outpoint =
        generate_stub_outpoint(&client, &kick_off_funding_address, kick_off_input_amount).await;

    let peg_out_graph = PegOutGraph::new(
        &operator_context,
        &peg_in_graph,
        Input {
            outpoint: kick_off_outpoint,
            amount: kick_off_input_amount,
        },
    );

    let json = serialize(&peg_out_graph);
    assert!(json.len() > 0);
    let deserialized_peg_out_graph = deserialize::<PegOutGraph>(&json);
    assert!(peg_out_graph == deserialized_peg_out_graph);
}
