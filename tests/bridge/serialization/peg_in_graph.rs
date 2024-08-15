use bitcoin::Amount;

use bitvm::bridge::{
    graphs::{
        base::{FEE_AMOUNT, INITIAL_AMOUNT},
        peg_in::PegInGraph,
    },
    scripts::generate_pay_to_pubkey_script_address,
    serialization::{deserialize, serialize},
    transactions::base::Input,
};

use super::super::{helper::generate_stub_outpoint, setup::setup_test};

#[tokio::test]
async fn test_peg_in_graph_serialization() {
    let (client, depositor_context, _, _, _, _, _, _, _, _, _, _, _, depositor_evm_address, _) =
        setup_test().await;

    let amount = Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT);

    let outpoint = generate_stub_outpoint(
        &client,
        &generate_pay_to_pubkey_script_address(
            depositor_context.network,
            &depositor_context.depositor_public_key,
        ),
        amount,
    )
    .await;

    let peg_in_graph = PegInGraph::new(
        &depositor_context,
        Input { outpoint, amount },
        &depositor_evm_address,
    );

    let json = serialize(&peg_in_graph);
    assert!(json.len() > 0);
    let deserialized_peg_in_graph = deserialize::<PegInGraph>(&json);
    assert!(peg_in_graph == deserialized_peg_in_graph);
}
