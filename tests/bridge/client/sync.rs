use bitcoin::Amount;

use bitvm::bridge::{
    graphs::base::{FEE_AMOUNT, INITIAL_AMOUNT},
    scripts::generate_pay_to_pubkey_script_address,
    transactions::base::Input,
};

use super::super::{helper::generate_stub_outpoint, setup::setup_test};

#[tokio::test]
async fn test_sync() {
    let mut config = setup_test().await;

    println!("Read from remote");
    config.client_0.sync().await;

    println!("Modify data and save");
    let amount = Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT + 1);
    let outpoint = generate_stub_outpoint(
        &config.client_0,
        &generate_pay_to_pubkey_script_address(
            config.depositor_context.network,
            &config.depositor_context.depositor_public_key,
        ),
        amount,
    )
    .await;

    let peg_in_graph_id = config
        .client_0
        .create_peg_in_graph(Input { outpoint, amount }, &config.depositor_evm_address)
        .await;

    config
        .client_0
        .create_peg_out_graph(
            &peg_in_graph_id,
            Input {
                outpoint: generate_stub_outpoint(
                    &config.client_0,
                    &generate_pay_to_pubkey_script_address(
                        config.depositor_context.network,
                        &config.depositor_context.depositor_public_key,
                    ),
                    amount,
                )
                .await,
                amount,
            },
        )
        .await;

    println!("Save to remote");
    config.client_0.flush().await;
}
