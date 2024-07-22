use bitcoin::Amount;

use bitvm::bridge::{
    graphs::base::{FEE_AMOUNT, INITIAL_AMOUNT},
    scripts::generate_pay_to_pubkey_script_address,
    transactions::base::Input,
};

use super::super::{helper::generate_stub_outpoint, setup::setup_test};

#[tokio::test]
async fn test_sync() {
    let (mut client, depositor_context, _, _, _, _, _, _, _, _, _, _, _, evm_address) =
        setup_test().await;

    println!("Modify data and save");
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

    client
        .create_peg_in_graph(Input { outpoint, amount }, &evm_address)
        .await;

    println!("Save to remote");
    client.flush().await;

    println!("Read from remote");
    client.sync().await;
}
