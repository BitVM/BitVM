use bitcoin::Amount;

use bridge::{
    graphs::base::PEG_OUT_FEE, scripts::generate_pay_to_pubkey_script_address,
    transactions::base::Input,
};

use crate::bridge::{
    faucet::{Faucet, FaucetType},
    helper::generate_stub_outpoint,
    setup::{setup_test, INITIAL_AMOUNT},
};

#[tokio::test]
async fn test_sync() {
    let mut config = setup_test().await;

    println!("Read from remote");
    config.client_0.sync().await;

    println!("Modify data and save");
    let amount = Amount::from_sat(INITIAL_AMOUNT + PEG_OUT_FEE + 1);
    let faucet = Faucet::new(FaucetType::EsploraRegtest);
    let address = generate_pay_to_pubkey_script_address(
        config.depositor_context.network,
        &config.depositor_context.depositor_public_key,
    );
    faucet.fund_input(&address, amount).await.wait().await;

    let outpoint = generate_stub_outpoint(&config.client_0, &address, amount).await;

    println!("Creating peg in graph ...");
    let peg_in_graph_id = config
        .client_0
        .create_peg_in_graph(Input { outpoint, amount }, &config.depositor_evm_address)
        .await;

    println!("Creating peg out graph ...");
    config.client_0.create_peg_out_graph(
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
        config.commitment_secrets,
    );

    println!("Save to remote");
    config.client_0.flush().await;
}
