use bitcoin::{Address, Amount, OutPoint};

use bitvm::bridge::client::client::BitVMClient;

pub const TX_WAIT_TIME: u64 = 45; // in seconds

pub async fn generate_stub_outpoint(
    client: &BitVMClient,
    funding_utxo_address: &Address,
    input_value: Amount,
) -> OutPoint {
    let funding_utxo = client
        .get_initial_utxo(funding_utxo_address.clone(), input_value)
        .await
        .unwrap_or_else(|| {
            panic!(
                "Fund {:?} with {} sats at https://faucet.mutinynet.com/",
                funding_utxo_address,
                input_value.to_sat()
            );
        });
    OutPoint {
        txid: funding_utxo.txid,
        vout: funding_utxo.vout,
    }
}

pub async fn verify_funding_inputs(client: &BitVMClient, funding_inputs: &Vec<(&Address, Amount)>) {
    let mut inputs_to_fund: Vec<(&Address, Amount)> = vec![];

    for funding_input in funding_inputs {
        if client
            .get_initial_utxo(funding_input.0.clone(), funding_input.1)
            .await
            .is_none()
        {
            inputs_to_fund.push((funding_input.0, funding_input.1));
        }
    }

    for input_to_fund in inputs_to_fund.clone() {
        println!(
            "Fund {:?} with {} sats at https://faucet.mutinynet.com/",
            input_to_fund.0,
            input_to_fund.1.to_sat()
        );
    }
    if inputs_to_fund.len() > 0 {
        panic!("You need to fund {} addresses first.", inputs_to_fund.len());
    }
}
