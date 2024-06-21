use bitcoin::key::Secp256k1;
use bitvm::{
    self,
    bridge::{
        client::BitVMClient,
        components::{
            connector_a::ConnectorA, connector_b::ConnectorB, connector_c::ConnectorC,
            connector_z::ConnectorZ,
        },
        context::BridgeContext,
        graph::{DEPOSITOR_SECRET, EVM_ADDRESS, N_OF_N_SECRET, OPERATOR_SECRET, WITHDRAWER_SECRET},
    },
};

pub fn setup_test() -> (
    BitVMClient,
    BridgeContext,
    ConnectorA,
    ConnectorB,
    ConnectorC,
    ConnectorZ,
) {
    let mut context = BridgeContext::new(bitcoin::Network::Testnet);
    context.initialize_evm_address(EVM_ADDRESS);
    context.initialize_operator(OPERATOR_SECRET);
    context.initialize_n_of_n(N_OF_N_SECRET);
    context.initialize_depositor(DEPOSITOR_SECRET);
    context.initialize_withdrawer(WITHDRAWER_SECRET);

    let client = BitVMClient::new();

    let connector_a = ConnectorA::new(
        context.network,
        &context.operator_taproot_public_key.unwrap(),
        &context.n_of_n_taproot_public_key.unwrap(),
    );
    let connector_b = ConnectorB::new(context.network, &context.n_of_n_taproot_public_key.unwrap());
    let connector_c = ConnectorC::new(context.network, &context.n_of_n_taproot_public_key.unwrap());
    let connector_z = ConnectorZ::new(
        context.network,
        context.evm_address.as_ref().unwrap(),
        &context.depositor_taproot_public_key.unwrap(),
        &context.n_of_n_taproot_public_key.unwrap(),
    );

    return (
        client,
        context,
        connector_a,
        connector_b,
        connector_c,
        connector_z,
    );
}
