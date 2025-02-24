use bitcoin::Network;

const REGTEST_ESPLORA_URL: &str = "http://localhost:8094/regtest/api/";
// This endpoint accepts non-standard transactions.
const ALPEN_SIGNET_ESPLORA_URL: &str = "https://esplora-large.devnet-annapurna.stratabtc.org";

// TODO: Needs to be updated for production environment.
pub fn get_esplora_url(network: Network) -> &'static str {
    match network {
        Network::Regtest => REGTEST_ESPLORA_URL,
        _ => ALPEN_SIGNET_ESPLORA_URL,
    }
}
