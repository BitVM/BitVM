use alloy::primitives::Address;
use bitcoin::{ecdsa, taproot, Amount, Denomination, OutPoint, PublicKey};
use clap::ArgMatches;
use core::str::FromStr;

use crate::bridge::constants::DestinationNetwork;

use super::query_response::{Response, ResponseStatus};

pub enum ArgType {
    DepositorPublicKey(PublicKey),
    ChainAddress(Address),
    OutPoint(OutPoint),
    Satoshis(Amount),
    EcdsaSignature(ecdsa::Signature),
    TaprootSignature(taproot::Signature),
}

pub fn validate(
    matches: &ArgMatches,
    args: Vec<String>,
    destination_network: DestinationNetwork,
) -> Result<Vec<ArgType>, Response> {
    let mut result: Vec<ArgType> = vec![];
    for arg in args.iter() {
        match matches.get_one::<String>(arg) {
            Some(value) => match arg.as_str() {
                "DEPOSITOR_PUBLIC_KEY" => match PublicKey::from_str(value) {
                    Ok(pubkey) => result.push(ArgType::DepositorPublicKey(pubkey)),
                    Err(_) => {
                        return Err(error_response(
                            "Invalid public key. Use bitcoin public key format.".to_string(),
                        ))
                    }
                },
                "DESTINATION_CHAIN_ADDRESS" | "WITHDRAWER_CHAIN_ADDRESS" => {
                    match Address::from_str(value) {
                        Ok(address) => result.push(ArgType::ChainAddress(address)),
                        Err(_) => {
                            return Err(error_response(format!(
                                "Invalid {}. Use {} address format.",
                                arg.as_str(),
                                destination_network
                            )))
                        }
                    }
                }
                "OUTPOINT" => match OutPoint::from_str(value) {
                    Ok(outpoint) => result.push(ArgType::OutPoint(outpoint)),
                    Err(_) => {
                        return Err(error_response(
                            "Invalid OutPoint. Use <txid>:<vout> format.".to_string(),
                        ))
                    }
                },
                "SATS" => match Amount::from_str_in(value, Denomination::Satoshi) {
                    Ok(amount) => result.push(ArgType::Satoshis(amount)),
                    Err(_) => {
                        return Err(error_response(
                            "Invalid amount of satoshis. Use u64.".to_string(),
                        ))
                    }
                },
                "DEPOSIT" => match ecdsa::Signature::from_slice(value.as_bytes()) {
                    Ok(sig) => result.push(ArgType::EcdsaSignature(sig)),
                    Err(_) => {
                        return Err(error_response(
                            "Invalid format of ecdsa signature.".to_string(),
                        ))
                    }
                },
                "CONFIRM" | "REFUND" => match taproot::Signature::from_slice(value.as_bytes()) {
                    Ok(sig) => result.push(ArgType::TaprootSignature(sig)),
                    Err(_) => {
                        return Err(error_response(format!(
                            "Invalid format of taproot signature for {} transaction.",
                            arg.as_str()
                        )))
                    }
                },
                _ => return Err(error_response(format!("Invalid argument: {}", arg))),
            },
            None => return Err(error_response(format!("Missing argument: {}", arg))),
        }
    }

    Ok(result)
}

fn error_response(err: String) -> Response {
    Response::new(ResponseStatus::NOK(err.to_string()), None)
}
