pub mod bitvm;
mod scripts;
pub mod utils;

#[tokio::main]
async fn main() {
    let mut client = bitvm::client::BitVMClient::new();
    client.listen().await
}
