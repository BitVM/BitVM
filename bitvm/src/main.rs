use bitvm::client;

#[tokio::main]
async fn main() {
    let mut client = crate::client::BitVMClient::new();
    client.listen().await
}
