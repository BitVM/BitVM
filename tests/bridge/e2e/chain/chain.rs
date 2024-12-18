use bitvm::bridge::client::chain::chain::Chain;

#[ignore]
#[tokio::test]
async fn test_rpc() {
    let adaptor = Chain::new();
    let result = adaptor.get_peg_out_init().await;
    assert!(result.is_ok());

    let events = result.unwrap();
    for event in events {
        println!("{:?}", event);
    }
}
