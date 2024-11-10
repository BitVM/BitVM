use bitvm::bridge::client::data_store::{base::DataStoreDriver, sftp::Sftp};

#[tokio::test]
async fn test_sftp() {
    println!("Start SFTP connection");
    let sftp = Sftp::new().await.unwrap();

    let path = "bridge_data/testnet/ethereum_sepolia/028b839569cde368894237913fe4fbd25d75eaf1ed019a39d479e693dac35be19e";

    println!("Try to upload json");
    let result = sftp
        .upload_json(
            "sftp_test.json",
            "{\"dog\":\"cat\"}".to_string(),
            Some(path),
        )
        .await;
    println!("Upload Result: {:?}", result);

    println!("Try to list objects");
    let objects = sftp.list_objects(Some(path)).await;
    println!("Objects: {:?}", objects);

    println!("Try to fetch json");
    let json = sftp.fetch_json("sftp_test.json", Some(path)).await;
    println!("Json: {:?}", json);
}
