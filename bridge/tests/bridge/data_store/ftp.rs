use bridge::client::data_store::{base::DataStoreDriver, ftp::ftp::Ftp};

#[ignore]
#[tokio::test]
async fn test_ftp() {
    println!("Start FTP connection");
    let ftp = Ftp::new().await.unwrap();

    let path = "bridge_data/testnet/ethereum_sepolia/028b839569cde368894237913fe4fbd25d75eaf1ed019a39d479e693dac35be19e";

    println!("Try to upload json");
    let result = ftp
        .upload_json("ftp_test.json", "{\"dog\":\"cat\"}".to_string(), Some(path))
        .await;
    println!("Upload Result: {:?}", result);

    println!("Try to list objects");
    let objects = ftp.list_objects(Some(path)).await;
    println!("Objects: {:?}", objects);

    println!("Try to fetch json");
    let json = ftp
        .fetch_json("1721392247764-bridge-client-data.json", Some(path))
        .await;
    println!("Json: {:?}", json);
}
