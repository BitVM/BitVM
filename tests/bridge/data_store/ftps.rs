use bitvm::bridge::client::data_store::{base::DataStoreDriver, ftp::ftps::Ftps};

#[tokio::test]
async fn test_ftps() {
    println!("Start FTPS connection");
    let ftps = Ftps::new().unwrap();

    println!("Try to list objects");
    let objects = ftps.list_objects().await;
    println!("Objects: {:?}", objects);

    println!("Try to fetch json");
    let json = ftps
        .fetch_json("1721392247764-bridge-client-data.json")
        .await;
    println!("Json: {:?}", json);

    println!("Try to upload json");
    let result = ftps
        .upload_json("ftps_test.json", "{\"dog\":\"cat\"}".to_string())
        .await;
    println!("Result: {:?}", result);
}
