use bitvm::bridge::client::data_store::{base::DataStoreDriver, ftp::ftp::Ftp};

#[tokio::test]
async fn test_ftp() {
    println!("Start FTP connection");
    let ftp = Ftp::new().unwrap();

    println!("Try to list objects");
    let objects = ftp.list_objects().await;
    println!("Objects: {:?}", objects);

    println!("Try to fetch json");
    let json = ftp
        .fetch_json("1721392247764-bridge-client-data.json")
        .await;
    println!("Json: {:?}", json);

    println!("Try to upload json");
    let result = ftp
        .upload_json("ftp_test.json", "{\"dog\":\"cat\"}".to_string())
        .await;
    println!("Result: {:?}", result);
}
