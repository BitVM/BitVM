use bitvm::bridge::client::data_store::{base::DataStoreDriver, sftp::Sftp};

#[tokio::test]
async fn test_sftp() {
    println!("Start SFTP connection");
    let sftp = Sftp::new().unwrap();

    println!("Try to list objects");
    let objects = sftp.list_objects().await;
    println!("Objects: {:?}", objects);

    println!("Try to fetch json");
    let json = sftp
        .fetch_json("1721392247764-bridge-client-data.json")
        .await;
    println!("Json: {:?}", json);

    println!("Try to upload json");
    let result = sftp
        .upload_json("sftp_test.json", "{\"dog\":\"cat\"}".to_string())
        .await;
    println!("Result: {:?}", result);
}
