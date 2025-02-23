use regex::Regex;
use std::cmp::Ordering;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::base::DataStoreDriver;
use super::{
    aws_s3::AwsS3,
    ftp::{ftp::Ftp, ftps::Ftps},
    sftp::Sftp,
};

static CLIENT_MISSING_CREDENTIALS_ERROR: &str =
    "Bridge client is missing AWS S3, FTP, FTPS, or SFTP credentials";

static DEFAULT_CLIENT_DATA_SUFFIX: &str = "-bridge-client-data.json";

pub struct DataStore {
    client_data_suffix: String,
    client_data_regex: Regex,
    aws_s3: Option<AwsS3>,
    ftp: Option<Ftp>,
    ftps: Option<Ftps>,
    sftp: Option<Sftp>,
}

impl DataStore {
    pub async fn new() -> Self {
        dotenv::dotenv().ok();
        let client_data_suffix = match dotenv::var("BRIDGE_DATA_STORE_CLIENT_DATA_SUFFIX") {
            Ok(suffix) => suffix,
            Err(_) => String::from(DEFAULT_CLIENT_DATA_SUFFIX),
        };
        Self {
            client_data_suffix: client_data_suffix.clone(),
            client_data_regex: Regex::new(&format!(r"(\d{{13}}){}", client_data_suffix)).unwrap(),
            aws_s3: AwsS3::new(),
            ftp: Ftp::new().await,
            ftps: Ftps::new().await,
            sftp: Sftp::new().await,
        }
    }

    pub fn get_file_timestamp(&self, file_name: &str) -> Result<u64, String> {
        if self.client_data_regex.is_match(file_name) {
            let mut timestamp_string = file_name.to_owned();
            timestamp_string.truncate(13);
            let timestamp = timestamp_string.parse::<u64>();
            return match timestamp {
                Ok(_) => Ok(timestamp.unwrap()),
                Err(_) => Err(String::from("Failed to parse file timestamp")),
            };
        }

        Err(String::from("Incorrect file name"))
    }

    pub async fn get_file_names(&self, file_path: Option<&str>) -> Result<Vec<String>, String> {
        match self.get_driver() {
            Ok(driver) => match driver.list_objects(file_path).await {
                Ok(keys) => {
                    let mut data_keys: Vec<String> = keys
                        .iter()
                        .map(|key| key.rsplit("/").next().unwrap().to_string())
                        .collect();

                    data_keys = data_keys
                        .iter()
                        .filter(|key| self.client_data_regex.is_match(key))
                        .cloned()
                        .collect();
                    data_keys.sort_by(|x, y| {
                        if x < y {
                            return Ordering::Less;
                        }
                        Ordering::Greater
                    });

                    Ok(data_keys)
                }
                Err(err) => Err(err.to_string()),
            },
            Err(err) => Err(err.to_string()),
        }
    }

    pub async fn fetch_data_by_key(
        &self,
        key: &String,
        file_path: Option<&str>,
    ) -> Result<Option<String>, String> {
        match self.get_driver() {
            Ok(driver) => {
                let json = driver.fetch_object(key, file_path).await;
                if let Ok(data) = json {
                    // println!("Fetched data file: {}", key);
                    return Ok(Some(data));
                }

                println!("No data file {} found", key);
                Ok(None)
            }
            Err(err) => Err(err.to_string()),
        }
    }

    pub async fn write_data(
        &self,
        contents: &String,
        file_path: Option<&str>,
    ) -> Result<String, String> {
        match self.get_driver() {
            Ok(driver) => {
                let time = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis();
                let file_name = self.create_file_name(time);
                let response = driver.upload_object(&file_name, contents, file_path).await;

                match response {
                    Ok(_) => Ok(file_name),
                    Err(_) => Err(String::from("Failed to save data file")),
                }
            }
            Err(err) => Err(err.to_string()),
        }
    }

    pub fn get_past_max_file_name_by_timestamp(
        &self,
        latest_timestamp: u64,
        period: u64,
    ) -> String {
        let past_max_timestamp =
            (Duration::from_millis(latest_timestamp) - Duration::from_secs(period)).as_millis();
        self.create_file_name(past_max_timestamp)
    }

    fn create_file_name(&self, timestamp: u128) -> String {
        format!("{}{}", timestamp, self.client_data_suffix)
    }

    fn get_driver(&self) -> Result<&dyn DataStoreDriver, &str> {
        if self.aws_s3.is_some() {
            Ok(self.aws_s3.as_ref().unwrap())
        } else if self.ftp.is_some() {
            Ok(self.ftp.as_ref().unwrap())
        } else if self.ftps.is_some() {
            Ok(self.ftps.as_ref().unwrap())
        } else if self.sftp.is_some() {
            Ok(self.sftp.as_ref().unwrap())
        } else {
            Err(CLIENT_MISSING_CREDENTIALS_ERROR)
        }
    }
}
